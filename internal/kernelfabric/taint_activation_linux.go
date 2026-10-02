//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type TaintActivationRequest struct {
	BPFFSRoot                     string
	Plan                          TaintActivationPlan
	SignedBootstrapReceipt        SignedTaintBootstrapReceipt
	BootstrapAttestationPublicKey ed25519.PublicKey
}

type TaintActivationResult struct {
	CgroupID   uint64
	PlanDigest string
}

// ActivateTaintCgroup is phase two of the taint install protocol.
//
// It verifies the signed local bootstrap receipt and the continued presence of
// every pinned link, initializes source/allow/failure state, and writes the
// protected-cgroup flag last. Before that final write, the globally attached
// LSM/tracepoint programs remain inert for this cgroup.
func ActivateTaintCgroup(req TaintActivationRequest) (TaintActivationResult, error) {
	if err := ValidateTaintActivationPlan(req.Plan); err != nil {
		return TaintActivationResult{}, err
	}
	if len(req.BootstrapAttestationPublicKey) != ed25519.PublicKeySize {
		return TaintActivationResult{}, errors.New("taint bootstrap attestation public key is required")
	}
	if err := VerifySignedTaintBootstrapReceipt(
		req.SignedBootstrapReceipt,
		req.BootstrapAttestationPublicKey,
	); err != nil {
		return TaintActivationResult{}, err
	}

	root := filepath.Clean(strings.TrimSpace(req.BPFFSRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	if !filepath.IsAbs(root) {
		return TaintActivationResult{}, errors.New("taint bpffs root must be absolute")
	}
	receipt := req.SignedBootstrapReceipt.Receipt
	if filepath.Clean(receipt.Host.BPFFSRoot) != root {
		return TaintActivationResult{}, errors.New("taint activation bpffs root differs from bootstrap receipt")
	}
	if filepath.Clean(receipt.CgroupPath) != filepath.Clean(req.Plan.CgroupPath) {
		return TaintActivationResult{}, errors.New("taint activation cgroup differs from bootstrap receipt")
	}

	currentHost, err := (LinuxBootstrapHostProvider{}).Snapshot(root)
	if err != nil {
		return TaintActivationResult{}, fmt.Errorf("capture current taint host snapshot: %w", err)
	}
	if currentHost.BootIDHash != receipt.Host.BootIDHash ||
		currentHost.KernelRelease != receipt.Host.KernelRelease {
		return TaintActivationResult{}, errors.New("taint bootstrap host identity changed before activation")
	}

	for _, pinned := range receipt.Links {
		loaded, err := link.LoadPinnedLink(pinned.Path, nil)
		if err != nil {
			return TaintActivationResult{}, fmt.Errorf("open pinned taint link %s: %w", pinned.Name, err)
		}
		_ = loaded.Close()
	}

	cgroupID, err := ResolveCgroupV2ID(req.Plan.CgroupPath)
	if err != nil {
		return TaintActivationResult{}, err
	}
	planDigest, err := TaintActivationPlanDigest(req.Plan)
	if err != nil {
		return TaintActivationResult{}, err
	}

	mapDir := filepath.Join(root, "maps")
	sourceMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tsrc"), ebpf.Hash, 16, 8, 32768)
	if err != nil {
		return TaintActivationResult{}, err
	}
	defer sourceMap.Close()
	allowMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tallow"), ebpf.Hash, 8, 8, 4096)
	if err != nil {
		return TaintActivationResult{}, err
	}
	defer allowMap.Close()
	failureMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tfail"), ebpf.Hash, 8, 8, 4096)
	if err != nil {
		return TaintActivationResult{}, err
	}
	defer failureMap.Close()
	dirtyMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tdirty"), ebpf.Array, 4, 8, 1)
	if err != nil {
		return TaintActivationResult{}, err
	}
	defer dirtyMap.Close()
	var (
		zeroKey     uint32
		sourceDirty uint64
	)
	if err := dirtyMap.Lookup(&zeroKey, &sourceDirty); err != nil {
		return TaintActivationResult{}, fmt.Errorf("read taint source identity continuity: %w", err)
	}
	if sourceDirty != 0 {
		return TaintActivationResult{}, fmt.Errorf(
			"taint source identity continuity is dirty before activation: %d",
			sourceDirty,
		)
	}
	cgroupMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tcgroups"), ebpf.Hash, 8, 4, 4096)
	if err != nil {
		return TaintActivationResult{}, err
	}
	defer cgroupMap.Close()

	addedSources := make([]TaintFileKey, 0, len(req.Plan.Sources))
	rollback := func() {
		for _, key := range addedSources {
			_ = sourceMap.Delete(&key)
		}
		_ = allowMap.Delete(&cgroupID)
		_ = failureMap.Delete(&cgroupID)
	}
	activated := false
	defer func() {
		if !activated {
			rollback()
		}
	}()

	for _, source := range req.Plan.Sources {
		key := source.File
		value := source.Labels
		if err := sourceMap.Update(&key, &value, ebpf.UpdateNoExist); err != nil {
			return TaintActivationResult{}, fmt.Errorf(
				"install taint source device=%d inode=%d: %w",
				key.Device,
				key.Inode,
				err,
			)
		}
		addedSources = append(addedSources, key)
	}

	allowed := req.Plan.AllowedLabels
	if err := allowMap.Update(&cgroupID, &allowed, ebpf.UpdateAny); err != nil {
		return TaintActivationResult{}, fmt.Errorf("install taint egress allow-mask: %w", err)
	}
	var zero uint64
	if err := failureMap.Update(&cgroupID, &zero, ebpf.UpdateAny); err != nil {
		return TaintActivationResult{}, fmt.Errorf("initialize taint uncertainty counter: %w", err)
	}

	// Activation point: write this last.
	var enabled uint32 = 1
	if err := cgroupMap.Update(&cgroupID, &enabled, ebpf.UpdateNoExist); err != nil {
		return TaintActivationResult{}, fmt.Errorf("activate protected taint cgroup: %w", err)
	}

	activated = true
	return TaintActivationResult{
		CgroupID:   cgroupID,
		PlanDigest: planDigest,
	}, nil
}

func ResolveTaintFileKey(path string) (TaintFileKey, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return TaintFileKey{}, errors.New("taint source path must be absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return TaintFileKey{}, fmt.Errorf("open taint source without symlink following: %w", err)
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return TaintFileKey{}, fmt.Errorf("stat taint source: %w", err)
	}
	if stat.Dev == 0 || stat.Ino == 0 {
		return TaintFileKey{}, errors.New("taint source file identity is zero")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return TaintFileKey{}, errors.New("taint source must be a regular file")
	}
	device, err := kernelDeviceID(uint64(stat.Dev))
	if err != nil {
		return TaintFileKey{}, err
	}
	return TaintFileKey{Device: device, Inode: stat.Ino}, nil
}

func kernelDeviceID(statDev uint64) (uint64, error) {
	major := uint64(unix.Major(statDev))
	minor := uint64(unix.Minor(statDev))
	const (
		majorMax = uint64(0xfff)
		minorMax = uint64(0xfffff)
	)
	if major > majorMax || minor > minorMax {
		return 0, fmt.Errorf(
			"taint source device major/minor exceeds kernel dev_t bounds: major=%d minor=%d",
			major,
			minor,
		)
	}
	// Linux kernel dev_t is MKDEV(major, minor) with 20 minor bits.
	// stat(2) exposes the userspace-encoded dev_t representation, which must
	// not be compared byte-for-byte with super_block.s_dev in BPF.
	return (major << 20) | minor, nil
}

func openExactTaintMap(
	path string,
	mapType ebpf.MapType,
	keySize uint32,
	valueSize uint32,
	maxEntries uint32,
) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned taint map %s: %w", filepath.Base(path), err)
	}
	if m.Type() != mapType ||
		m.KeySize() != keySize ||
		m.ValueSize() != valueSize ||
		m.MaxEntries() != maxEntries {
		_ = m.Close()
		return nil, fmt.Errorf(
			"pinned taint map %s ABI mismatch: type=%s key=%d value=%d max=%d",
			filepath.Base(path),
			m.Type(),
			m.KeySize(),
			m.ValueSize(),
			m.MaxEntries(),
		)
	}
	return m, nil
}

// TaintCgroupActivationState provides the minimum observation needed after a
// crash at the activation boundary. A caller can distinguish "not activated"
// from "activation may have happened" by reading the protected-cgroup map.
func TaintCgroupActivationState(bpffsRoot string, cgroupID uint64) (bool, error) {
	root := filepath.Clean(strings.TrimSpace(bpffsRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	m, err := openExactTaintMap(
		filepath.Join(root, "maps", "aegis_tcgroups"),
		ebpf.Hash,
		8,
		4,
		4096,
	)
	if err != nil {
		return false, err
	}
	defer m.Close()

	var enabled uint32
	if err := m.Lookup(&cgroupID, &enabled); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return enabled != 0, nil
}

// TaintSourceIdentityDirtyState returns the global source-identity invalidation
// counter. Any non-zero value means at least one registered source inode was
// unlinked or participated in a rename/replacement after registration.
func TaintSourceIdentityDirtyState(bpffsRoot string) (uint64, error) {
	root := filepath.Clean(strings.TrimSpace(bpffsRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	m, err := openExactTaintMap(
		filepath.Join(root, "maps", "aegis_tdirty"),
		ebpf.Array,
		4,
		8,
		1,
	)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	var (
		key   uint32
		dirty uint64
	)
	if err := m.Lookup(&key, &dirty); err != nil {
		return 0, err
	}
	return dirty, nil
}

func removeTaintPin(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Best-effort rollback helper. The caller's primary error is more useful.
		return
	}
}
