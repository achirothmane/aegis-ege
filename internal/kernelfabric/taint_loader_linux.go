//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const DefaultTaintBPFFSRoot = "/sys/fs/bpf/aegis-ege/taint"

type TaintBootstrapLoader struct {
	HostProvider BootstrapHostProvider
}

type TaintBootstrapLoadRequest struct {
	ArtifactPath          string
	CgroupPath            string
	BPFFSRoot             string
	SignedManifest        SignedBootstrapManifest
	Trust                 BootstrapTrustStore
	AttestationPrivateKey ed25519.PrivateKey
	Now                   time.Time
}

type TaintBootstrapLoadResult struct {
	SignedReceipt SignedTaintBootstrapReceipt
}

// LoadAndAttach verifies the signed taint artifact, validates its exact ELF
// surface, loads all maps/programs, attaches LSM/fork/connect hooks, pins every
// program/map/link, and emits a signed local receipt.
//
// This install phase deliberately does NOT add the target cgroup to
// aegis_tcgroups. Activation is a separate phase so a partially installed
// artifact cannot become an enforcement authority.
func (l TaintBootstrapLoader) LoadAndAttach(
	ctx context.Context,
	req TaintBootstrapLoadRequest,
) (TaintBootstrapLoadResult, error) {
	if err := ctx.Err(); err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	if len(req.AttestationPrivateKey) != ed25519.PrivateKeySize {
		return TaintBootstrapLoadResult{}, errors.New("taint bootstrap attestation private key is required")
	}

	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedBootstrapManifest(req.SignedManifest, req.Trust, now); err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	if err := ValidateTaintBootstrapManifest(req.SignedManifest.Manifest); err != nil {
		return TaintBootstrapLoadResult{}, err
	}

	stagedArtifact, cleanupArtifact, err := StageVerifiedBootstrapArtifact(
		req.ArtifactPath,
		req.SignedManifest.Manifest,
	)
	if err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	defer cleanupArtifact()

	cgroupPath := filepath.Clean(strings.TrimSpace(req.CgroupPath))
	if _, err := ResolveCgroupV2ID(cgroupPath); err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("validate taint bootstrap cgroup: %w", err)
	}

	root := filepath.Clean(strings.TrimSpace(req.BPFFSRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	if !filepath.IsAbs(root) {
		return TaintBootstrapLoadResult{}, errors.New("taint bpffs root must be absolute")
	}

	hostProvider := l.HostProvider
	if hostProvider == nil {
		hostProvider = LinuxBootstrapHostProvider{}
	}
	host, err := hostProvider.Snapshot(root)
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("capture taint bootstrap host snapshot: %w", err)
	}
	if filepath.Clean(host.BPFFSRoot) != root {
		return TaintBootstrapLoadResult{}, errors.New("taint bootstrap host snapshot bpffs root mismatch")
	}

	spec, err := ebpf.LoadCollectionSpec(stagedArtifact)
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("parse verified taint BPF artifact: %w", err)
	}
	if err := validateTaintCollectionSpec(spec); err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("remove BPF memlock limit: %w", err)
	}

	programDir := filepath.Join(root, "programs")
	mapDir := filepath.Join(root, "maps")
	linkDir := filepath.Join(root, "links")
	for _, dir := range []string{programDir, mapDir, linkDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return TaintBootstrapLoadResult{}, fmt.Errorf("create taint bpffs directory %s: %w", dir, err)
		}
	}
	if err := ensureTaintPinsVacant(programDir, mapDir, linkDir); err != nil {
		return TaintBootstrapLoadResult{}, err
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("load verified taint BPF artifact: %w", err)
	}
	defer collection.Close()

	attached := make(map[string]link.Link, len(taintBootstrapPrograms))
	closeAttached := func() {
		for _, attachedLink := range attached {
			if attachedLink != nil {
				_ = attachedLink.Close()
			}
		}
	}
	defer closeAttached()

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: collection.Programs["aegis_fperm"],
	})
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("attach taint BPF LSM file_permission: %w", err)
	}
	attached["aegis_fperm"] = lsmLink

	forkLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: collection.Programs["aegis_fork"],
	})
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("attach taint fork raw tracepoint: %w", err)
	}
	attached["aegis_fork"] = forkLink

	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: collection.Programs["aegis_tconn4"],
	})
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("attach taint IPv4 connect guard: %w", err)
	}
	attached["aegis_tconn4"] = connect4Link

	connect6Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: collection.Programs["aegis_tconn6"],
	})
	if err != nil {
		return TaintBootstrapLoadResult{}, fmt.Errorf("attach taint IPv6 connect guard: %w", err)
	}
	attached["aegis_tconn6"] = connect6Link

	var pinned []string
	cleanupPins := func() {
		for i := len(pinned) - 1; i >= 0; i-- {
			_ = os.Remove(pinned[i])
		}
	}
	success := false
	defer func() {
		if !success {
			cleanupPins()
		}
	}()

	for _, expected := range taintBootstrapPrograms {
		path := filepath.Join(programDir, expected.PinName)
		if err := collection.Programs[expected.Name].Pin(path); err != nil {
			return TaintBootstrapLoadResult{}, fmt.Errorf("pin taint BPF program %s: %w", expected.Name, err)
		}
		pinned = append(pinned, path)
	}
	for _, expected := range taintBootstrapMaps {
		path := filepath.Join(mapDir, expected.Name)
		if err := collection.Maps[expected.Name].Pin(path); err != nil {
			return TaintBootstrapLoadResult{}, fmt.Errorf("pin taint BPF map %s: %w", expected.Name, err)
		}
		pinned = append(pinned, path)
	}
	for _, expected := range taintBootstrapPrograms {
		path := filepath.Join(linkDir, expected.PinName)
		if err := attached[expected.PinName].Pin(path); err != nil {
			return TaintBootstrapLoadResult{}, fmt.Errorf("pin taint BPF link %s: %w", expected.PinName, err)
		}
		pinned = append(pinned, path)
	}

	programs, err := attestTaintPrograms(collection)
	if err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	maps, err := attestTaintMaps(collection)
	if err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	links := make([]TaintPinnedLinkAttestation, 0, len(taintBootstrapPrograms))
	for _, expected := range taintBootstrapPrograms {
		links = append(links, TaintPinnedLinkAttestation{
			Name:       expected.PinName,
			Path:       filepath.Join(linkDir, expected.PinName),
			ProgramPin: filepath.Join(programDir, expected.PinName),
			AttachType: expected.AttachType,
		})
	}

	manifestDigest, err := BootstrapManifestDigest(req.SignedManifest.Manifest)
	if err != nil {
		return TaintBootstrapLoadResult{}, err
	}
	receipt := TaintBootstrapReceipt{
		Version:             TaintBootstrapReceiptVersion,
		ManifestDigest:      manifestDigest,
		ManifestSignerKeyID: req.SignedManifest.KeyID,
		ArtifactSHA256:      req.SignedManifest.Manifest.ArtifactSHA256,
		ArtifactSize:        req.SignedManifest.Manifest.ArtifactSize,
		Host:                host,
		CgroupPath:          cgroupPath,
		Programs:            programs,
		Maps:                maps,
		Links:               links,
		CompletedAt:         now,
	}
	signedReceipt, err := SignTaintBootstrapReceipt(receipt, req.AttestationPrivateKey)
	if err != nil {
		return TaintBootstrapLoadResult{}, err
	}

	success = true
	return TaintBootstrapLoadResult{SignedReceipt: signedReceipt}, nil
}

func validateTaintCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("taint BPF collection spec is nil")
	}
	if len(spec.Programs) != len(taintBootstrapPrograms) {
		return fmt.Errorf("%w: ELF program count=%d want=%d", ErrTaintBootstrapManifest, len(spec.Programs), len(taintBootstrapPrograms))
	}
	if len(spec.Maps) != len(taintBootstrapMaps) {
		return fmt.Errorf("%w: ELF map count=%d want=%d", ErrTaintBootstrapManifest, len(spec.Maps), len(taintBootstrapMaps))
	}

	expectedProgramTypes := map[string]struct {
		programType ebpf.ProgramType
		attachType  ebpf.AttachType
	}{
		"aegis_fperm":  {ebpf.LSM, ebpf.AttachLSMMac},
		"aegis_fork":   {ebpf.RawTracepoint, ebpf.AttachNone},
		"aegis_tconn4": {ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect},
		"aegis_tconn6": {ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect},
	}
	for name, expected := range expectedProgramTypes {
		program := spec.Programs[name]
		if program == nil {
			return fmt.Errorf("%w: missing ELF program %s", ErrTaintBootstrapManifest, name)
		}
		if program.Type != expected.programType {
			return fmt.Errorf("%w: program %s type=%s", ErrTaintBootstrapManifest, name, program.Type)
		}
		if name != "aegis_fork" && program.AttachType != expected.attachType {
			return fmt.Errorf("%w: program %s attach=%s", ErrTaintBootstrapManifest, name, program.AttachType)
		}
	}

	expectedMaps := map[string]struct {
		mapType    ebpf.MapType
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
	}{
		"aegis_tsrc":     {ebpf.Hash, 16, 8, 32768},
		"aegis_ftaint":   {ebpf.Hash, 16, 8, 65536},
		"aegis_ptaint":   {ebpf.Hash, 4, 8, 65536},
		"aegis_tcgroups": {ebpf.Hash, 8, 4, 4096},
		"aegis_tallow":   {ebpf.Hash, 8, 8, 4096},
		"aegis_tfail":    {ebpf.Hash, 8, 8, 4096},
		"aegis_tevents":  {ebpf.RingBuf, 0, 0, 1 << 20},
		"aegis_tacct":    {ebpf.Array, 4, TaintAccountingSize, 1},
	}
	for name, expected := range expectedMaps {
		m := spec.Maps[name]
		if m == nil {
			return fmt.Errorf("%w: missing ELF map %s", ErrTaintBootstrapManifest, name)
		}
		if m.Type != expected.mapType ||
			m.KeySize != expected.keySize ||
			m.ValueSize != expected.valueSize ||
			m.MaxEntries != expected.maxEntries {
			return fmt.Errorf(
				"%w: map %s type=%s key=%d value=%d max=%d",
				ErrTaintBootstrapManifest,
				name,
				m.Type,
				m.KeySize,
				m.ValueSize,
				m.MaxEntries,
			)
		}
	}
	return nil
}

func ensureTaintPinsVacant(programDir, mapDir, linkDir string) error {
	for _, expected := range taintBootstrapPrograms {
		for _, path := range []string{
			filepath.Join(programDir, expected.PinName),
			filepath.Join(linkDir, expected.PinName),
		} {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("taint BPF pin already exists: %s", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for _, expected := range taintBootstrapMaps {
		path := filepath.Join(mapDir, expected.Name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("taint BPF map pin already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func attestTaintPrograms(collection *ebpf.Collection) ([]PinnedProgramAttestation, error) {
	out := make([]PinnedProgramAttestation, 0, len(taintBootstrapPrograms))
	expectedTypes := map[string]ebpf.ProgramType{
		"aegis_fperm":  ebpf.LSM,
		"aegis_fork":   ebpf.RawTracepoint,
		"aegis_tconn4": ebpf.CGroupSockAddr,
		"aegis_tconn6": ebpf.CGroupSockAddr,
	}
	for _, expected := range taintBootstrapPrograms {
		program := collection.Programs[expected.Name]
		if program == nil || program.Type() != expectedTypes[expected.Name] {
			return nil, fmt.Errorf("loaded taint program %s type mismatch", expected.Name)
		}
		info, err := program.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect taint program %s: %w", expected.Name, err)
		}
		id, ok := info.ID()
		if !ok || id == 0 || strings.TrimSpace(info.Tag) == "" {
			return nil, fmt.Errorf("taint program %s lacks kernel id/tag", expected.Name)
		}
		out = append(out, PinnedProgramAttestation{
			PinName:    expected.PinName,
			ID:         uint32(id),
			Name:       info.Name,
			Type:       expected.Type,
			Tag:        info.Tag,
			AttachType: expected.AttachType,
		})
	}
	return out, nil
}

func attestTaintMaps(collection *ebpf.Collection) ([]PinnedMapAttestation, error) {
	out := make([]PinnedMapAttestation, 0, len(taintBootstrapMaps))
	for _, expected := range taintBootstrapMaps {
		m := collection.Maps[expected.Name]
		if m == nil {
			return nil, fmt.Errorf("loaded taint map %s is missing", expected.Name)
		}
		info, err := m.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect taint map %s: %w", expected.Name, err)
		}
		id, ok := info.ID()
		if !ok || id == 0 {
			return nil, fmt.Errorf("taint map %s lacks kernel id", expected.Name)
		}
		out = append(out, PinnedMapAttestation{
			Name:       expected.Name,
			ID:         uint32(id),
			Type:       expected.Type,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			MaxEntries: info.MaxEntries,
		})
	}
	return out, nil
}
