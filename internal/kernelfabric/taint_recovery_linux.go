//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type TaintRecoveryRequest struct {
	BPFFSRoot              string
	Plan                   TaintActivationPlan
	SignedAuthorization    SignedTaintRecoveryAuthorization
	RecoveryAuthorityKey   ed25519.PublicKey
	Now                    time.Time
}

type TaintRecoveryResult struct {
	CgroupID       uint64
	PlanDigest     string
	PreviousEpoch  uint64
	EnrollmentEpoch uint64
	ClearedDirty   uint64
}

func RecoverTaintSourceContinuity(req TaintRecoveryRequest) (TaintRecoveryResult, error) {
	if err := ValidateTaintActivationPlan(req.Plan); err != nil {
		return TaintRecoveryResult{}, err
	}
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedTaintRecoveryAuthorization(
		req.SignedAuthorization,
		req.RecoveryAuthorityKey,
		now,
	); err != nil {
		return TaintRecoveryResult{}, err
	}
	auth := req.SignedAuthorization.Authorization

	root := filepath.Clean(strings.TrimSpace(req.BPFFSRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	if !filepath.IsAbs(root) {
		return TaintRecoveryResult{}, errors.New("taint recovery bpffs root must be absolute")
	}
	if filepath.Clean(auth.BPFFSRoot) != root {
		return TaintRecoveryResult{}, errors.New("taint recovery authorization bpffs root mismatch")
	}

	planDigest, err := TaintActivationPlanDigest(req.Plan)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	if planDigest != auth.PlanDigest {
		return TaintRecoveryResult{}, errors.New("taint recovery authorization plan digest mismatch")
	}

	cgroupID, err := ResolveCgroupV2ID(req.Plan.CgroupPath)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	if cgroupID != auth.CgroupID {
		return TaintRecoveryResult{}, errors.New("taint recovery authorization cgroup mismatch")
	}

	host, err := (LinuxBootstrapHostProvider{}).Snapshot(root)
	if err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("capture taint recovery host snapshot: %w", err)
	}
	if host.BootIDHash != auth.BootIDHash {
		return TaintRecoveryResult{}, errors.New("taint recovery authorization boot identity mismatch")
	}

	mapDir := filepath.Join(root, "maps")
	sourceMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tsrc"), ebpf.Hash, 16, 8, 32768)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	defer sourceMap.Close()
	dirtyMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tdirty"), ebpf.Array, 4, 8, 1)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	defer dirtyMap.Close()
	armedMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tarmed"), ebpf.Array, 4, 4, 1)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	defer armedMap.Close()
	epochMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tepoch"), ebpf.Array, 4, 8, 1)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	defer epochMap.Close()
	allowMap, err := openExactTaintMap(filepath.Join(mapDir, "aegis_tallow"), ebpf.Hash, 8, 8, 4096)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	defer allowMap.Close()

	active, err := TaintCgroupActivationState(root, cgroupID)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	if !active {
		return TaintRecoveryResult{}, errors.New("taint recovery requires an active protected cgroup")
	}

	var zeroKey uint32
	var armed uint32
	if err := armedMap.Lookup(&zeroKey, &armed); err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("read taint source lifetime arm state: %w", err)
	}
	if armed == 0 {
		return TaintRecoveryResult{}, errors.New("taint recovery requires source lifetime guard to remain armed")
	}

	var currentEpoch uint64
	if err := epochMap.Lookup(&zeroKey, &currentEpoch); err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("read taint enrollment epoch: %w", err)
	}
	if currentEpoch != auth.FromEpoch {
		return TaintRecoveryResult{}, fmt.Errorf(
			"taint recovery epoch mismatch: current=%d authorized_from=%d",
			currentEpoch,
			auth.FromEpoch,
		)
	}

	currentDirty, err := taintSourceDirtyCount(dirtyMap)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	if currentDirty == 0 || currentDirty != auth.ExpectedDirty {
		return TaintRecoveryResult{}, fmt.Errorf(
			"taint recovery dirty-state mismatch: current=%d authorized=%d",
			currentDirty,
			auth.ExpectedDirty,
		)
	}

	var currentAllowed uint64
	if err := allowMap.Lookup(&cgroupID, &currentAllowed); err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("read current taint allow-mask: %w", err)
	}
	if currentAllowed != req.Plan.AllowedLabels {
		return TaintRecoveryResult{}, errors.New("taint recovery cannot change the admitted egress label policy")
	}

	// The authorization binds a freshly generated plan digest, but the kernel
	// still re-observes every source immediately before any mutable recovery
	// state is changed.
	if err := revalidateTaintSourceBindings(root, req.Plan.Sources); err != nil {
		return TaintRecoveryResult{}, err
	}

	previousSources, err := snapshotTaintSourceMap(sourceMap)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	rollbackSources := true
	defer func() {
		if rollbackSources {
			_ = restoreTaintSourceMap(sourceMap, previousSources)
		}
	}()

	desired := make(map[TaintFileKey]uint64, len(req.Plan.Sources))
	for _, source := range req.Plan.Sources {
		desired[source.File] = source.Labels
	}
	if err := replaceTaintSourceMap(sourceMap, desired); err != nil {
		return TaintRecoveryResult{}, err
	}

	// Close the recovery mutation window with a second kernel observation after
	// the candidate source map is installed but while DIRTY still blocks effects.
	if err := revalidateTaintSourceBindings(root, req.Plan.Sources); err != nil {
		return TaintRecoveryResult{}, err
	}
	dirtyBeforeCommit, err := taintSourceDirtyCount(dirtyMap)
	if err != nil {
		return TaintRecoveryResult{}, err
	}
	if dirtyBeforeCommit != auth.ExpectedDirty {
		return TaintRecoveryResult{}, fmt.Errorf(
			"taint source continuity changed during recovery: current=%d authorized=%d",
			dirtyBeforeCommit,
			auth.ExpectedDirty,
		)
	}

	// Advance the fencing epoch before clearing DIRTY. A crash after this write
	// remains fail-closed because DIRTY is still non-zero; the old authorization
	// can no longer be replayed because its FromEpoch is stale.
	nextEpoch := auth.ToEpoch
	if err := epochMap.Update(&zeroKey, &nextEpoch, ebpf.UpdateAny); err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("advance taint enrollment epoch: %w", err)
	}

	// Final recovery effect boundary. Only this last write can restore egress.
	var clean uint64
	if err := dirtyMap.Update(&zeroKey, &clean, ebpf.UpdateAny); err != nil {
		return TaintRecoveryResult{}, fmt.Errorf("clear taint source continuity dirty state: %w", err)
	}

	rollbackSources = false
	return TaintRecoveryResult{
		CgroupID:        cgroupID,
		PlanDigest:      planDigest,
		PreviousEpoch:   auth.FromEpoch,
		EnrollmentEpoch: nextEpoch,
		ClearedDirty:    auth.ExpectedDirty,
	}, nil
}

func TaintEnrollmentEpoch(bpffsRoot string) (uint64, error) {
	root := filepath.Clean(strings.TrimSpace(bpffsRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	m, err := openExactTaintMap(
		filepath.Join(root, "maps", "aegis_tepoch"),
		ebpf.Array,
		4,
		8,
		1,
	)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	var key uint32
	var epoch uint64
	if err := m.Lookup(&key, &epoch); err != nil {
		return 0, err
	}
	return epoch, nil
}

func snapshotTaintSourceMap(m *ebpf.Map) (map[TaintFileKey]uint64, error) {
	out := make(map[TaintFileKey]uint64)
	iter := m.Iterate()
	var key TaintFileKey
	var value uint64
	for iter.Next(&key, &value) {
		out[key] = value
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate taint source map: %w", err)
	}
	return out, nil
}

func replaceTaintSourceMap(m *ebpf.Map, desired map[TaintFileKey]uint64) error {
	current, err := snapshotTaintSourceMap(m)
	if err != nil {
		return err
	}
	for key := range current {
		if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale taint source device=%d inode=%d: %w", key.Device, key.Inode, err)
		}
	}
	for key, value := range desired {
		k := key
		v := value
		if err := m.Update(&k, &v, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("install recovered taint source device=%d inode=%d: %w", key.Device, key.Inode, err)
		}
	}
	return nil
}

func restoreTaintSourceMap(m *ebpf.Map, snapshot map[TaintFileKey]uint64) error {
	current, err := snapshotTaintSourceMap(m)
	if err != nil {
		return err
	}
	for key := range current {
		_ = m.Delete(&key)
	}
	for key, value := range snapshot {
		k := key
		v := value
		if err := m.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
