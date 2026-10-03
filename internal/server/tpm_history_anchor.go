//go:build linux && cgo

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const tpmNVHistoryAnchorStateVersion = "aegis.ege/tpm-nv-history-anchor/v1"

var (
	ErrTPMHistoryAnchorUnprovisioned       = errors.New("TPM history anchor is not provisioned")
	ErrTPMHistoryAnchorRollback            = errors.New("TPM history anchor rollback detected")
	ErrTPMHistoryAnchorInvalid             = errors.New("TPM history anchor state is invalid")
	ErrTPMHistoryAnchorDeviceChanged       = errors.New("TPM history anchor device identity changed")
	ErrTPMHistoryAnchorMeasuredBootChanged = errors.New("TPM history anchor measured boot identity changed")
)

type TPMNVHistoryAnchorConfig struct {
	NVIndex         tpm2.TPMHandle
	HeadNVIndex     tpm2.TPMHandle
	StatePath       string
	OwnerAuth       []byte
	EndorsementAuth []byte
	IndexAuth       []byte
	HeadIndexAuth   []byte
}

type TPMNVHistoryAnchor struct {
	helper *TPMNVMonotonicRoot
	cfg    TPMNVHistoryAnchorConfig
	mu     sync.Mutex
}

type tpmNVHistoryAnchorState struct {
	Version              string `json:"version"`
	DeviceIdentity       string `json:"device_identity"`
	MeasuredBootIdentity string `json:"measured_boot_identity"`
	Generation           uint64 `json:"generation"`
	PreviousGeneration   uint64 `json:"previous_generation,omitempty"`
	Sequence             uint64 `json:"sequence"`
	PreviousSequence     uint64 `json:"previous_sequence,omitempty"`
	HeadDigest           string `json:"head_digest,omitempty"`
	PreviousHeadDigest             string `json:"previous_head_digest,omitempty"`
	TransitionKind                 string `json:"transition_kind,omitempty"`
	PredecessorDeviceIdentity      string `json:"predecessor_device_identity,omitempty"`
	MigrationSourceStateDigest     string `json:"migration_source_state_digest,omitempty"`
	MigrationAuthorizationDigest   string `json:"migration_authorization_digest,omitempty"`
	Digest                         string `json:"digest"`
}

var _ kernelfabric.TaintRecoveryHistoryAnchor = (*TPMNVHistoryAnchor)(nil)

func ProvisionTPMNVHistoryAnchor(
	ctx context.Context,
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) error {
	if err := validateTPMNVHistoryAnchorConfig(device, cfg); err != nil {
		return err
	}
	rootCfg := historyAnchorRootConfig(cfg)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, path := range []string{cfg.StatePath, cfg.StatePath + ".pending"} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%w: state path already exists: %s", ErrTPMHistoryAnchorInvalid, path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	counterDef := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(cfg.OwnerAuth),
		},
		Auth: tpm2.TPM2BAuth{Buffer: append([]byte(nil), cfg.IndexAuth...)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: cfg.NVIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				AuthWrite:  true,
				AuthRead:   true,
				NT:         tpm2.TPMNTCounter,
				NoDA:       true,
			},
			DataSize: 8,
		}),
	}
	if _, err := counterDef.Execute(device); err != nil {
		return fmt.Errorf("define TPM history counter 0x%x: %w", uint32(cfg.NVIndex), err)
	}

	provisioned := false
	defer func() {
		if provisioned {
			return
		}
		undefineTPMNVHistorySpaceBestEffort(device, cfg.HeadNVIndex, cfg.OwnerAuth)
		undefineTPMNVHistorySpaceBestEffort(device, cfg.NVIndex, cfg.OwnerAuth)
	}()

	if err := defineTPMNVHistoryProtectedHead(device, cfg); err != nil {
		return err
	}

	helper, err := NewTPMNVMonotonicRoot(device, rootCfg)
	if err != nil {
		return err
	}
	deviceIdentity, err := helper.deviceIdentity(ctx)
	if err != nil {
		return fmt.Errorf("bind TPM history device identity: %w", err)
	}
	measuredBootIdentity, err := helper.measuredBootIdentity(ctx)
	if err != nil {
		return fmt.Errorf("bind TPM history measured boot identity: %w", err)
	}
	generation, err := helper.incrementCounter(ctx)
	if err != nil {
		return fmt.Errorf("initialize TPM history counter: %w", err)
	}

	anchor := &TPMNVHistoryAnchor{helper: helper, cfg: cfg}
	if err := anchor.writeProtectedHead(ctx, tpmNVHistoryProtectedHead{
		Generation: generation,
		Sequence:   0,
	}); err != nil {
		return fmt.Errorf("initialize TPM history exact head: %w", err)
	}

	if err := writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath, tpmNVHistoryAnchorState{
		Version:              tpmNVHistoryAnchorStateVersion,
		DeviceIdentity:       deviceIdentity,
		MeasuredBootIdentity: measuredBootIdentity,
		Generation:           generation,
		Sequence:             0,
	}); err != nil {
		return err
	}
	provisioned = true
	return nil
}

func NewTPMNVHistoryAnchor(
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) (*TPMNVHistoryAnchor, error) {
	if err := validateTPMNVHistoryAnchorConfig(device, cfg); err != nil {
		return nil, err
	}
	rootCfg := historyAnchorRootConfig(cfg)
	helper, err := NewTPMNVMonotonicRoot(device, rootCfg)
	if err != nil {
		return nil, err
	}
	cfg.StatePath = filepath.Clean(cfg.StatePath)
	cfg.OwnerAuth = append([]byte(nil), cfg.OwnerAuth...)
	cfg.EndorsementAuth = append([]byte(nil), cfg.EndorsementAuth...)
	cfg.IndexAuth = append([]byte(nil), cfg.IndexAuth...)
	cfg.HeadIndexAuth = append([]byte(nil), cfg.HeadIndexAuth...)
	return &TPMNVHistoryAnchor{helper: helper, cfg: cfg}, nil
}

func (a *TPMNVHistoryAnchor) DeviceIdentity(ctx context.Context) (string, error) {
	if a == nil || a.helper == nil {
		return "", errors.New("TPM history anchor is unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.helper.deviceIdentity(ctx)
}

func (a *TPMNVHistoryAnchor) MeasuredBootIdentity(ctx context.Context) (string, error) {
	if a == nil || a.helper == nil {
		return "", errors.New("TPM history anchor is unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.helper.measuredBootIdentity(ctx)
}

func (a *TPMNVHistoryAnchor) Current(
	ctx context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := a.recoverLocked(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	return publicTPMHistoryAnchorState(state), nil
}

func (a *TPMNVHistoryAnchor) CompareAndAdvance(
	ctx context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if err := validateTPMHistoryAnchorPublicState(expected); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if err := validateTPMHistoryAnchorPublicState(next); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if next.Sequence != expected.Sequence+1 {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: non-successor sequence expected=%d next=%d",
			ErrTPMHistoryAnchorInvalid,
			expected.Sequence,
			next.Sequence,
		)
	}
	if next.HeadDigest == "" {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: successor head digest is required",
			ErrTPMHistoryAnchorInvalid,
		)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := a.recoverLocked(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	current := publicTPMHistoryAnchorState(state)

	if current == next {
		if state.PreviousSequence != expected.Sequence ||
			state.PreviousHeadDigest != expected.HeadDigest {
			return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
				"%w: idempotent predecessor mismatch",
				ErrTPMHistoryAnchorInvalid,
			)
		}
		return current, nil
	}
	if current != expected {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: current=(%d,%s) expected=(%d,%s) next=(%d,%s)",
			ErrTPMHistoryAnchorRollback,
			current.Sequence,
			current.HeadDigest,
			expected.Sequence,
			expected.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}
	if state.Generation == ^uint64(0) {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: generation exhausted",
			ErrTPMHistoryAnchorInvalid,
		)
	}

	pending := state
	pending.PreviousGeneration = state.Generation
	pending.Generation = state.Generation + 1
	pending.PreviousSequence = state.Sequence
	pending.Sequence = next.Sequence
	pending.PreviousHeadDigest = state.HeadDigest
	pending.HeadDigest = next.HeadDigest
	pending.TransitionKind = ""
	pending.Digest = ""

	pendingPath := a.cfg.StatePath + ".pending"
	if err := writeTPMNVHistoryAnchorStateAtomic(pendingPath, pending); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"persist pending TPM history anchor: %w",
			err,
		)
	}
	if err := a.writeProtectedHead(ctx, tpmNVHistoryProtectedHead{
		Generation: pending.Generation,
		Sequence:   pending.Sequence,
		HeadDigest: pending.HeadDigest,
	}); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"commit TPM history exact head: %w",
			err,
		)
	}
	generation, err := a.helper.incrementCounter(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"increment TPM history counter: %w",
			err,
		)
	}
	if generation != pending.Generation {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: counter=%d expected=%d",
			ErrTPMHistoryAnchorRollback,
			generation,
			pending.Generation,
		)
	}
	if err := promoteTPMNVHistoryAnchorPending(pendingPath, a.cfg.StatePath); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"promote TPM history anchor: %w",
			err,
		)
	}
	return next, nil
}

func (a *TPMNVHistoryAnchor) recoverLocked(
	ctx context.Context,
) (tpmNVHistoryAnchorState, error) {
	generation, err := a.helper.readCounter(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, fmt.Errorf("read TPM history counter: %w", err)
	}
	protectedHead, err := a.readProtectedHead(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}

	committed, committedOK, err := readTPMNVHistoryAnchorState(a.cfg.StatePath)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	if !committedOK {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: state=%s counter=%d protected=(%d,%d,%s)",
			ErrTPMHistoryAnchorUnprovisioned,
			a.cfg.StatePath,
			generation,
			protectedHead.Generation,
			protectedHead.Sequence,
			protectedHead.HeadDigest,
		)
	}

	deviceIdentity, err := a.helper.deviceIdentity(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, fmt.Errorf("read TPM history device identity: %w", err)
	}
	if committed.DeviceIdentity != deviceIdentity {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: enrolled=%s observed=%s",
			ErrTPMHistoryAnchorDeviceChanged,
			committed.DeviceIdentity,
			deviceIdentity,
		)
	}
	measuredBootIdentity, err := a.helper.measuredBootIdentity(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"read TPM history measured boot identity: %w",
			err,
		)
	}
	if committed.MeasuredBootIdentity != measuredBootIdentity {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: enrolled=%s observed=%s",
			ErrTPMHistoryAnchorMeasuredBootChanged,
			committed.MeasuredBootIdentity,
			measuredBootIdentity,
		)
	}

	pendingPath := a.cfg.StatePath + ".pending"
	pending, pendingOK, err := readTPMNVHistoryAnchorState(pendingPath)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	if pendingOK && pending.DeviceIdentity != committed.DeviceIdentity {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: committed=%s pending=%s",
			ErrTPMHistoryAnchorDeviceChanged,
			committed.DeviceIdentity,
			pending.DeviceIdentity,
		)
	}
	if pendingOK && pending.MeasuredBootIdentity != committed.MeasuredBootIdentity {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: committed=%s pending=%s",
			ErrTPMHistoryAnchorMeasuredBootChanged,
			committed.MeasuredBootIdentity,
			pending.MeasuredBootIdentity,
		)
	}

	committedProtected := protectedTPMHistoryHeadMatches(protectedHead, committed)
	pendingSuccessor := pendingOK && isTPMHistoryAnchorPendingSuccessor(committed, pending)
	pendingMigration := pendingOK && isTPMHistoryAnchorPendingMigration(committed, pending)
	pendingRecoverable := pendingSuccessor || pendingMigration
	pendingProtected := pendingOK && protectedTPMHistoryHeadMatches(protectedHead, pending)

	if committed.Generation == generation && committedProtected {
		if !pendingOK {
			return committed, nil
		}
		if pendingRecoverable {
			if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
				return tpmNVHistoryAnchorState{}, err
			}
			if err := syncTPMRootDirectory(filepath.Dir(a.cfg.StatePath)); err != nil {
				return tpmNVHistoryAnchorState{}, err
			}
			return committed, nil
		}
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: unexpected pending state committed=%d pending=%d counter=%d",
			ErrTPMHistoryAnchorRollback,
			committed.Generation,
			pending.Generation,
			generation,
		)
	}

	if pendingRecoverable && pendingProtected {
		switch generation {
		case committed.Generation:
			advanced, err := a.helper.incrementCounter(ctx)
			if err != nil {
				return tpmNVHistoryAnchorState{}, fmt.Errorf(
					"finish TPM history counter after exact-head commit: %w",
					err,
				)
			}
			if advanced != pending.Generation {
				return tpmNVHistoryAnchorState{}, fmt.Errorf(
					"%w: counter=%d pending_generation=%d",
					ErrTPMHistoryAnchorRollback,
					advanced,
					pending.Generation,
				)
			}
		case pending.Generation:
			// Counter and exact head are already committed; only the companion
			// promotion was interrupted.
		default:
			return tpmNVHistoryAnchorState{}, fmt.Errorf(
				"%w: counter=%d committed=%d pending=%d",
				ErrTPMHistoryAnchorRollback,
				generation,
				committed.Generation,
				pending.Generation,
			)
		}
		if err := promoteTPMNVHistoryAnchorPending(pendingPath, a.cfg.StatePath); err != nil {
			return tpmNVHistoryAnchorState{}, err
		}
		return pending, nil
	}

	return tpmNVHistoryAnchorState{}, fmt.Errorf(
		"%w: committed=(gen=%d seq=%d head=%s) pending=(gen=%d seq=%d head=%s) counter=%d protected=(gen=%d seq=%d head=%s)",
		ErrTPMHistoryAnchorRollback,
		committed.Generation,
		committed.Sequence,
		committed.HeadDigest,
		pending.Generation,
		pending.Sequence,
		pending.HeadDigest,
		generation,
		protectedHead.Generation,
		protectedHead.Sequence,
		protectedHead.HeadDigest,
	)
}

func isTPMHistoryAnchorPendingSuccessor(
	committed,
	pending tpmNVHistoryAnchorState,
) bool {
	return pending.PreviousGeneration == committed.Generation &&
		pending.Generation == committed.Generation+1 &&
		pending.PreviousSequence == committed.Sequence &&
		pending.Sequence == committed.Sequence+1 &&
		pending.PreviousHeadDigest == committed.HeadDigest &&
		pending.HeadDigest != ""
}

func isTPMHistoryAnchorPendingMigration(
	committed,
	pending tpmNVHistoryAnchorState,
) bool {
	return committed.Sequence == 0 &&
		committed.HeadDigest == "" &&
		pending.TransitionKind == tpmHistoryTransitionMigrationImport &&
		pending.PreviousGeneration == committed.Generation &&
		pending.Generation == committed.Generation+1 &&
		pending.PreviousSequence == 0 &&
		pending.PreviousHeadDigest == "" &&
		pending.Sequence > 0 &&
		pending.HeadDigest != "" &&
		validSHA256Ref(pending.PredecessorDeviceIdentity) &&
		validSHA256Ref(pending.MigrationSourceStateDigest) &&
		validSHA256Ref(pending.MigrationAuthorizationDigest)
}

func publicTPMHistoryAnchorState(
	state tpmNVHistoryAnchorState,
) kernelfabric.TaintRecoveryHistoryAnchorState {
	return kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   state.Sequence,
		HeadDigest: state.HeadDigest,
	}
}

func historyAnchorRootConfig(cfg TPMNVHistoryAnchorConfig) TPMNVMonotonicRootConfig {
	return TPMNVMonotonicRootConfig{
		NVIndex:         cfg.NVIndex,
		StatePath:       filepath.Clean(cfg.StatePath),
		OwnerAuth:       append([]byte(nil), cfg.OwnerAuth...),
		EndorsementAuth: append([]byte(nil), cfg.EndorsementAuth...),
		IndexAuth:       append([]byte(nil), cfg.IndexAuth...),
	}
}

func validateTPMHistoryAnchorPublicState(
	state kernelfabric.TaintRecoveryHistoryAnchorState,
) error {
	if state.Sequence == 0 {
		if state.HeadDigest != "" {
			return fmt.Errorf(
				"%w: sequence zero cannot carry a head digest",
				ErrTPMHistoryAnchorInvalid,
			)
		}
		return nil
	}
	if state.HeadDigest == "" {
		return fmt.Errorf(
			"%w: nonzero sequence requires a head digest",
			ErrTPMHistoryAnchorInvalid,
		)
	}
	return validateTPMHistoryHeadDigest(state.HeadDigest)
}

func validateTPMHistoryHeadDigest(digest string) error {
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("%w: invalid head digest %q", ErrTPMHistoryAnchorInvalid, digest)
	}
	raw := strings.TrimPrefix(digest, "sha256:")
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%w: invalid head digest %q", ErrTPMHistoryAnchorInvalid, digest)
	}
	return nil
}

func readTPMNVHistoryAnchorState(path string) (tpmNVHistoryAnchorState, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return tpmNVHistoryAnchorState{}, false, nil
		}
		return tpmNVHistoryAnchorState{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return tpmNVHistoryAnchorState{}, false, fmt.Errorf(
			"%w: state path is symlink: %s",
			ErrTPMHistoryAnchorInvalid,
			path,
		)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tpmNVHistoryAnchorState{}, false, err
	}
	var state tpmNVHistoryAnchorState
	if err := json.Unmarshal(data, &state); err != nil {
		return tpmNVHistoryAnchorState{}, false, fmt.Errorf(
			"%w: decode state: %v",
			ErrTPMHistoryAnchorInvalid,
			err,
		)
	}
	if err := verifyTPMNVHistoryAnchorState(state); err != nil {
		return tpmNVHistoryAnchorState{}, false, err
	}
	return state, true, nil
}

func writeTPMNVHistoryAnchorStateAtomic(
	path string,
	state tpmNVHistoryAnchorState,
) error {
	sealed, err := sealTPMNVHistoryAnchorState(state)
	if err != nil {
		return err
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".tpm-history-anchor-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncTPMRootDirectory(dir)
}

func promoteTPMNVHistoryAnchorPending(pendingPath, committedPath string) error {
	if err := os.Rename(pendingPath, committedPath); err != nil {
		return err
	}
	return syncTPMRootDirectory(filepath.Dir(committedPath))
}

func sealTPMNVHistoryAnchorState(
	state tpmNVHistoryAnchorState,
) (tpmNVHistoryAnchorState, error) {
	state.Version = tpmNVHistoryAnchorStateVersion
	if strings.TrimSpace(state.DeviceIdentity) == "" ||
		strings.TrimSpace(state.MeasuredBootIdentity) == "" ||
		state.Generation == 0 {
		return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
	}
	if err := validateTPMHistoryMigrationLineage(state); err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	if state.Sequence == 0 {
		if state.HeadDigest != "" ||
			state.PreviousSequence != 0 ||
			state.PreviousHeadDigest != "" ||
			state.TransitionKind != "" ||
			state.PredecessorDeviceIdentity != "" ||
			state.MigrationSourceStateDigest != "" ||
			state.MigrationAuthorizationDigest != "" {
			return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
		}
	} else {
		if err := validateTPMHistoryHeadDigest(state.HeadDigest); err != nil {
			return tpmNVHistoryAnchorState{}, err
		}
		switch state.TransitionKind {
		case "":
			if state.PreviousSequence+1 != state.Sequence {
				return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
			}
			if state.Sequence > 1 && state.PreviousHeadDigest == "" {
				return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
			}
			if state.PreviousHeadDigest != "" {
				if err := validateTPMHistoryHeadDigest(state.PreviousHeadDigest); err != nil {
					return tpmNVHistoryAnchorState{}, err
				}
			}
		case tpmHistoryTransitionMigrationImport:
			if state.PreviousSequence != 0 ||
				state.PreviousHeadDigest != "" ||
				state.PredecessorDeviceIdentity == "" ||
				state.MigrationSourceStateDigest == "" ||
				state.MigrationAuthorizationDigest == "" {
				return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
			}
		default:
			return tpmNVHistoryAnchorState{}, ErrTPMHistoryAnchorInvalid
		}
	}
	state.Digest = ""
	payload, err := json.Marshal(state)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	sum := sha256.Sum256(payload)
	state.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return state, nil
}

func validateTPMHistoryMigrationLineage(state tpmNVHistoryAnchorState) error {
	values := []string{
		state.PredecessorDeviceIdentity,
		state.MigrationSourceStateDigest,
		state.MigrationAuthorizationDigest,
	}
	present := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != len(values) {
		return ErrTPMHistoryAnchorInvalid
	}
	if !validSHA256Ref(state.PredecessorDeviceIdentity) ||
		!validSHA256Ref(state.MigrationSourceStateDigest) ||
		!validSHA256Ref(state.MigrationAuthorizationDigest) {
		return ErrTPMHistoryAnchorInvalid
	}
	if state.PredecessorDeviceIdentity == state.DeviceIdentity {
		return ErrTPMHistoryAnchorInvalid
	}
	return nil
}

func verifyTPMNVHistoryAnchorState(state tpmNVHistoryAnchorState) error {
	if state.Version != tpmNVHistoryAnchorStateVersion ||
		strings.TrimSpace(state.DeviceIdentity) == "" ||
		strings.TrimSpace(state.MeasuredBootIdentity) == "" ||
		state.Generation == 0 {
		return ErrTPMHistoryAnchorInvalid
	}
	expected := state.Digest
	sealed, err := sealTPMNVHistoryAnchorState(state)
	if err != nil {
		return err
	}
	if expected == "" || expected != sealed.Digest {
		return fmt.Errorf("%w: digest mismatch", ErrTPMHistoryAnchorInvalid)
	}
	return nil
}
