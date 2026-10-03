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
	ErrTPMHistoryAnchorUnprovisioned      = errors.New("TPM history anchor is not provisioned")
	ErrTPMHistoryAnchorRollback           = errors.New("TPM history anchor rollback detected")
	ErrTPMHistoryAnchorInvalid            = errors.New("TPM history anchor state is invalid")
	ErrTPMHistoryAnchorDeviceChanged      = errors.New("TPM history anchor device identity changed")
	ErrTPMHistoryAnchorMeasuredBootChanged = errors.New("TPM history anchor measured boot identity changed")
)

type TPMNVHistoryAnchorConfig struct {
	NVIndex         tpm2.TPMHandle
	StatePath       string
	OwnerAuth       []byte
	EndorsementAuth []byte
	IndexAuth       []byte
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
	HeadDigest           string `json:"head_digest,omitempty"`
	PreviousHeadDigest   string `json:"previous_head_digest,omitempty"`
	Digest                string `json:"digest"`
}

var _ kernelfabric.TaintRecoveryHistoryAnchor = (*TPMNVHistoryAnchor)(nil)

func ProvisionTPMNVHistoryAnchor(
	ctx context.Context,
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) error {
	rootCfg := historyAnchorRootConfig(cfg)
	if err := validateTPMNVRootConfig(device, rootCfg); err != nil {
		return err
	}
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

	def := tpm2.NVDefineSpace{
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
	if _, err := def.Execute(device); err != nil {
		return fmt.Errorf("define TPM history counter 0x%x: %w", uint32(cfg.NVIndex), err)
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

	return writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath, tpmNVHistoryAnchorState{
		Version:              tpmNVHistoryAnchorStateVersion,
		DeviceIdentity:       deviceIdentity,
		MeasuredBootIdentity: measuredBootIdentity,
		Generation:           generation,
	})
}

func NewTPMNVHistoryAnchor(
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) (*TPMNVHistoryAnchor, error) {
	rootCfg := historyAnchorRootConfig(cfg)
	helper, err := NewTPMNVMonotonicRoot(device, rootCfg)
	if err != nil {
		return nil, err
	}
	cfg.StatePath = filepath.Clean(cfg.StatePath)
	cfg.OwnerAuth = append([]byte(nil), cfg.OwnerAuth...)
	cfg.EndorsementAuth = append([]byte(nil), cfg.EndorsementAuth...)
	cfg.IndexAuth = append([]byte(nil), cfg.IndexAuth...)
	return &TPMNVHistoryAnchor{helper: helper, cfg: cfg}, nil
}

func (a *TPMNVHistoryAnchor) Advance(
	ctx context.Context,
	previousDigest,
	nextDigest string,
) error {
	if previousDigest != "" {
		if err := validateTPMHistoryHeadDigest(previousDigest); err != nil {
			return err
		}
	}
	if err := validateTPMHistoryHeadDigest(nextDigest); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := a.recoverLocked(ctx)
	if err != nil {
		return err
	}
	if state.HeadDigest == nextDigest {
		if state.PreviousHeadDigest != previousDigest {
			return fmt.Errorf(
				"%w: idempotent predecessor mismatch: got=%s want=%s",
				ErrTPMHistoryAnchorInvalid,
				previousDigest,
				state.PreviousHeadDigest,
			)
		}
		return nil
	}
	if state.HeadDigest != previousDigest {
		return fmt.Errorf(
			"%w: predecessor mismatch: anchor=%s expected=%s next=%s",
			ErrTPMHistoryAnchorRollback,
			state.HeadDigest,
			previousDigest,
			nextDigest,
		)
	}
	if state.Generation == ^uint64(0) {
		return fmt.Errorf("%w: generation exhausted", ErrTPMHistoryAnchorInvalid)
	}

	next := state
	next.PreviousGeneration = state.Generation
	next.Generation = state.Generation + 1
	next.PreviousHeadDigest = state.HeadDigest
	next.HeadDigest = nextDigest
	next.Digest = ""

	pendingPath := a.cfg.StatePath + ".pending"
	if err := writeTPMNVHistoryAnchorStateAtomic(pendingPath, next); err != nil {
		return fmt.Errorf("persist pending TPM history anchor: %w", err)
	}
	generation, err := a.helper.incrementCounter(ctx)
	if err != nil {
		return fmt.Errorf("increment TPM history counter: %w", err)
	}
	if generation != next.Generation {
		return fmt.Errorf(
			"%w: counter=%d expected=%d",
			ErrTPMHistoryAnchorRollback,
			generation,
			next.Generation,
		)
	}
	if err := promoteTPMNVHistoryAnchorPending(pendingPath, a.cfg.StatePath); err != nil {
		return fmt.Errorf("promote TPM history anchor: %w", err)
	}
	return nil
}

func (a *TPMNVHistoryAnchor) Current(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.recoverLocked(ctx)
	if err != nil {
		return "", err
	}
	return state.HeadDigest, nil
}

func (a *TPMNVHistoryAnchor) recoverLocked(ctx context.Context) (tpmNVHistoryAnchorState, error) {
	generation, err := a.helper.readCounter(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, fmt.Errorf("read TPM history counter: %w", err)
	}
	committed, committedOK, err := readTPMNVHistoryAnchorState(a.cfg.StatePath)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	if !committedOK {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: state=%s counter=%d",
			ErrTPMHistoryAnchorUnprovisioned,
			a.cfg.StatePath,
			generation,
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
		return tpmNVHistoryAnchorState{}, fmt.Errorf("read TPM history measured boot identity: %w", err)
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

	if committed.Generation == generation {
		if !pendingOK {
			return committed, nil
		}
		if pending.PreviousGeneration == committed.Generation &&
			pending.Generation == committed.Generation+1 &&
			pending.PreviousHeadDigest == committed.HeadDigest {
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

	if pendingOK &&
		pending.Generation == generation &&
		pending.PreviousGeneration == committed.Generation &&
		committed.Generation+1 == pending.Generation &&
		pending.PreviousHeadDigest == committed.HeadDigest {
		if err := promoteTPMNVHistoryAnchorPending(pendingPath, a.cfg.StatePath); err != nil {
			return tpmNVHistoryAnchorState{}, err
		}
		return pending, nil
	}

	return tpmNVHistoryAnchorState{}, fmt.Errorf(
		"%w: committed=%d pending=%d counter=%d",
		ErrTPMHistoryAnchorRollback,
		committed.Generation,
		pending.Generation,
		generation,
	)
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

func writeTPMNVHistoryAnchorStateAtomic(path string, state tpmNVHistoryAnchorState) error {
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
	if state.HeadDigest != "" {
		if err := validateTPMHistoryHeadDigest(state.HeadDigest); err != nil {
			return tpmNVHistoryAnchorState{}, err
		}
	}
	if state.PreviousHeadDigest != "" {
		if err := validateTPMHistoryHeadDigest(state.PreviousHeadDigest); err != nil {
			return tpmNVHistoryAnchorState{}, err
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
