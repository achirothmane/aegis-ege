package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const tpmNVRootStateVersion = "aegis.ege/tpm-nv-monotonic-root/v3"

var tpmRootMeasuredBootPCRs = []uint{0, 2, 4, 7}

var (
	ErrTPMMonotonicRootUnprovisioned = errors.New("TPM monotonic root is not provisioned")
	ErrTPMMonotonicRootScopeMissing  = errors.New("TPM monotonic root scope is not initialized")
	ErrTPMMonotonicRootRollback      = errors.New("TPM monotonic root rollback detected")
	ErrTPMMonotonicRootDeviceChanged       = errors.New("TPM monotonic root device identity changed")
	ErrTPMMonotonicRootMeasuredBootChanged = errors.New("TPM monotonic root measured boot identity changed")
	ErrTPMMonotonicRootInvalid             = errors.New("TPM monotonic root state is invalid")
)

type TPMNVMonotonicRootConfig struct {
	NVIndex          tpm2.TPMHandle
	StatePath        string
	OwnerAuth        []byte
	EndorsementAuth  []byte
	IndexAuth        []byte
}

type TPMNVMonotonicRoot struct {
	tpm transport.TPM
	cfg TPMNVMonotonicRootConfig
	mu  sync.Mutex
}

var _ kernelfabric.PlatformMeasurementSource = (*TPMNVMonotonicRoot)(nil)

type tpmNVRootState struct {
	Version                      string                                           `json:"version"`
	DeviceIdentity               string                                           `json:"device_identity"`
	MeasuredBootIdentity         string                                           `json:"measured_boot_identity"`
	Generation                   uint64                                           `json:"generation"`
	PreviousGeneration           uint64                                           `json:"previous_generation,omitempty"`
	PredecessorDeviceIdentity    string                                           `json:"predecessor_device_identity,omitempty"`
	MigrationSourceStateDigest   string                                           `json:"migration_source_state_digest,omitempty"`
	MigrationAuthorizationDigest           string                                           `json:"migration_authorization_digest,omitempty"`
	MigrationDestinationAttestationDigest string                                           `json:"migration_destination_attestation_digest,omitempty"`
	Scopes                                 map[string]egeproto.CapabilityAuthoritySnapshot `json:"scopes"`
	Digest                       string                                           `json:"digest"`
}

func ProvisionTPMNVMonotonicRoot(ctx context.Context, device transport.TPM, cfg TPMNVMonotonicRootConfig) error {
	if err := validateTPMNVRootConfig(device, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, path := range []string{cfg.StatePath, cfg.StatePath + ".pending"} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%w: state path already exists: %s", ErrTPMMonotonicRootInvalid, path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(cfg.OwnerAuth),
		},
		Auth:       tpm2.TPM2BAuth{Buffer: append([]byte(nil), cfg.IndexAuth...)},
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
		return fmt.Errorf("define TPM NV counter 0x%x: %w", uint32(cfg.NVIndex), err)
	}

	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		return err
	}
	deviceIdentity, err := root.deviceIdentity(ctx)
	if err != nil {
		return fmt.Errorf("bind TPM monotonic root device identity: %w", err)
	}
	measuredBootIdentity, err := root.measuredBootIdentity(ctx)
	if err != nil {
		return fmt.Errorf("bind TPM monotonic root measured boot identity: %w", err)
	}
	generation, err := root.incrementCounter(ctx)
	if err != nil {
		return fmt.Errorf("initialize TPM NV counter: %w", err)
	}
	return writeTPMNVRootStateAtomic(cfg.StatePath, tpmNVRootState{
		Version:              tpmNVRootStateVersion,
		DeviceIdentity:       deviceIdentity,
		MeasuredBootIdentity: measuredBootIdentity,
		Generation:           generation,
		Scopes:         map[string]egeproto.CapabilityAuthoritySnapshot{},
	})
}

func NewTPMNVMonotonicRoot(device transport.TPM, cfg TPMNVMonotonicRootConfig) (*TPMNVMonotonicRoot, error) {
	if err := validateTPMNVRootConfig(device, cfg); err != nil {
		return nil, err
	}
	cfg.StatePath = filepath.Clean(cfg.StatePath)
	cfg.OwnerAuth = append([]byte(nil), cfg.OwnerAuth...)
	cfg.EndorsementAuth = append([]byte(nil), cfg.EndorsementAuth...)
	cfg.IndexAuth = append([]byte(nil), cfg.IndexAuth...)
	return &TPMNVMonotonicRoot{tpm: device, cfg: cfg}, nil
}

func (r *TPMNVMonotonicRoot) Advance(ctx context.Context, scope CapabilityFenceScope, observed egeproto.CapabilityAuthoritySnapshot) (egeproto.CapabilityAuthoritySnapshot, error) {
	if err := validateCapabilityAuthoritySnapshot(observed); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("%w: observed authority: %v", ErrTPMMonotonicRootInvalid, err)
	}
	scopeKey, err := capabilityMonotonicScopeKey(scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.recoverLocked(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	if current, ok := state.Scopes[scopeKey]; ok {
		relation, err := compareCapabilityMonotonicRoot(current, observed)
		if err != nil {
			return egeproto.CapabilityAuthoritySnapshot{}, err
		}
		switch relation {
		case capabilityRootEqual, capabilityRootAhead:
			return current, nil
		case capabilityRootBehind:
		default:
			return egeproto.CapabilityAuthoritySnapshot{}, ErrTPMMonotonicRootInvalid
		}
	}

	if state.Generation == ^uint64(0) {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("%w: generation exhausted", ErrTPMMonotonicRootInvalid)
	}
	next := cloneTPMNVRootState(state)
	next.PreviousGeneration = state.Generation
	next.Generation = state.Generation + 1
	next.Scopes[scopeKey] = observed

	pendingPath := r.cfg.StatePath + ".pending"
	if err := writeTPMNVRootStateAtomic(pendingPath, next); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("persist pending TPM root state: %w", err)
	}
	generation, err := r.incrementCounter(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("increment TPM root counter: %w", err)
	}
	if generation != next.Generation {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("%w: counter=%d expected=%d", ErrTPMMonotonicRootRollback, generation, next.Generation)
	}
	if err := promoteTPMNVRootPending(pendingPath, r.cfg.StatePath); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("promote TPM root state: %w", err)
	}
	return observed, nil
}

func (r *TPMNVMonotonicRoot) Current(ctx context.Context, scope CapabilityFenceScope) (egeproto.CapabilityAuthoritySnapshot, error) {
	scopeKey, err := capabilityMonotonicScopeKey(scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.recoverLocked(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	current, ok := state.Scopes[scopeKey]
	if !ok {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("%w: %s", ErrTPMMonotonicRootScopeMissing, scopeKey)
	}
	return current, nil
}

// CurrentPlatformMeasurement exports the currently verified platform boot
// measurement through the generic kernelfabric contract. recoverLocked performs
// the TPM counter, device-identity, measured-boot, pending-state, and rollback
// checks before any commitment is returned.
func (r *TPMNVMonotonicRoot) CurrentPlatformMeasurement(
	ctx context.Context,
) (kernelfabric.PlatformMeasurementCommitment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.recoverLocked(ctx)
	if err != nil {
		return kernelfabric.PlatformMeasurementCommitment{}, err
	}
	return kernelfabric.NewPlatformMeasurementCommitment(
		kernelfabric.PlatformMeasurementClassMeasuredBoot,
		state.DeviceIdentity,
		state.MeasuredBootIdentity,
		state.Generation,
	)
}

func (r *TPMNVMonotonicRoot) recoverLocked(ctx context.Context) (tpmNVRootState, error) {
	generation, err := r.readCounter(ctx)
	if err != nil {
		return tpmNVRootState{}, fmt.Errorf("read TPM root counter: %w", err)
	}
	committed, committedOK, err := readTPMNVRootState(r.cfg.StatePath)
	if err != nil {
		return tpmNVRootState{}, err
	}
	if !committedOK {
		return tpmNVRootState{}, fmt.Errorf("%w: state=%s counter=%d", ErrTPMMonotonicRootUnprovisioned, r.cfg.StatePath, generation)
	}
	deviceIdentity, err := r.deviceIdentity(ctx)
	if err != nil {
		return tpmNVRootState{}, fmt.Errorf("read TPM root device identity: %w", err)
	}
	if committed.DeviceIdentity != deviceIdentity {
		return tpmNVRootState{}, fmt.Errorf("%w: enrolled=%s observed=%s", ErrTPMMonotonicRootDeviceChanged, committed.DeviceIdentity, deviceIdentity)
	}
	measuredBootIdentity, err := r.measuredBootIdentity(ctx)
	if err != nil {
		return tpmNVRootState{}, fmt.Errorf("read TPM root measured boot identity: %w", err)
	}
	if committed.MeasuredBootIdentity != measuredBootIdentity {
		return tpmNVRootState{}, fmt.Errorf("%w: enrolled=%s observed=%s", ErrTPMMonotonicRootMeasuredBootChanged, committed.MeasuredBootIdentity, measuredBootIdentity)
	}
	pendingPath := r.cfg.StatePath + ".pending"
	pending, pendingOK, err := readTPMNVRootState(pendingPath)
	if err != nil {
		return tpmNVRootState{}, err
	}
	if pendingOK && pending.DeviceIdentity != committed.DeviceIdentity {
		return tpmNVRootState{}, fmt.Errorf("%w: committed=%s pending=%s", ErrTPMMonotonicRootDeviceChanged, committed.DeviceIdentity, pending.DeviceIdentity)
	}
	if pendingOK && pending.MeasuredBootIdentity != committed.MeasuredBootIdentity {
		return tpmNVRootState{}, fmt.Errorf("%w: committed=%s pending=%s", ErrTPMMonotonicRootMeasuredBootChanged, committed.MeasuredBootIdentity, pending.MeasuredBootIdentity)
	}

	if committed.Generation == generation {
		if !pendingOK {
			return committed, nil
		}
		if pending.PreviousGeneration == committed.Generation && pending.Generation == committed.Generation+1 {
			if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
				return tpmNVRootState{}, err
			}
			if err := syncTPMRootDirectory(filepath.Dir(r.cfg.StatePath)); err != nil {
				return tpmNVRootState{}, err
			}
			return committed, nil
		}
		return tpmNVRootState{}, fmt.Errorf("%w: unexpected pending state committed=%d pending=%d counter=%d", ErrTPMMonotonicRootRollback, committed.Generation, pending.Generation, generation)
	}

	if pendingOK &&
		pending.Generation == generation &&
		pending.PreviousGeneration == committed.Generation &&
		committed.Generation+1 == pending.Generation {
		if err := promoteTPMNVRootPending(pendingPath, r.cfg.StatePath); err != nil {
			return tpmNVRootState{}, err
		}
		return pending, nil
	}

	return tpmNVRootState{}, fmt.Errorf("%w: committed=%d pending=%d counter=%d", ErrTPMMonotonicRootRollback, committed.Generation, pending.Generation, generation)
}

func (r *TPMNVMonotonicRoot) deviceIdentity(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	response, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(r.cfg.EndorsementAuth),
		},
		InPublic: tpm2.New2B(tpm2.ECCEKTemplate),
	}).Execute(r.tpm)
	if err != nil {
		return "", err
	}
	defer func() {
		_, _ = (tpm2.FlushContext{FlushHandle: response.ObjectHandle}).Execute(r.tpm)
	}()
	if len(response.Name.Buffer) == 0 {
		return "", fmt.Errorf("%w: empty endorsement primary name", ErrTPMMonotonicRootInvalid)
	}
	sum := sha256.Sum256(response.Name.Buffer)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (r *TPMNVMonotonicRoot) measuredBootIdentity(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	selection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpmRootMeasuredBootPCRs...),
			},
		},
	}
	response, err := (tpm2.PCRRead{PCRSelectionIn: selection}).Execute(r.tpm)
	if err != nil {
		return "", err
	}
	if len(response.PCRValues.Digests) != len(tpmRootMeasuredBootPCRs) {
		return "", fmt.Errorf("%w: measured boot PCR count=%d want=%d", ErrTPMMonotonicRootInvalid, len(response.PCRValues.Digests), len(tpmRootMeasuredBootPCRs))
	}
	h := sha256.New()
	_, _ = h.Write([]byte("aegis.ege/tpm-measured-boot/v1\x00"))
	for i, pcr := range tpmRootMeasuredBootPCRs {
		digest := response.PCRValues.Digests[i].Buffer
		if len(digest) != sha256.Size {
			return "", fmt.Errorf("%w: PCR %d digest size=%d", ErrTPMMonotonicRootInvalid, pcr, len(digest))
		}
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], uint32(pcr))
		_, _ = h.Write(index[:])
		_, _ = h.Write(digest)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (r *TPMNVMonotonicRoot) readCounter(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	pub, err := r.readNVPublic()
	if err != nil {
		return 0, err
	}
	authHandle := tpm2.AuthHandle{Handle: r.cfg.NVIndex, Name: pub.NVName, Auth: tpm2.PasswordAuth(r.cfg.IndexAuth)}
	response, err := (tpm2.NVRead{
		AuthHandle: authHandle,
		NVIndex:    tpm2.NamedHandle{Handle: r.cfg.NVIndex, Name: pub.NVName},
		Size:       8,
	}).Execute(r.tpm)
	if err != nil {
		return 0, err
	}
	if len(response.Data.Buffer) != 8 {
		return 0, fmt.Errorf("%w: counter returned %d bytes", ErrTPMMonotonicRootInvalid, len(response.Data.Buffer))
	}
	return binary.BigEndian.Uint64(response.Data.Buffer), nil
}

func (r *TPMNVMonotonicRoot) incrementCounter(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	pub, err := r.readNVPublic()
	if err != nil {
		return 0, err
	}
	authHandle := tpm2.AuthHandle{Handle: r.cfg.NVIndex, Name: pub.NVName, Auth: tpm2.PasswordAuth(r.cfg.IndexAuth)}
	if _, err := (tpm2.NVIncrement{
		AuthHandle: authHandle,
		NVIndex:    tpm2.NamedHandle{Handle: r.cfg.NVIndex, Name: pub.NVName},
	}).Execute(r.tpm); err != nil {
		return 0, err
	}
	return r.readCounter(ctx)
}

func (r *TPMNVMonotonicRoot) readNVPublic() (*tpm2.NVReadPublicResponse, error) {
	response, err := (tpm2.NVReadPublic{NVIndex: r.cfg.NVIndex}).Execute(r.tpm)
	if err != nil {
		return nil, err
	}
	public, err := response.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	if public.NVIndex != r.cfg.NVIndex || public.Attributes.NT != tpm2.TPMNTCounter || public.DataSize != 8 {
		return nil, fmt.Errorf("%w: NV index 0x%x is not expected counter", ErrTPMMonotonicRootInvalid, uint32(r.cfg.NVIndex))
	}
	return response, nil
}

func validateTPMNVRootConfig(device transport.TPM, cfg TPMNVMonotonicRootConfig) error {
	if device == nil {
		return fmt.Errorf("%w: TPM transport required", ErrTPMMonotonicRootInvalid)
	}
	if cfg.NVIndex == 0 {
		return fmt.Errorf("%w: NV index required", ErrTPMMonotonicRootInvalid)
	}
	if strings.TrimSpace(cfg.StatePath) == "" {
		return fmt.Errorf("%w: state path required", ErrTPMMonotonicRootInvalid)
	}
	return nil
}

func capabilityMonotonicScopeKey(scope CapabilityFenceScope) (string, error) {
	parts := []string{
		strings.TrimSpace(scope.IntentID),
		strings.TrimSpace(scope.Kind),
		strings.TrimSpace(scope.Target.Type),
		strings.TrimSpace(scope.Target.Name),
	}
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("%w: complete capability scope required", ErrTPMMonotonicRootInvalid)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cloneTPMNVRootState(state tpmNVRootState) tpmNVRootState {
	cloned := state
	cloned.Scopes = make(map[string]egeproto.CapabilityAuthoritySnapshot, len(state.Scopes))
	for key, value := range state.Scopes {
		cloned.Scopes[key] = value
	}
	cloned.Digest = ""
	return cloned
}

func readTPMNVRootState(path string) (tpmNVRootState, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return tpmNVRootState{}, false, nil
		}
		return tpmNVRootState{}, false, err
	}
	var state tpmNVRootState
	if err := json.Unmarshal(data, &state); err != nil {
		return tpmNVRootState{}, false, fmt.Errorf("%w: decode state: %v", ErrTPMMonotonicRootInvalid, err)
	}
	if err := verifyTPMNVRootState(state); err != nil {
		return tpmNVRootState{}, false, err
	}
	return state, true, nil
}

func writeTPMNVRootStateAtomic(path string, state tpmNVRootState) error {
	sealed, err := sealTPMNVRootState(state)
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
	temp, err := os.CreateTemp(dir, ".tpm-root-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
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
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	return syncTPMRootDirectory(dir)
}

func promoteTPMNVRootPending(pendingPath, committedPath string) error {
	if err := os.Rename(pendingPath, committedPath); err != nil {
		return err
	}
	return syncTPMRootDirectory(filepath.Dir(committedPath))
}

func syncTPMRootDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func sealTPMNVRootState(state tpmNVRootState) (tpmNVRootState, error) {
	state.Version = tpmNVRootStateVersion
	if state.Generation == 0 {
		return tpmNVRootState{}, fmt.Errorf("%w: zero generation", ErrTPMMonotonicRootInvalid)
	}
	if state.Scopes == nil {
		state.Scopes = map[string]egeproto.CapabilityAuthoritySnapshot{}
	}
	state.Digest = ""
	payload, err := json.Marshal(state)
	if err != nil {
		return tpmNVRootState{}, err
	}
	sum := sha256.Sum256(payload)
	state.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return state, nil
}

func verifyTPMNVRootState(state tpmNVRootState) error {
	if state.Version != tpmNVRootStateVersion ||
		strings.TrimSpace(state.DeviceIdentity) == "" ||
		strings.TrimSpace(state.MeasuredBootIdentity) == "" ||
		state.Generation == 0 ||
		state.Scopes == nil {
		return ErrTPMMonotonicRootInvalid
	}
	expected := state.Digest
	sealed, err := sealTPMNVRootState(state)
	if err != nil {
		return err
	}
	if expected == "" || expected != sealed.Digest {
		return fmt.Errorf("%w: digest mismatch", ErrTPMMonotonicRootInvalid)
	}
	for _, snapshot := range state.Scopes {
		if err := validateCapabilityAuthoritySnapshot(snapshot); err != nil {
			return fmt.Errorf("%w: invalid snapshot: %v", ErrTPMMonotonicRootInvalid, err)
		}
	}
	return nil
}
