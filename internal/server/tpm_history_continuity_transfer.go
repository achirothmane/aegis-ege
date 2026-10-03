//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const (
	TPMHistoryContinuityTransferAuthorizationVersion = "aegis.ege/tpm-history-continuity-transfer-authorization/v1"
	tpmHistoryTransitionMigrationImport               = "migration-import"
)

var (
	ErrTPMHistoryContinuityAuthorization = errors.New("TPM history continuity transfer authorization is invalid")
	ErrTPMHistoryContinuityDestination   = errors.New("TPM history continuity transfer destination is invalid")
	ErrTPMHistoryContinuityReplay        = errors.New("TPM history continuity transfer replay detected")
	ErrTPMHistoryContinuityWitness       = errors.New("TPM history continuity witness mismatch")
)

type TPMHistoryContinuityTransferAuthorization struct {
	Version                            string    `json:"version"`
	TransferID                         string    `json:"transfer_id"`
	HistoryWitnessID                   string    `json:"history_witness_id"`
	HistoryWitnessPolicyHash           string    `json:"history_witness_policy_hash"`
	OwnershipWitnessID                 string    `json:"ownership_witness_id"`
	OwnershipWitnessPolicyHash         string    `json:"ownership_witness_policy_hash"`
	SourceDeviceIdentity               string    `json:"source_device_identity"`
	SourceMeasuredBootIdentity         string    `json:"source_measured_boot_identity"`
	SourceStateDigest                  string    `json:"source_state_digest"`
	SourceGeneration                   uint64    `json:"source_generation"`
	SourceSequence                     uint64    `json:"source_sequence"`
	SourceHeadDigest                   string    `json:"source_head_digest"`
	SourceOwnershipEpoch               uint64    `json:"source_ownership_epoch"`
	SourceOwnershipAuthorizationDigest string    `json:"source_ownership_authorization_digest,omitempty"`
	DestinationDeviceIdentity          string    `json:"destination_device_identity"`
	DestinationMeasuredBootIdentity    string    `json:"destination_measured_boot_identity"`
	DestinationStateDigest             string    `json:"destination_state_digest"`
	DestinationGeneration              uint64    `json:"destination_generation"`
	DestinationNVIndex                 uint32    `json:"destination_nv_index"`
	DestinationHeadNVIndex             uint32    `json:"destination_head_nv_index"`
	DestinationAttestationDigest         string    `json:"destination_attestation_digest"`
	DestinationAttestationGenesisEpoch   uint64    `json:"destination_attestation_genesis_epoch"`
	DestinationAttestationTrustRootRef   string    `json:"destination_attestation_trust_root_ref"`
	DestinationAttestationTrustRootEpoch uint64    `json:"destination_attestation_trust_root_epoch"`
	DestinationAttestationPolicyHash     string    `json:"destination_attestation_policy_hash"`
	NotBefore                            time.Time `json:"not_before"`
	ExpiresAt                          time.Time `json:"expires_at"`
}

type SignedTPMHistoryContinuityTransferAuthorization struct {
	Authorization TPMHistoryContinuityTransferAuthorization `json:"authorization"`
	KeyID         string                                    `json:"key_id"`
	Signature     string                                    `json:"signature"`
}

func ValidateTPMHistoryContinuityTransferAuthorization(
	auth TPMHistoryContinuityTransferAuthorization,
) error {
	if auth.Version != TPMHistoryContinuityTransferAuthorizationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTPMHistoryContinuityAuthorization, auth.Version)
	}
	if strings.TrimSpace(auth.TransferID) == "" ||
		strings.TrimSpace(auth.HistoryWitnessID) == "" ||
		strings.TrimSpace(auth.OwnershipWitnessID) == "" {
		return fmt.Errorf("%w: transfer and witness ids are required", ErrTPMHistoryContinuityAuthorization)
	}
	if !validSHA256Ref(auth.HistoryWitnessPolicyHash) ||
		!validSHA256Ref(auth.OwnershipWitnessPolicyHash) ||
		!validSHA256Ref(auth.DestinationAttestationDigest) ||
		!validSHA256Ref(auth.DestinationAttestationPolicyHash) {
		return fmt.Errorf("%w: witness policy or destination attestation binding is invalid", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.DestinationAttestationGenesisEpoch == 0 ||
		auth.DestinationAttestationTrustRootEpoch == 0 ||
		strings.TrimSpace(auth.DestinationAttestationTrustRootRef) == "" {
		return fmt.Errorf("%w: destination attestation trust binding is invalid", ErrTPMHistoryContinuityAuthorization)
	}
	if !validSHA256Ref(auth.SourceDeviceIdentity) ||
		!validSHA256Ref(auth.SourceMeasuredBootIdentity) ||
		!validSHA256Ref(auth.SourceStateDigest) ||
		!validSHA256Ref(auth.SourceHeadDigest) ||
		!validSHA256Ref(auth.DestinationDeviceIdentity) ||
		!validSHA256Ref(auth.DestinationMeasuredBootIdentity) ||
		!validSHA256Ref(auth.DestinationStateDigest) {
		return fmt.Errorf("%w: digest-bound identity or state field is invalid", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.SourceDeviceIdentity == auth.DestinationDeviceIdentity {
		return fmt.Errorf("%w: source and destination devices must differ", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.SourceGeneration == 0 || auth.SourceSequence == 0 || auth.DestinationGeneration == 0 {
		return fmt.Errorf("%w: source history and destination generation must be non-zero", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.DestinationNVIndex == 0 ||
		auth.DestinationHeadNVIndex == 0 ||
		auth.DestinationNVIndex == auth.DestinationHeadNVIndex {
		return fmt.Errorf("%w: destination TPM NV indexes are invalid", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.SourceOwnershipEpoch == 0 {
		if auth.SourceOwnershipAuthorizationDigest != "" {
			return fmt.Errorf("%w: genesis ownership cannot carry prior authorization", ErrTPMHistoryContinuityAuthorization)
		}
	} else if !validSHA256Ref(auth.SourceOwnershipAuthorizationDigest) {
		return fmt.Errorf("%w: source ownership authorization digest is invalid", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.NotBefore.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.NotBefore) {
		return fmt.Errorf("%w: validity window is invalid", ErrTPMHistoryContinuityAuthorization)
	}
	return nil
}

func SignTPMHistoryContinuityTransferAuthorization(
	auth TPMHistoryContinuityTransferAuthorization,
	privateKey ed25519.PrivateKey,
) (SignedTPMHistoryContinuityTransferAuthorization, error) {
	if err := ValidateTPMHistoryContinuityTransferAuthorization(auth); err != nil {
		return SignedTPMHistoryContinuityTransferAuthorization{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTPMHistoryContinuityTransferAuthorization{}, errors.New("invalid Ed25519 history continuity transfer key")
	}
	payload, err := canonicalTPMHistoryContinuityTransferAuthorizationPayload(auth)
	if err != nil {
		return SignedTPMHistoryContinuityTransferAuthorization{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedTPMHistoryContinuityTransferAuthorization{
		Authorization: auth,
		KeyID:         tpmHistoryContinuityTransferKeyID(publicKey),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTPMHistoryContinuityTransferAuthorization(
	signed SignedTPMHistoryContinuityTransferAuthorization,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := ValidateTPMHistoryContinuityTransferAuthorization(signed.Authorization); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 public key", ErrTPMHistoryContinuityAuthorization)
	}
	if signed.KeyID != tpmHistoryContinuityTransferKeyID(publicKey) {
		return fmt.Errorf("%w: signer key mismatch", ErrTPMHistoryContinuityAuthorization)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrTPMHistoryContinuityAuthorization)
	}
	payload, err := canonicalTPMHistoryContinuityTransferAuthorizationPayload(signed.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("%w: signature verification failed", ErrTPMHistoryContinuityAuthorization)
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Authorization.NotBefore.UTC()) ||
		!now.Before(signed.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrTPMHistoryContinuityAuthorization)
	}
	return nil
}

func TPMHistoryContinuityTransferAuthorizationDigest(
	signed SignedTPMHistoryContinuityTransferAuthorization,
) (string, error) {
	payload, err := canonicalTPMHistoryContinuityTransferAuthorizationPayload(signed.Authorization)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		Payload   []byte `json:"payload"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{
		Payload: payload,
		KeyID: signed.KeyID,
		Signature: signed.Signature,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/tpm-history-continuity-transfer-commitment/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// TransferTPMNVHistoryContinuity performs a two-phase authority handoff.
//
// The ownership quorum is first moved from the source device to a deterministic
// quiesced identity. At that point neither source nor destination is active.
// Only after the external history head is re-validated while quiesced is the
// exact source head imported into the destination TPM. The quorum is then moved
// to the destination device.
//
// This ordering intentionally prefers temporary unavailability over dual
// authority or an unverified history fork.
func TransferTPMNVHistoryContinuity(
	ctx context.Context,
	sourceStatePath string,
	destination *TPMNVHistoryAnchor,
	historyWitness *ExternalHeadTaintRecoveryHistoryAnchor,
	ownership *TaintRecoveryHistoryOwnershipWitness,
	signed SignedTPMHistoryContinuityTransferAuthorization,
	transferPublicKey ed25519.PublicKey,
	destinationAttestation SignedTPMRootMigrationDestinationAttestation,
	attestationTrust TPMRootMigrationAttestationTrust,
	now time.Time,
) error {
	if destination == nil || historyWitness == nil || ownership == nil {
		return fmt.Errorf("%w: destination and both witnesses are required", ErrTPMHistoryContinuityAuthorization)
	}
	if err := VerifySignedTPMHistoryContinuityTransferAuthorization(signed, transferPublicKey, now); err != nil {
		return err
	}
	if err := attestationTrust.verifySignedAttestation(destinationAttestation, now); err != nil {
		return err
	}
	if len(transferPublicKey) != ed25519.PublicKeySize || attestationTrust.publicKeyEquals(transferPublicKey) {
		return fmt.Errorf(
			"%w: transfer and destination-attestation authorities must be independent",
			ErrTPMHistoryContinuityAuthorization,
		)
	}
	auth := signed.Authorization
	if !attestationTrust.matchesAuthorization(
		auth.DestinationAttestationGenesisEpoch,
		auth.DestinationAttestationTrustRootRef,
		auth.DestinationAttestationTrustRootEpoch,
		auth.DestinationAttestationPolicyHash,
	) {
		return fmt.Errorf(
			"%w: destination attestation trust state does not match Genesis binding",
			ErrTPMHistoryContinuityAuthorization,
		)
	}
	att := destinationAttestation.Attestation
	attestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		return err
	}
	if auth.DestinationAttestationDigest != attestationDigest ||
		att.MigrationID != auth.TransferID ||
		att.DestinationDeviceIdentity != auth.DestinationDeviceIdentity ||
		att.DestinationMeasuredBootIdentity != auth.DestinationMeasuredBootIdentity ||
		att.DestinationGeneration != auth.DestinationGeneration {
		return fmt.Errorf(
			"%w: destination attestation does not match transfer authorization",
			ErrTPMHistoryContinuityAuthorization,
		)
	}
	if auth.HistoryWitnessID != historyWitness.historyID ||
		auth.OwnershipWitnessID != ownership.witnessID {
		return fmt.Errorf("%w: witness identity mismatch", ErrTPMHistoryContinuityAuthorization)
	}
	if auth.HistoryWitnessPolicyHash != historyWitness.QuorumPolicyHash() ||
		auth.OwnershipWitnessPolicyHash != ownership.QuorumPolicyHash() {
		return fmt.Errorf("%w: witness quorum policy mismatch", ErrTPMHistoryContinuityAuthorization)
	}
	if uint32(destination.cfg.NVIndex) != auth.DestinationNVIndex ||
		uint32(destination.cfg.HeadNVIndex) != auth.DestinationHeadNVIndex {
		return fmt.Errorf("%w: destination NV index mismatch", ErrTPMHistoryContinuityDestination)
	}

	commitment, err := TPMHistoryContinuityTransferAuthorizationDigest(signed)
	if err != nil {
		return err
	}
	source, ok, err := readTPMNVHistoryAnchorState(sourceStatePath)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: source history anchor state is missing", ErrTPMHistoryContinuityAuthorization)
	}
	if source.DeviceIdentity != auth.SourceDeviceIdentity ||
		source.MeasuredBootIdentity != auth.SourceMeasuredBootIdentity ||
		source.Digest != auth.SourceStateDigest ||
		source.Generation != auth.SourceGeneration ||
		source.Sequence != auth.SourceSequence ||
		source.HeadDigest != auth.SourceHeadDigest {
		return fmt.Errorf("%w: source state does not match authorization", ErrTPMHistoryContinuityAuthorization)
	}

	expectedOwnership := TaintRecoveryHistoryOwnershipState{
		Epoch:                auth.SourceOwnershipEpoch,
		ActiveDeviceIdentity: auth.SourceDeviceIdentity,
		AuthorizationDigest:  auth.SourceOwnershipAuthorizationDigest,
	}
	if err := validateTaintRecoveryHistoryOwnershipState(expectedOwnership); err != nil {
		return err
	}
	finalOwnership := TaintRecoveryHistoryOwnershipState{
		Epoch:                expectedOwnership.Epoch + 2,
		ActiveDeviceIdentity: auth.DestinationDeviceIdentity,
		AuthorizationDigest:  commitment,
	}
	quiesced := TaintRecoveryHistoryOwnershipState{
		Epoch:                expectedOwnership.Epoch + 1,
		ActiveDeviceIdentity: quiescedRecoveryHistoryOwnershipIdentity(commitment),
		AuthorizationDigest:  commitment,
	}
	expectedHistory := kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   auth.SourceSequence,
		HeadDigest: auth.SourceHeadDigest,
	}

	currentOwnership, err := ownership.Current(ctx)
	if err != nil {
		if !errors.Is(err, journal.ErrExternalHeadQuorum) {
			return err
		}
		// A prior finalization may have partially advanced the quorum and left
		// source/quiesced/final states split across members. Recovery is only
		// admissible when the exact history head still matches and the
		// destination TPM is already prepared with this same authorization.
		if err := requireExactHistoryWitness(ctx, historyWitness, expectedHistory); err != nil {
			return err
		}
		destinationState, err := preflightTPMHistoryContinuityDestination(
			ctx,
			destination,
			auth,
			commitment,
		)
		if err != nil {
			return err
		}
		if !isPreparedTPMHistoryContinuityDestination(destinationState, auth, commitment) {
			return fmt.Errorf(
				"%w: ownership quorum is split before destination preparation",
				ErrTPMHistoryContinuityWitness,
			)
		}
		recovered, err := ownership.RecoverAuthorizedTransfer(
			ctx,
			expectedOwnership,
			quiesced,
			finalOwnership,
		)
		if err != nil {
			return err
		}
		if recovered != finalOwnership {
			return fmt.Errorf(
				"%w: recovered ownership=%+v expected=%+v",
				ErrTPMHistoryContinuityWitness,
				recovered,
				finalOwnership,
			)
		}
		return nil
	}
	if currentOwnership == finalOwnership {
		return ErrTPMHistoryContinuityReplay
	}

	if err := requireExactHistoryWitness(ctx, historyWitness, expectedHistory); err != nil {
		return err
	}

	// Validate the destination before quiescing the source, so a configuration
	// error cannot unnecessarily stop a healthy active device.
	if _, err := preflightTPMHistoryContinuityDestination(
		ctx,
		destination,
		auth,
		commitment,
	); err != nil {
		return err
	}

	switch currentOwnership {
	case expectedOwnership:
		quiesced, err = ownership.BeginTransfer(ctx, expectedOwnership, commitment)
		if err != nil {
			return err
		}
	case quiesced:
		// Resume a transfer interrupted after source quiescence.
	default:
		return fmt.Errorf(
			"%w: ownership current=%+v expected source=%+v or quiesced=%+v",
			ErrTPMHistoryContinuityWitness,
			currentOwnership,
			expectedOwnership,
			quiesced,
		)
	}

	// This read is deliberately after source quiescence. A head that changed
	// before the ownership CAS makes the authorization stale and leaves the
	// system fail-closed rather than activating a destination at an older head.
	if err := requireExactHistoryWitness(ctx, historyWitness, expectedHistory); err != nil {
		return err
	}

	if err := importTPMHistoryContinuityDestination(
		ctx,
		destination,
		auth,
		commitment,
	); err != nil {
		return err
	}

	completed, err := ownership.CompleteTransfer(
		ctx,
		quiesced,
		auth.DestinationDeviceIdentity,
		commitment,
	)
	if errors.Is(err, ErrTaintRecoveryHistoryOwnershipReplay) {
		return ErrTPMHistoryContinuityReplay
	}
	if err != nil {
		return err
	}
	if completed != finalOwnership {
		return fmt.Errorf(
			"%w: final ownership=%+v expected=%+v",
			ErrTPMHistoryContinuityWitness,
			completed,
			finalOwnership,
		)
	}

	return nil
}

func preflightTPMHistoryContinuityDestination(
	ctx context.Context,
	destination *TPMNVHistoryAnchor,
	auth TPMHistoryContinuityTransferAuthorization,
	authorizationDigest string,
) (tpmNVHistoryAnchorState, error) {
	destination.mu.Lock()
	defer destination.mu.Unlock()

	state, err := destination.recoverLocked(ctx)
	if err != nil {
		return tpmNVHistoryAnchorState{}, err
	}
	if state.DeviceIdentity != auth.DestinationDeviceIdentity ||
		state.MeasuredBootIdentity != auth.DestinationMeasuredBootIdentity {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: destination TPM identity does not match authorization",
			ErrTPMHistoryContinuityDestination,
		)
	}

	if isPreparedTPMHistoryContinuityDestination(state, auth, authorizationDigest) {
		return state, nil
	}
	if state.Generation != auth.DestinationGeneration ||
		state.Digest != auth.DestinationStateDigest ||
		state.Sequence != 0 ||
		state.HeadDigest != "" ||
		state.PredecessorDeviceIdentity != "" ||
		state.MigrationSourceStateDigest != "" ||
		state.MigrationAuthorizationDigest != "" ||
		state.MigrationDestinationAttestationDigest != "" ||
		state.MigrationAttestationGenesisEpoch != 0 ||
		state.MigrationAttestationTrustRootRef != "" ||
		state.MigrationAttestationTrustRootEpoch != 0 ||
		state.MigrationAttestationPolicyHash != "" ||
		state.MigrationHistoryWitnessPolicyHash != "" ||
		state.MigrationOwnershipWitnessPolicyHash != "" {
		return tpmNVHistoryAnchorState{}, fmt.Errorf(
			"%w: destination is not the authorized fresh anchor",
			ErrTPMHistoryContinuityDestination,
		)
	}
	return state, nil
}

func importTPMHistoryContinuityDestination(
	ctx context.Context,
	destination *TPMNVHistoryAnchor,
	auth TPMHistoryContinuityTransferAuthorization,
	authorizationDigest string,
) error {
	destination.mu.Lock()
	defer destination.mu.Unlock()

	state, err := destination.recoverLocked(ctx)
	if err != nil {
		return err
	}
	if isPreparedTPMHistoryContinuityDestination(state, auth, authorizationDigest) {
		return nil
	}
	if state.DeviceIdentity != auth.DestinationDeviceIdentity ||
		state.MeasuredBootIdentity != auth.DestinationMeasuredBootIdentity ||
		state.Generation != auth.DestinationGeneration ||
		state.Digest != auth.DestinationStateDigest ||
		state.Sequence != 0 ||
		state.HeadDigest != "" {
		return fmt.Errorf("%w: destination changed after preflight", ErrTPMHistoryContinuityDestination)
	}
	if state.Generation == ^uint64(0) {
		return fmt.Errorf("%w: destination generation exhausted", ErrTPMHistoryContinuityDestination)
	}

	pending := state
	pending.PreviousGeneration = state.Generation
	pending.Generation = state.Generation + 1
	pending.PreviousSequence = 0
	pending.Sequence = auth.SourceSequence
	pending.PreviousHeadDigest = ""
	pending.HeadDigest = auth.SourceHeadDigest
	pending.TransitionKind = tpmHistoryTransitionMigrationImport
	pending.PredecessorDeviceIdentity = auth.SourceDeviceIdentity
	pending.MigrationSourceStateDigest = auth.SourceStateDigest
	pending.MigrationAuthorizationDigest = authorizationDigest
	pending.MigrationDestinationAttestationDigest = auth.DestinationAttestationDigest
	pending.MigrationAttestationGenesisEpoch = auth.DestinationAttestationGenesisEpoch
	pending.MigrationAttestationTrustRootRef = auth.DestinationAttestationTrustRootRef
	pending.MigrationAttestationTrustRootEpoch = auth.DestinationAttestationTrustRootEpoch
	pending.MigrationAttestationPolicyHash = auth.DestinationAttestationPolicyHash
	pending.MigrationHistoryWitnessPolicyHash = auth.HistoryWitnessPolicyHash
	pending.MigrationOwnershipWitnessPolicyHash = auth.OwnershipWitnessPolicyHash
	pending.Digest = ""

	pendingPath := destination.cfg.StatePath + ".pending"
	if err := writeTPMNVHistoryAnchorStateAtomic(pendingPath, pending); err != nil {
		return fmt.Errorf("persist pending TPM history continuity import: %w", err)
	}
	if err := destination.writeProtectedHead(ctx, tpmNVHistoryProtectedHead{
		Generation: pending.Generation,
		Sequence:   pending.Sequence,
		HeadDigest: pending.HeadDigest,
	}); err != nil {
		return fmt.Errorf("commit destination TPM exact history head: %w", err)
	}
	generation, err := destination.helper.incrementCounter(ctx)
	if err != nil {
		return fmt.Errorf("increment destination TPM history counter: %w", err)
	}
	if generation != pending.Generation {
		return fmt.Errorf(
			"%w: destination counter=%d expected=%d",
			ErrTPMHistoryAnchorRollback,
			generation,
			pending.Generation,
		)
	}
	if err := promoteTPMNVHistoryAnchorPending(pendingPath, destination.cfg.StatePath); err != nil {
		return fmt.Errorf("promote TPM history continuity import: %w", err)
	}
	return nil
}

func isPreparedTPMHistoryContinuityDestination(
	state tpmNVHistoryAnchorState,
	auth TPMHistoryContinuityTransferAuthorization,
	authorizationDigest string,
) bool {
	return state.DeviceIdentity == auth.DestinationDeviceIdentity &&
		state.MeasuredBootIdentity == auth.DestinationMeasuredBootIdentity &&
		state.Generation == auth.DestinationGeneration+1 &&
		state.Sequence == auth.SourceSequence &&
		state.HeadDigest == auth.SourceHeadDigest &&
		state.TransitionKind == tpmHistoryTransitionMigrationImport &&
		state.PredecessorDeviceIdentity == auth.SourceDeviceIdentity &&
		state.MigrationSourceStateDigest == auth.SourceStateDigest &&
		state.MigrationAuthorizationDigest == authorizationDigest &&
		state.MigrationDestinationAttestationDigest == auth.DestinationAttestationDigest &&
		state.MigrationAttestationGenesisEpoch == auth.DestinationAttestationGenesisEpoch &&
		state.MigrationAttestationTrustRootRef == auth.DestinationAttestationTrustRootRef &&
		state.MigrationAttestationTrustRootEpoch == auth.DestinationAttestationTrustRootEpoch &&
		state.MigrationAttestationPolicyHash == auth.DestinationAttestationPolicyHash &&
		state.MigrationHistoryWitnessPolicyHash == auth.HistoryWitnessPolicyHash &&
		state.MigrationOwnershipWitnessPolicyHash == auth.OwnershipWitnessPolicyHash
}

func requireExactHistoryWitness(
	ctx context.Context,
	witness *ExternalHeadTaintRecoveryHistoryAnchor,
	expected kernelfabric.TaintRecoveryHistoryAnchorState,
) error {
	current, err := witness.Current(ctx)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf(
			"%w: history witness=(%d,%q) expected=(%d,%q)",
			ErrTPMHistoryContinuityWitness,
			current.Sequence,
			current.HeadDigest,
			expected.Sequence,
			expected.HeadDigest,
		)
	}
	return nil
}

func canonicalTPMHistoryContinuityTransferAuthorizationPayload(
	auth TPMHistoryContinuityTransferAuthorization,
) ([]byte, error) {
	auth.TransferID = strings.TrimSpace(auth.TransferID)
	auth.HistoryWitnessID = strings.TrimSpace(auth.HistoryWitnessID)
	auth.HistoryWitnessPolicyHash = strings.TrimSpace(auth.HistoryWitnessPolicyHash)
	auth.OwnershipWitnessID = strings.TrimSpace(auth.OwnershipWitnessID)
	auth.OwnershipWitnessPolicyHash = strings.TrimSpace(auth.OwnershipWitnessPolicyHash)
	auth.SourceDeviceIdentity = strings.TrimSpace(auth.SourceDeviceIdentity)
	auth.SourceMeasuredBootIdentity = strings.TrimSpace(auth.SourceMeasuredBootIdentity)
	auth.SourceStateDigest = strings.TrimSpace(auth.SourceStateDigest)
	auth.SourceHeadDigest = strings.TrimSpace(auth.SourceHeadDigest)
	auth.SourceOwnershipAuthorizationDigest = strings.TrimSpace(auth.SourceOwnershipAuthorizationDigest)
	auth.DestinationDeviceIdentity = strings.TrimSpace(auth.DestinationDeviceIdentity)
	auth.DestinationMeasuredBootIdentity = strings.TrimSpace(auth.DestinationMeasuredBootIdentity)
	auth.DestinationStateDigest = strings.TrimSpace(auth.DestinationStateDigest)
	auth.DestinationAttestationTrustRootRef = strings.TrimSpace(auth.DestinationAttestationTrustRootRef)
	auth.DestinationAttestationPolicyHash = strings.TrimSpace(auth.DestinationAttestationPolicyHash)
	auth.NotBefore = auth.NotBefore.UTC()
	auth.ExpiresAt = auth.ExpiresAt.UTC()
	body, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/tpm-history-continuity-transfer-authorization/v1\x00"), body...), nil
}

func tpmHistoryContinuityTransferKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(append([]byte("aegis-ege/tpm-history-continuity-transfer-key/v1\x00"), publicKey...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
