//go:build linux && cgo

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

var ErrTPMEnrollmentSuccessorGovernance = errors.New("TPM enrollment successor governance is invalid")

// CompleteAndCommitGovernedTPMEnrollmentSuccessor appends the next durable
// enrollment identity only after the exact predecessor receipt head has been
// transferred to, and made active on, the replacement TPM under the existing
// quorum-backed continuity protocol.
//
// The function does not perform the TPM continuity transfer. It verifies that
// the transfer has already completed and that its durable lineage, witness
// policies, destination attestation, live TPM identities, successor enrollment
// ceremony, and independent successor-governance authorization all agree.
func CompleteAndCommitGovernedTPMEnrollmentSuccessor(
	ctx context.Context,
	pending kernelfabric.PendingTPMEnrollment,
	proof kernelfabric.TPMEnrollmentProof,
	now time.Time,
	destination *TPMNVHistoryAnchor,
	store kernelfabric.AnchoredEnrollmentIdentityStore,
	enrollmentAuthorityKey ed25519.PrivateKey,
	signedSuccessor kernelfabric.SignedEnrollmentIdentitySuccessorAuthorization,
	successorGovernancePublicKey ed25519.PublicKey,
	signedTransfer SignedTPMHistoryContinuityTransferAuthorization,
	transferPublicKey ed25519.PublicKey,
	destinationAttestation SignedTPMRootMigrationDestinationAttestation,
	attestationTrust TPMRootMigrationAttestationTrust,
) (
	kernelfabric.EnrolledTPMIdentity,
	kernelfabric.SignedEnrollmentIdentityReceipt,
	string,
	error,
) {
	fail := func(format string, args ...any) (
		kernelfabric.EnrolledTPMIdentity,
		kernelfabric.SignedEnrollmentIdentityReceipt,
		string,
		error,
	) {
		allArgs := append([]any{ErrTPMEnrollmentSuccessorGovernance}, args...)
		return kernelfabric.EnrolledTPMIdentity{},
			kernelfabric.SignedEnrollmentIdentityReceipt{},
			"",
			fmt.Errorf("%w: "+format, allArgs...)
	}

	if ctx == nil || destination == nil {
		return fail("context and destination TPM anchor are required")
	}
	if err := ctx.Err(); err != nil {
		return kernelfabric.EnrolledTPMIdentity{}, kernelfabric.SignedEnrollmentIdentityReceipt{}, "", err
	}
	if len(enrollmentAuthorityKey) != ed25519.PrivateKeySize ||
		len(successorGovernancePublicKey) != ed25519.PublicKeySize ||
		len(transferPublicKey) != ed25519.PublicKeySize {
		return fail("all enrollment, governance, and transfer keys are required")
	}
	if err := attestationTrust.validate(); err != nil {
		return fail("Genesis-bound destination attestation trust is required: %v", err)
	}
	enrollmentPublicKey := enrollmentAuthorityKey.Public().(ed25519.PublicKey)
	if bytes.Equal(successorGovernancePublicKey, enrollmentPublicKey) ||
		bytes.Equal(successorGovernancePublicKey, transferPublicKey) ||
		attestationTrust.publicKeyEquals(successorGovernancePublicKey) {
		return fail("successor governance authority must be independent of enrollment, transfer, and destination-attestation authorities")
	}
	if attestationTrust.publicKeyEquals(transferPublicKey) {
		return fail("continuity transfer and destination-attestation authorities must be independent")
	}

	effectiveNow := now.UTC()
	if now.IsZero() {
		effectiveNow = time.Now().UTC()
	}
	if err := kernelfabric.VerifySignedEnrollmentIdentitySuccessorAuthorization(
		signedSuccessor,
		successorGovernancePublicKey,
		effectiveNow,
	); err != nil {
		return fail("verify successor governance authorization: %v", err)
	}
	if err := VerifySignedTPMHistoryContinuityTransferAuthorization(
		signedTransfer,
		transferPublicKey,
		effectiveNow,
	); err != nil {
		return fail("verify TPM continuity transfer authorization: %v", err)
	}
	if err := attestationTrust.verifySignedAttestation(
		destinationAttestation,
		effectiveNow,
	); err != nil {
		return fail("verify Genesis-bound destination attestation: %v", err)
	}

	successor := signedSuccessor.Authorization
	transfer := signedTransfer.Authorization
	attestation := destinationAttestation.Attestation
	if !attestationTrust.matchesAuthorization(
		transfer.DestinationAttestationGenesisEpoch,
		transfer.DestinationAttestationTrustRootRef,
		transfer.DestinationAttestationTrustRootEpoch,
		transfer.DestinationAttestationPolicyHash,
	) {
		return fail("continuity transfer attestation trust does not match verified Genesis")
	}

	successorDigest, err := kernelfabric.EnrollmentIdentitySuccessorAuthorizationDigest(signedSuccessor)
	if err != nil {
		return fail("digest successor authorization: %v", err)
	}
	transferDigest, err := TPMHistoryContinuityTransferAuthorizationDigest(signedTransfer)
	if err != nil {
		return fail("digest continuity transfer authorization: %v", err)
	}
	attestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		return fail("digest destination attestation: %v", err)
	}
	requestDigest, err := kernelfabric.TPMEnrollmentRequestDigest(pending.Request)
	if err != nil {
		return fail("digest successor enrollment request: %v", err)
	}

	if pending.Request.DeviceID != successor.DeviceID ||
		pending.Challenge.DeviceID != successor.DeviceID ||
		pending.Challenge.EnrollmentID != successor.SuccessorEnrollmentID ||
		pending.Challenge.EnrollmentRequestDigest != successor.SuccessorEnrollmentRequestDigest ||
		requestDigest != successor.SuccessorEnrollmentRequestDigest ||
		pending.EKSPKISHA256 != successor.SuccessorHardwareIdentityDigest ||
		pending.Challenge.EKSPKISHA256 != successor.SuccessorHardwareIdentityDigest {
		return fail("successor enrollment ceremony does not match governance authorization")
	}

	if transferDigest != successor.ContinuityTransferAuthorizationDigest ||
		attestationDigest != successor.DestinationAttestationDigest ||
		transfer.SourceDeviceIdentity != successor.SourceDeviceIdentity ||
		transfer.SourceSequence != successor.PredecessorSequence ||
		transfer.SourceHeadDigest != successor.PredecessorReceiptDigest ||
		transfer.DestinationDeviceIdentity != successor.DestinationDeviceIdentity ||
		transfer.DestinationMeasuredBootIdentity != successor.DestinationMeasuredBootIdentity ||
		transfer.DestinationGeneration != successor.DestinationGeneration ||
		transfer.HistoryWitnessPolicyHash != successor.HistoryWitnessPolicyHash ||
		transfer.OwnershipWitnessPolicyHash != successor.OwnershipWitnessPolicyHash ||
		transfer.DestinationAttestationDigest != successor.DestinationAttestationDigest {
		return fail("continuity transfer does not match successor governance authorization")
	}
	if attestation.MigrationID != transfer.TransferID ||
		attestation.EnrolledDeviceID != successor.DeviceID ||
		attestation.DestinationDeviceIdentity != successor.DestinationDeviceIdentity ||
		attestation.DestinationMeasuredBootIdentity != successor.DestinationMeasuredBootIdentity ||
		attestation.DestinationGeneration != successor.DestinationGeneration {
		return fail("destination attestation does not match successor governance authorization")
	}

	owned, ok := store.Anchor.(*OwnedConjunctiveTaintRecoveryHistoryAnchor)
	if !ok || owned == nil {
		return fail("successor receipt store requires owned conjunctive TPM/quorum anchor")
	}
	local, ok := owned.Local.(*TPMNVHistoryAnchor)
	if !ok || local != destination {
		return fail("successor receipt store is not bound to the authorized destination TPM")
	}
	historyWitness, ok := owned.Witness.(*ExternalHeadTaintRecoveryHistoryAnchor)
	if !ok || historyWitness == nil || owned.Ownership == nil {
		return fail("successor receipt store requires the authorized history and ownership quorum witnesses")
	}
	if historyWitness.QuorumPolicyHash() != successor.HistoryWitnessPolicyHash ||
		owned.Ownership.QuorumPolicyHash() != successor.OwnershipWitnessPolicyHash {
		return fail("live witness quorum policy differs from successor authorization")
	}

	liveDeviceIdentity, err := destination.DeviceIdentity(ctx)
	if err != nil {
		return fail("read live destination TPM device identity: %v", err)
	}
	liveMeasuredBootIdentity, err := destination.MeasuredBootIdentity(ctx)
	if err != nil {
		return fail("read live destination measured boot identity: %v", err)
	}
	liveEnrollmentHardwareIdentity, err := destination.helper.enrollmentHardwareIdentity(ctx)
	if err != nil {
		return fail("read live destination enrollment hardware identity: %v", err)
	}
	if liveDeviceIdentity != successor.DestinationDeviceIdentity ||
		liveMeasuredBootIdentity != successor.DestinationMeasuredBootIdentity ||
		liveEnrollmentHardwareIdentity != successor.SuccessorHardwareIdentityDigest {
		return fail("live destination TPM does not match successor hardware identity")
	}

	ownershipState, err := owned.Ownership.Current(ctx)
	if err != nil {
		return fail("read destination ownership witness: %v", err)
	}
	if ownershipState.ActiveDeviceIdentity != successor.DestinationDeviceIdentity ||
		ownershipState.AuthorizationDigest != transferDigest {
		return fail("destination TPM is not active under the exact continuity transfer")
	}

	destination.mu.Lock()
	destinationState, err := destination.recoverLocked(ctx)
	destination.mu.Unlock()
	if err != nil {
		return fail("read migrated destination anchor state: %v", err)
	}
	if destinationState.DeviceIdentity != successor.DestinationDeviceIdentity ||
		destinationState.MeasuredBootIdentity != successor.DestinationMeasuredBootIdentity ||
		destinationState.PredecessorDeviceIdentity != successor.SourceDeviceIdentity ||
		destinationState.MigrationAuthorizationDigest != transferDigest ||
		destinationState.MigrationDestinationAttestationDigest != attestationDigest ||
		destinationState.MigrationAttestationGenesisEpoch != transfer.DestinationAttestationGenesisEpoch ||
		destinationState.MigrationAttestationTrustRootRef != transfer.DestinationAttestationTrustRootRef ||
		destinationState.MigrationAttestationTrustRootEpoch != transfer.DestinationAttestationTrustRootEpoch ||
		destinationState.MigrationAttestationPolicyHash != transfer.DestinationAttestationPolicyHash ||
		destinationState.MigrationHistoryWitnessPolicyHash != successor.HistoryWitnessPolicyHash ||
		destinationState.MigrationOwnershipWitnessPolicyHash != successor.OwnershipWitnessPolicyHash {
		return fail("destination TPM migration lineage does not match successor authorization")
	}

	identity, err := kernelfabric.CompleteTPMEnrollment(pending, proof, effectiveNow)
	if err != nil {
		return fail("complete successor TPM enrollment ceremony: %v", err)
	}
	completedAt := proof.CompletedAt.UTC()
	if proof.CompletedAt.IsZero() ||
		completedAt.Before(pending.Challenge.IssuedAt.UTC()) ||
		!completedAt.Before(pending.Challenge.ExpiresAt.UTC()) ||
		completedAt.After(effectiveNow) {
		return fail("successor proof completion time is outside the verified enrollment ceremony window")
	}
	identity.EnrolledAt = completedAt
	if identity.DeviceID != successor.DeviceID ||
		identity.EKSPKISHA256 != successor.SuccessorHardwareIdentityDigest ||
		identity.EKSPKISHA256 != liveEnrollmentHardwareIdentity {
		return fail("completed successor enrollment identity does not match live destination TPM")
	}

	current, currentDigest, exists, err := store.Current(ctx, enrollmentPublicKey)
	if err != nil {
		return fail("read current governed enrollment head: %v", err)
	}
	if !exists {
		return fail("predecessor enrollment receipt is missing")
	}

	// Idempotent retry after R(n+1) was already committed.
	if current.Receipt.Sequence == successor.PredecessorSequence+1 &&
		current.Receipt.Version == kernelfabric.EnrollmentIdentityReceiptVersionV2 &&
		current.Receipt.PreviousReceiptDigest == successor.PredecessorReceiptDigest &&
		current.Receipt.SuccessorAuthorizationDigest == successorDigest &&
		current.Receipt.ReceiptID == successor.SuccessorEnrollmentID {
		if err := kernelfabric.VerifyEnrollmentIdentityReceiptForIdentity(
			current,
			enrollmentPublicKey,
			identity,
		); err != nil {
			return fail("committed successor receipt differs from repeated ceremony: %v", err)
		}
		if destinationState.Sequence != current.Receipt.Sequence ||
			destinationState.HeadDigest != currentDigest {
			return fail("destination durable head differs from already committed successor receipt")
		}
		return identity, current, currentDigest, nil
	}

	if current.Receipt.Sequence != successor.PredecessorSequence ||
		currentDigest != successor.PredecessorReceiptDigest ||
		current.Receipt.DeviceID != successor.DeviceID ||
		current.Receipt.EKSPKISHA256 != successor.PredecessorHardwareIdentityDigest {
		return fail("current enrollment receipt is not the exact authorized predecessor")
	}
	if destinationState.Sequence != successor.PredecessorSequence ||
		destinationState.HeadDigest != successor.PredecessorReceiptDigest {
		return fail("destination TPM did not inherit the exact predecessor receipt head")
	}

	receipt, err := kernelfabric.NewGovernedEnrollmentIdentitySuccessorReceipt(
		successor.SuccessorEnrollmentID,
		successor.PredecessorSequence+1,
		successor.PredecessorReceiptDigest,
		successorDigest,
		identity,
		identity.EnrolledAt,
	)
	if err != nil {
		return fail("construct governed successor receipt: %v", err)
	}
	signedReceipt, err := kernelfabric.SignEnrollmentIdentityReceipt(receipt, enrollmentAuthorityKey)
	if err != nil {
		return fail("sign governed successor receipt: %v", err)
	}
	digest, err := store.AppendGovernedSuccessor(
		ctx,
		signedReceipt,
		enrollmentPublicKey,
		signedSuccessor,
		successorGovernancePublicKey,
		effectiveNow,
	)
	if err != nil {
		return fail("commit governed successor receipt: %v", err)
	}
	return identity, signedReceipt, digest, nil
}
