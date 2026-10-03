package computesettlement

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const governedSuccessorEnrollmentRootBindingVersion = "aegis.compute/governed-successor-enrollment-root-binding/v0"

type GovernedSuccessorEnrollmentBoundAegisExecutionRoot struct {
	DurableEnrollmentBoundAegisExecutionRoot
	SuccessorAuthorization       kernelfabric.SignedEnrollmentIdentitySuccessorAuthorization
	SuccessorAuthorizationDigest string
}

// CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot extends VCS-11 by
// requiring a governed v2 successor receipt and the exact signed authorization
// that permitted the hardware-root replacement.
func CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
	ctx context.Context,
	pid int,
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	platformSource kernelfabric.PlatformMeasurementSource,
	enrolled kernelfabric.EnrolledTPMIdentity,
	receiptSource kernelfabric.EnrollmentIdentityReceiptReader,
	enrollmentAuthorityPublicKey ed25519.PublicKey,
	signedSuccessor kernelfabric.SignedEnrollmentIdentitySuccessorAuthorization,
	successorGovernance journal.GenesisEnrollmentSuccessorGovernanceBinding,
	now time.Time,
) (GovernedSuccessorEnrollmentBoundAegisExecutionRoot, error) {
	root, err := CaptureDurableEnrollmentBoundAegisExecutionRoot(
		ctx,
		pid,
		state,
		activation,
		runtimeLease,
		expectedProfile,
		trust,
		platformSource,
		enrolled,
		receiptSource,
		enrollmentAuthorityPublicKey,
		now,
	)
	if err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, err
	}
	receipt := root.EnrollmentReceipt.Receipt
	if len(enrollmentAuthorityPublicKey) != ed25519.PublicKeySize {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("enrollment authority public key is required")
	}
	successorGovernancePublicKey, err := successorGovernance.PublicKey()
	if err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("Genesis-bound successor governance trust is required: %w", err)
	}
	if string(enrollmentAuthorityPublicKey) == string(successorGovernancePublicKey) {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("successor governance authority must differ from enrollment authority")
	}
	if signedSuccessor.Authorization.Version != kernelfabric.EnrollmentIdentitySuccessorAuthorizationVersionV2 {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("VCS-13 requires Genesis-bound successor authorization v2")
	}
	if signedSuccessor.Authorization.GovernanceGenesisEpoch != successorGovernance.GenesisEpoch() ||
		signedSuccessor.Authorization.GovernanceCapabilityEnvelopeHash != successorGovernance.CapabilityEnvelopeHash() ||
		signedSuccessor.Authorization.GovernancePolicyHash != successorGovernance.PolicyHash() {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("successor governance authorization does not match verified Genesis binding")
	}
	// Authorization freshness is consumed at the successor transition boundary.
	// A committed R2 must remain verifiable after that short-lived authorization
	// window expires, so durable verification uses the enrollment-signed receipt
	// issuance time rather than the current settlement time.
	if err := kernelfabric.VerifySignedEnrollmentIdentitySuccessorAuthorization(
		signedSuccessor,
		successorGovernancePublicKey,
		receipt.IssuedAt,
	); err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("verify governed successor authorization at receipt issuance: %w", err)
	}
	authorizationDigest, err := kernelfabric.EnrollmentIdentitySuccessorAuthorizationDigest(signedSuccessor)
	if err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, err
	}
	auth := signedSuccessor.Authorization
	if receipt.Version != kernelfabric.EnrollmentIdentityReceiptVersionV2 {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("governed successor execution requires enrollment receipt v2")
	}
	if receipt.Sequence != auth.PredecessorSequence+1 ||
		receipt.PreviousReceiptDigest != auth.PredecessorReceiptDigest ||
		receipt.SuccessorAuthorizationDigest != authorizationDigest ||
		receipt.ReceiptID != auth.SuccessorEnrollmentID ||
		receipt.DeviceID != auth.DeviceID ||
		receipt.EKSPKISHA256 != auth.SuccessorHardwareIdentityDigest ||
		root.DevicePlatformBinding.PlatformIdentityDigest != auth.SuccessorHardwareIdentityDigest {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, errors.New("governed successor authorization does not bind the current enrollment receipt and hardware root")
	}
	if _, err := kernelfabric.ParseSHA256Digest(root.Root.BootMeasurementDigest); err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("durable successor boot measurement digest: %w", err)
	}
	if _, err := kernelfabric.ParseSHA256Digest(authorizationDigest); err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("successor authorization digest: %w", err)
	}

	h := sha256.New()
	_, _ = h.Write([]byte(governedSuccessorEnrollmentRootBindingVersion + "\x00"))
	_, _ = h.Write([]byte(root.Root.BootMeasurementDigest))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(authorizationDigest))
	root.Root.BootMeasurementDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))

	return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{
		DurableEnrollmentBoundAegisExecutionRoot: root,
		SuccessorAuthorization:                   signedSuccessor,
		SuccessorAuthorizationDigest:             authorizationDigest,
	}, nil
}
