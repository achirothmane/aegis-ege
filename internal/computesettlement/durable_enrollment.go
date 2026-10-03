package computesettlement

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const durableEnrollmentRootBindingVersion = "aegis.compute/durable-enrollment-root-binding/v0"

type DurableEnrollmentBoundAegisExecutionRoot struct {
	DeviceBoundHardwareRootedAegisExecutionRoot
	EnrollmentReceipt       kernelfabric.SignedEnrollmentIdentityReceipt
	EnrollmentReceiptDigest string
}

// CaptureDurableEnrollmentBoundAegisExecutionRoot extends VCS-10 by requiring
// the current enrollment identity to be represented by the exact signed durable
// receipt currently committed by a monotonic exact-head anchor.
func CaptureDurableEnrollmentBoundAegisExecutionRoot(
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
	now time.Time,
) (DurableEnrollmentBoundAegisExecutionRoot, error) {
	if receiptSource == nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, errors.New("durable enrollment receipt source is required")
	}
	root, err := CaptureDeviceBoundHardwareRootedAegisExecutionRoot(
		ctx,
		pid,
		state,
		activation,
		runtimeLease,
		expectedProfile,
		trust,
		platformSource,
		enrolled,
		now,
	)
	if err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, err
	}

	signed, digest, exists, err := receiptSource.Current(ctx, enrollmentAuthorityPublicKey)
	if err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("read current durable enrollment receipt: %w", err)
	}
	if !exists {
		return DurableEnrollmentBoundAegisExecutionRoot{}, errors.New("current durable enrollment receipt is missing")
	}
	if err := kernelfabric.VerifyEnrollmentIdentityReceiptForIdentity(
		signed,
		enrollmentAuthorityPublicKey,
		enrolled,
	); err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("verify current enrollment receipt: %w", err)
	}
	if signed.Receipt.DeviceID != root.DeviceID {
		return DurableEnrollmentBoundAegisExecutionRoot{}, errors.New("durable enrollment receipt DeviceID differs from live Aegis DeviceID")
	}
	if signed.Receipt.EKSPKISHA256 != root.DevicePlatformBinding.PlatformIdentityDigest {
		return DurableEnrollmentBoundAegisExecutionRoot{}, errors.New("durable enrollment receipt TPM identity differs from current platform identity")
	}
	expectedDigest, err := kernelfabric.EnrollmentIdentityReceiptDigest(signed)
	if err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, err
	}
	if expectedDigest != digest {
		return DurableEnrollmentBoundAegisExecutionRoot{}, errors.New("durable enrollment receipt source returned inconsistent head digest")
	}
	if _, err := kernelfabric.ParseSHA256Digest(root.Root.BootMeasurementDigest); err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("device-bound boot measurement digest: %w", err)
	}
	if _, err := kernelfabric.ParseSHA256Digest(digest); err != nil {
		return DurableEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf("enrollment receipt digest: %w", err)
	}

	h := sha256.New()
	_, _ = h.Write([]byte(durableEnrollmentRootBindingVersion + "\x00"))
	_, _ = h.Write([]byte(root.Root.BootMeasurementDigest))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(digest))
	root.Root.BootMeasurementDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))

	return DurableEnrollmentBoundAegisExecutionRoot{
		DeviceBoundHardwareRootedAegisExecutionRoot: root,
		EnrollmentReceipt:                          signed,
		EnrollmentReceiptDigest:                    digest,
	}, nil
}
