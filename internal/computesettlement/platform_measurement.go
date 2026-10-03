package computesettlement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const hardwareRootedBootBindingVersion = "aegis.compute/hardware-rooted-boot-binding/v0"

type HardwareRootedAegisExecutionRoot struct {
	LiveAegisExecutionRoot
	PlatformMeasurement kernelfabric.PlatformMeasurementCommitment
}

// CaptureHardwareRootedAegisExecutionRoot extends VCS-08 by replacing its
// software/runtime-lineage-only BootMeasurementDigest with a composition of
// that lineage and a current generic measured-boot commitment exported by the
// trusted platform measurement source.
func CaptureHardwareRootedAegisExecutionRoot(
	ctx context.Context,
	pid int,
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	platformSource kernelfabric.PlatformMeasurementSource,
	now time.Time,
) (HardwareRootedAegisExecutionRoot, error) {
	if platformSource == nil {
		return HardwareRootedAegisExecutionRoot{}, errors.New("platform measurement source is required")
	}
	base, err := CaptureLiveAegisExecutionRoot(
		pid,
		state,
		activation,
		runtimeLease,
		expectedProfile,
		trust,
		now,
	)
	if err != nil {
		return HardwareRootedAegisExecutionRoot{}, err
	}
	commitment, err := platformSource.CurrentPlatformMeasurement(ctx)
	if err != nil {
		return HardwareRootedAegisExecutionRoot{}, fmt.Errorf("read current platform measurement: %w", err)
	}
	return BindPlatformMeasurement(base, commitment)
}

// BindPlatformMeasurement composes the already-verified VCS-08 runtime
// attestation lineage with a generic platform measured-boot commitment. The
// consumer never receives PCR indexes, TPM handles, or event-log semantics.
func BindPlatformMeasurement(
	root LiveAegisExecutionRoot,
	commitment kernelfabric.PlatformMeasurementCommitment,
) (HardwareRootedAegisExecutionRoot, error) {
	if err := kernelfabric.ValidatePlatformMeasurementCommitment(commitment); err != nil {
		return HardwareRootedAegisExecutionRoot{}, fmt.Errorf("platform measurement commitment: %w", err)
	}
	if commitment.EvidenceClass != kernelfabric.PlatformMeasurementClassMeasuredBoot {
		return HardwareRootedAegisExecutionRoot{}, fmt.Errorf("unsupported platform measurement evidence class %q", commitment.EvidenceClass)
	}
	if _, err := kernelfabric.ParseSHA256Digest(root.AttestationLineageDigest); err != nil {
		return HardwareRootedAegisExecutionRoot{}, fmt.Errorf("Aegis attestation lineage digest: %w", err)
	}
	if root.Root.BootMeasurementDigest != root.AttestationLineageDigest {
		return HardwareRootedAegisExecutionRoot{}, errors.New("live Aegis root was already rebound or has inconsistent boot measurement state")
	}

	h := sha256.New()
	_, _ = h.Write([]byte(hardwareRootedBootBindingVersion + "\\x00"))
	_, _ = h.Write([]byte(root.AttestationLineageDigest))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(commitment.CommitmentDigest))
	boundDigest := "sha256:" + hex.EncodeToString(h.Sum(nil))

	root.Root.BootMeasurementDigest = boundDigest
	return HardwareRootedAegisExecutionRoot{
		LiveAegisExecutionRoot: root,
		PlatformMeasurement:    commitment,
	}, nil
}
