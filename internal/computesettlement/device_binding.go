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

const deviceHardwareRootBindingVersion = "aegis.compute/device-hardware-root-binding/v0"

type DeviceBoundHardwareRootedAegisExecutionRoot struct {
	HardwareRootedAegisExecutionRoot
	DevicePlatformBinding kernelfabric.EnrolledDevicePlatformBinding
}

// CaptureDeviceBoundHardwareRootedAegisExecutionRoot extends VCS-09 by
// requiring the Aegis DeviceID enrollment record and the platform measurement
// source to resolve to the same TPM EK SPKI identity.
func CaptureDeviceBoundHardwareRootedAegisExecutionRoot(
	ctx context.Context,
	pid int,
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	platformSource kernelfabric.PlatformMeasurementSource,
	enrolled kernelfabric.EnrolledTPMIdentity,
	now time.Time,
) (DeviceBoundHardwareRootedAegisExecutionRoot, error) {
	root, err := CaptureHardwareRootedAegisExecutionRoot(
		ctx,
		pid,
		state,
		activation,
		runtimeLease,
		expectedProfile,
		trust,
		platformSource,
		now,
	)
	if err != nil {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, err
	}
	return BindEnrolledDeviceHardwareRoot(root, enrolled)
}

func BindEnrolledDeviceHardwareRoot(
	root HardwareRootedAegisExecutionRoot,
	enrolled kernelfabric.EnrolledTPMIdentity,
) (DeviceBoundHardwareRootedAegisExecutionRoot, error) {
	if root.DeviceID == "" {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, errors.New("live Aegis device id is required")
	}
	if err := kernelfabric.ValidatePlatformMeasurementCommitment(root.PlatformMeasurement); err != nil {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, fmt.Errorf("platform measurement: %w", err)
	}
	binding, err := kernelfabric.BindEnrolledDeviceToPlatform(
		root.DeviceID,
		enrolled,
		root.PlatformMeasurement,
	)
	if err != nil {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, fmt.Errorf("bind enrolled device to hardware root: %w", err)
	}
	if _, err := kernelfabric.ParseSHA256Digest(root.Root.BootMeasurementDigest); err != nil {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, fmt.Errorf("hardware-rooted boot measurement digest: %w", err)
	}
	if _, err := kernelfabric.ParseSHA256Digest(binding.BindingDigest); err != nil {
		return DeviceBoundHardwareRootedAegisExecutionRoot{}, fmt.Errorf("device/platform binding digest: %w", err)
	}

	h := sha256.New()
	_, _ = h.Write([]byte(deviceHardwareRootBindingVersion + "\x00"))
	_, _ = h.Write([]byte(root.Root.BootMeasurementDigest))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(binding.BindingDigest))
	root.Root.BootMeasurementDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))

	return DeviceBoundHardwareRootedAegisExecutionRoot{
		HardwareRootedAegisExecutionRoot: root,
		DevicePlatformBinding:            binding,
	}, nil
}
