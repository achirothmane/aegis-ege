package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const EnrolledDevicePlatformBindingVersion = "aegis.ege/enrolled-device-platform-binding/v1"

// EnrolledDevicePlatformBinding proves that the Aegis enrollment identity and
// the generic platform measurement source are rooted in the same TPM EK SPKI.
// It deliberately binds a DeviceID namespace to a hardware-root identity
// namespace without exposing TPM/PCR implementation details downstream.
type EnrolledDevicePlatformBinding struct {
	Version                          string `json:"version"`
	DeviceID                         string `json:"device_id"`
	EnrollmentHardwareIdentityDigest string `json:"enrollment_hardware_identity_digest"`
	PlatformIdentityDigest           string `json:"platform_identity_digest"`
	PlatformMeasurementDigest        string `json:"platform_measurement_digest"`
	BindingDigest                    string `json:"binding_digest"`
}

func BindEnrolledDeviceToPlatform(
	expectedDeviceID string,
	enrolled EnrolledTPMIdentity,
	commitment PlatformMeasurementCommitment,
) (EnrolledDevicePlatformBinding, error) {
	expectedDeviceID = strings.TrimSpace(expectedDeviceID)
	if expectedDeviceID == "" {
		return EnrolledDevicePlatformBinding{}, errors.New("expected device id is required")
	}
	if strings.TrimSpace(enrolled.DeviceID) == "" || enrolled.DeviceID != expectedDeviceID {
		return EnrolledDevicePlatformBinding{}, errors.New("enrolled device id differs from expected device id")
	}
	if _, err := ParseSHA256Digest(enrolled.EKSPKISHA256); err != nil {
		return EnrolledDevicePlatformBinding{}, fmt.Errorf("enrolled EK SPKI digest: %w", err)
	}
	if err := ValidatePlatformMeasurementCommitment(commitment); err != nil {
		return EnrolledDevicePlatformBinding{}, fmt.Errorf("platform measurement commitment: %w", err)
	}
	if commitment.EvidenceClass != PlatformMeasurementClassMeasuredBoot {
		return EnrolledDevicePlatformBinding{}, fmt.Errorf("unsupported platform measurement evidence class %q", commitment.EvidenceClass)
	}
	if enrolled.EKSPKISHA256 != commitment.PlatformIdentityDigest {
		return EnrolledDevicePlatformBinding{}, errors.New("enrolled TPM EK identity differs from platform hardware identity")
	}

	h := sha256.New()
	_, _ = h.Write([]byte("aegis.ege/enrolled-device-platform-binding/v1\x00"))
	_, _ = h.Write([]byte(expectedDeviceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(enrolled.EKSPKISHA256))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(commitment.CommitmentDigest))

	binding := EnrolledDevicePlatformBinding{
		Version:                           EnrolledDevicePlatformBindingVersion,
		DeviceID:                          expectedDeviceID,
		EnrollmentHardwareIdentityDigest: enrolled.EKSPKISHA256,
		PlatformIdentityDigest:           commitment.PlatformIdentityDigest,
		PlatformMeasurementDigest:        commitment.CommitmentDigest,
		BindingDigest:                     "sha256:" + hex.EncodeToString(h.Sum(nil)),
	}
	if err := ValidateEnrolledDevicePlatformBinding(binding); err != nil {
		return EnrolledDevicePlatformBinding{}, err
	}
	return binding, nil
}

func ValidateEnrolledDevicePlatformBinding(binding EnrolledDevicePlatformBinding) error {
	if binding.Version != EnrolledDevicePlatformBindingVersion {
		return fmt.Errorf("unsupported enrolled device/platform binding version %q", binding.Version)
	}
	if strings.TrimSpace(binding.DeviceID) == "" {
		return errors.New("enrolled device/platform binding device id is required")
	}
	if _, err := ParseSHA256Digest(binding.EnrollmentHardwareIdentityDigest); err != nil {
		return fmt.Errorf("enrollment hardware identity digest: %w", err)
	}
	if _, err := ParseSHA256Digest(binding.PlatformIdentityDigest); err != nil {
		return fmt.Errorf("platform identity digest: %w", err)
	}
	if _, err := ParseSHA256Digest(binding.PlatformMeasurementDigest); err != nil {
		return fmt.Errorf("platform measurement digest: %w", err)
	}
	if _, err := ParseSHA256Digest(binding.BindingDigest); err != nil {
		return fmt.Errorf("device/platform binding digest: %w", err)
	}
	if binding.EnrollmentHardwareIdentityDigest != binding.PlatformIdentityDigest {
		return errors.New("enrollment and platform hardware identities differ")
	}
	return nil
}
