package kernelfabric

import "testing"

func TestBindEnrolledDeviceToPlatformRequiresSameTPMEK(t *testing.T) {
	ek := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	measurement := PlatformMeasurementCommitment{
		Version:                PlatformMeasurementCommitmentVersion,
		EvidenceClass:          PlatformMeasurementClassMeasuredBoot,
		CommitmentDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PlatformIdentityDigest: ek,
		VerifiedGeneration:     9,
	}
	binding, err := BindEnrolledDeviceToPlatform(
		"device-1",
		EnrolledTPMIdentity{DeviceID: "device-1", EKSPKISHA256: ek},
		measurement,
	)
	if err != nil {
		t.Fatal(err)
	}
	if binding.DeviceID != "device-1" || binding.EnrollmentHardwareIdentityDigest != ek || binding.PlatformIdentityDigest != ek {
		t.Fatalf("unexpected binding: %+v", binding)
	}
}

func TestBindEnrolledDeviceToPlatformRejectsBorrowedTPM(t *testing.T) {
	measurement := PlatformMeasurementCommitment{
		Version:                PlatformMeasurementCommitmentVersion,
		EvidenceClass:          PlatformMeasurementClassMeasuredBoot,
		CommitmentDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PlatformIdentityDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		VerifiedGeneration:     9,
	}
	_, err := BindEnrolledDeviceToPlatform(
		"device-1",
		EnrolledTPMIdentity{
			DeviceID:    "device-1",
			EKSPKISHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		measurement,
	)
	if err == nil {
		t.Fatal("borrowed TPM platform identity must be rejected")
	}
}

func TestBindEnrolledDeviceToPlatformRejectsDifferentDeviceNamespace(t *testing.T) {
	ek := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	measurement := PlatformMeasurementCommitment{
		Version:                PlatformMeasurementCommitmentVersion,
		EvidenceClass:          PlatformMeasurementClassMeasuredBoot,
		CommitmentDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PlatformIdentityDigest: ek,
		VerifiedGeneration:     9,
	}
	_, err := BindEnrolledDeviceToPlatform(
		"device-expected",
		EnrolledTPMIdentity{DeviceID: "device-other", EKSPKISHA256: ek},
		measurement,
	)
	if err == nil {
		t.Fatal("different enrolled DeviceID must be rejected")
	}
}
