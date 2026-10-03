//go:build linux

package computesettlement

import (
	"context"
	"os"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func TestVCS10EnrolledDeviceBoundHardwareRootDrivesSettlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	ek := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitment := vcs09Commitment(t,
		ek,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		51,
	)
	enrolled := kernelfabric.EnrolledTPMIdentity{
		DeviceID:     live.state.DeviceID,
		EKSPKISHA256: ek,
	}

	root, err := CaptureDeviceBoundHardwareRootedAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		enrolled,
		live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if root.DevicePlatformBinding.DeviceID != live.state.DeviceID {
		t.Fatalf("unexpected device binding: %+v", root.DevicePlatformBinding)
	}
	if root.DevicePlatformBinding.EnrollmentHardwareIdentityDigest != ek || root.DevicePlatformBinding.PlatformIdentityDigest != ek {
		t.Fatalf("hardware identity was not bound exactly: %+v", root.DevicePlatformBinding)
	}

	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, live.profile, streams, providerAuthority, tenantAuthority)
	provenance := vcs07Provenance(t, f, live.profile, root.Root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)
	result := vcs07Reconcile(
		t,
		f,
		live.profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root.Root,
		provenance,
		bindings,
		provenanceAuthority,
	)
	if result.Disposition != Settled {
		t.Fatalf("device-bound hardware root should settle through VCS-07: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS10BorrowedHardwareRootIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	commitment := vcs09Commitment(t,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		51,
	)
	enrolled := kernelfabric.EnrolledTPMIdentity{
		DeviceID:     live.state.DeviceID,
		EKSPKISHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	_, err := CaptureDeviceBoundHardwareRootedAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		enrolled,
		live.now,
	)
	if err == nil {
		t.Fatal("device must not borrow a measured-boot root from a different TPM EK")
	}
}

func TestVCS10DifferentEnrolledDeviceIDIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	ek := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitment := vcs09Commitment(t,
		ek,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		51,
	)
	enrolled := kernelfabric.EnrolledTPMIdentity{
		DeviceID:     "device:other",
		EKSPKISHA256: ek,
	}
	_, err := CaptureDeviceBoundHardwareRootedAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		enrolled,
		live.now,
	)
	if err == nil {
		t.Fatal("different enrolled DeviceID must not bind to current runtime root")
	}
}

func TestVCS10DeviceBindingChangesExecutionRoot(t *testing.T) {
	live := newVCS08LiveFixture(t)
	ek := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitmentA := vcs09Commitment(t,
		ek,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		51,
	)
	commitmentB := vcs09Commitment(t,
		ek,
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		52,
	)
	enrolled := kernelfabric.EnrolledTPMIdentity{DeviceID: live.state.DeviceID, EKSPKISHA256: ek}

	base, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(), live.state, live.activation, live.runtimeLease, live.profile, live.trust, live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	hwA, err := BindPlatformMeasurement(base, commitmentA)
	if err != nil {
		t.Fatal(err)
	}
	hwB, err := BindPlatformMeasurement(base, commitmentB)
	if err != nil {
		t.Fatal(err)
	}
	rootA, err := BindEnrolledDeviceHardwareRoot(hwA, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := BindEnrolledDeviceHardwareRoot(hwB, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	if rootA.Root.BootMeasurementDigest == rootB.Root.BootMeasurementDigest {
		t.Fatal("device/platform binding must remain part of the downstream execution root")
	}
}
