//go:build linux

package computesettlement

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

type vcs09PlatformMeasurementSource struct {
	commitment kernelfabric.PlatformMeasurementCommitment
	err        error
}

func (s vcs09PlatformMeasurementSource) CurrentPlatformMeasurement(context.Context) (kernelfabric.PlatformMeasurementCommitment, error) {
	if s.err != nil {
		return kernelfabric.PlatformMeasurementCommitment{}, s.err
	}
	return s.commitment, nil
}

func TestVCS09HardwareRootedCommitmentDrivesVCS07Settlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	commitment := vcs09Commitment(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		41,
	)

	root, err := CaptureHardwareRootedAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if root.Root.BootMeasurementDigest == root.AttestationLineageDigest {
		t.Fatal("hardware-rooted boot digest must compose platform commitment with VCS-08 lineage")
	}
	if root.PlatformMeasurement.CommitmentDigest != commitment.CommitmentDigest {
		t.Fatal("platform measurement commitment was not preserved")
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
		t.Fatalf("hardware-rooted execution should settle through VCS-07: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.ExecutionRootEstablished {
		t.Fatal("expected hardware-rooted execution provenance to be established")
	}
}

func TestVCS09DifferentMeasuredBootCommitmentChangesExecutionRoot(t *testing.T) {
	live := newVCS08LiveFixture(t)
	base, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(), live.state, live.activation, live.runtimeLease, live.profile, live.trust, live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	a := vcs09Commitment(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		41,
	)
	b := vcs09Commitment(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		41,
	)
	rootA, err := BindPlatformMeasurement(base, a)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := BindPlatformMeasurement(base, b)
	if err != nil {
		t.Fatal(err)
	}
	if rootA.Root.BootMeasurementDigest == rootB.Root.BootMeasurementDigest {
		t.Fatal("different measured boot commitments must change VCS execution root")
	}
}

func TestVCS09GenerationAdvanceDoesNotChangeUnchangedBootIdentity(t *testing.T) {
	live := newVCS08LiveFixture(t)
	base, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(), live.state, live.activation, live.runtimeLease, live.profile, live.trust, live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	a := vcs09Commitment(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		41,
	)
	b := vcs09Commitment(t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		42,
	)
	rootA, err := BindPlatformMeasurement(base, a)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := BindPlatformMeasurement(base, b)
	if err != nil {
		t.Fatal(err)
	}
	if rootA.Root.BootMeasurementDigest != rootB.Root.BootMeasurementDigest {
		t.Fatal("unrelated monotonic generation advance must not change unchanged measured boot identity")
	}
}

func TestVCS09PlatformSourceFailureFailsClosed(t *testing.T) {
	live := newVCS08LiveFixture(t)
	_, err := CaptureHardwareRootedAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{err: errors.New("platform root unavailable")},
		live.now,
	)
	if err == nil {
		t.Fatal("unavailable platform measurement source must fail closed")
	}
}

func TestVCS09UnsupportedEvidenceClassIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	base, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(), live.state, live.activation, live.runtimeLease, live.profile, live.trust, live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := kernelfabric.NewPlatformMeasurementCommitment(
		"SOFTWARE_ONLY",
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindPlatformMeasurement(base, commitment); err == nil {
		t.Fatal("non-measured-boot platform evidence must not satisfy VCS-09")
	}
}

func vcs09Commitment(t *testing.T, platform, measurement string, generation uint64) kernelfabric.PlatformMeasurementCommitment {
	t.Helper()
	commitment, err := kernelfabric.NewPlatformMeasurementCommitment(
		kernelfabric.PlatformMeasurementClassMeasuredBoot,
		platform,
		measurement,
		generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return commitment
}
