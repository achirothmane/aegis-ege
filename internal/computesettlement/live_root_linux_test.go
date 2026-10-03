//go:build linux

package computesettlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func TestVCS08LiveAegisExecutionRootDrivesVCS07Settlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	root, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		live.now,
	)
	if err != nil {
		t.Fatal(err)
	}

	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(
		t,
		f,
		live.profile,
		streams,
		providerAuthority,
		tenantAuthority,
	)
	provenance := vcs07Provenance(
		t,
		f,
		live.profile,
		root.Root,
		provenanceAuthority,
	)
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
		t.Fatalf("live Aegis execution root should drive VCS-07 settlement: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.ExecutionRootEstablished {
		t.Fatal("expected VCS-07 execution root to be established")
	}
	if root.ExecutableArtifactDigest != live.profile.ArtifactDigest {
		t.Fatal("live executable artifact was not bound into compute profile")
	}
}

func TestVCS08LiveProcessIdentitySubstitutionIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	observation := live.observation
	observation.ProcessIdentity.ProcessStartTimeTicks++

	_, err := ProduceLiveAegisExecutionRoot(
		live.state,
		live.activation,
		live.runtimeLease,
		observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("substituted live process identity must be rejected")
	}
}

func TestVCS08LiveCgroupSubstitutionIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	observation := live.observation
	observation.CgroupID++

	_, err := ProduceLiveAegisExecutionRoot(
		live.state,
		live.activation,
		live.runtimeLease,
		observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("substituted cgroup identity must be rejected")
	}
}

func TestVCS08LiveExecutableSubstitutionIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	profile := live.profile
	profile.ArtifactDigest = vcs08Digest("different-executable")

	_, err := CaptureLiveAegisExecutionRoot(
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("profile bound to a different executable artifact must be rejected")
	}
}

func TestVCS08StaleRuntimeTrustLeaseInLifecycleStateIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	state := live.state
	state.RuntimeTrustLeaseDigest = vcs08Digest("older-runtime-trust-lease")

	_, err := ProduceLiveAegisExecutionRoot(
		state,
		live.activation,
		live.runtimeLease,
		live.observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("stale runtime trust lease must be rejected")
	}
}

func TestVCS08RuntimeTrustEpochMismatchIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	state := live.state
	state.RuntimeTrustEpoch++

	_, err := ProduceLiveAegisExecutionRoot(
		state,
		live.activation,
		live.runtimeLease,
		live.observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("runtime trust epoch mismatch must be rejected")
	}
}

func TestVCS08ExpiredRuntimeTrustLeaseIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)

	_, err := ProduceLiveAegisExecutionRoot(
		live.state,
		live.activation,
		live.runtimeLease,
		live.observation,
		live.profile,
		live.trust,
		live.runtimeLease.Lease.ExpiresAt.Add(time.Nanosecond),
	)
	if err == nil {
		t.Fatal("expired runtime trust lease must be rejected")
	}
}

func TestVCS08BootIdentityMismatchIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	state := live.state
	state.RuntimeTrustBootIDHash = vcs08Digest("different-boot")

	_, err := ProduceLiveAegisExecutionRoot(
		state,
		live.activation,
		live.runtimeLease,
		live.observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("runtime trust boot identity mismatch must be rejected")
	}
}

func TestVCS08WorkloadSpecProfileMismatchIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	profile := live.profile
	profile.WorkloadDigest = vcs08Digest("different-workload-spec")

	_, err := ProduceLiveAegisExecutionRoot(
		live.state,
		live.activation,
		live.runtimeLease,
		live.observation,
		profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("compute profile bound to another workload spec must be rejected")
	}
}

func TestVCS08TamperedActivationReceiptIsRejected(t *testing.T) {
	live := newVCS08LiveFixture(t)
	activation := live.activation
	activation.Receipt.WorkloadID = "workload:tampered"

	_, err := ProduceLiveAegisExecutionRoot(
		live.state,
		activation,
		live.runtimeLease,
		live.observation,
		live.profile,
		live.trust,
		live.now,
	)
	if err == nil {
		t.Fatal("tampered activation receipt must be rejected")
	}
}

type vcs08LiveFixture struct {
	now          time.Time
	state        kernelfabric.WorkloadLifecycleState
	activation   kernelfabric.SignedWorkloadActivationReceipt
	runtimeLease kernelfabric.SignedRuntimeTrustLease
	observation  AegisRuntimeObservation
	profile      WorkloadPerformanceProfile
	trust        AegisExecutionRootTrust
}

func newVCS08LiveFixture(t *testing.T) vcs08LiveFixture {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	processObservation, err := kernelfabric.ObserveLinuxProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !processObservation.Exists {
		t.Fatal("test process disappeared during live observation")
	}
	artifactDigest, err := liveLinuxExecutableDigest(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePub, lifecyclePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	workloadSpecDigest := vcs08Digest("live-workload-spec")
	activation, err := kernelfabric.SignWorkloadActivationReceipt(
		kernelfabric.WorkloadActivationReceipt{
			Version:            kernelfabric.WorkloadActivationReceiptVersionV2,
			ActivationID:       "activation:vcs08",
			GrantID:            "grant:vcs08",
			GrantDigest:        vcs08Digest("grant"),
			DeviceID:           "device:vcs08",
			WorkloadID:         "workload:vcs08",
			WorkloadSpecDigest: workloadSpecDigest,
			TargetCgroup:       processObservation.ObservedCgroup,
			TargetCgroupID:     processObservation.ObservedCgroupID,
			ProcessID:          os.Getpid(),
			ProcessIdentity:    &processObservation.Identity,
			StartedAt:          now.Add(-30 * time.Second),
		},
		hostPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := kernelfabric.SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		t.Fatal(err)
	}

	lease, err := kernelfabric.SignRuntimeTrustLease(
		kernelfabric.RuntimeTrustLease{
			Version:              kernelfabric.RuntimeTrustLeaseVersion,
			LeaseID:              "runtime-lease:vcs08",
			LeaseEpoch:           7,
			DeviceID:             activation.Receipt.DeviceID,
			WorkloadID:           activation.Receipt.WorkloadID,
			Generation:           1,
			LifecycleEpoch:       1,
			ActivationDigest:     activationDigest,
			WorkloadSpecDigest:   workloadSpecDigest,
			TargetCgroup:         processObservation.ObservedCgroup,
			TargetCgroupID:       processObservation.ObservedCgroupID,
			BootstrapDigest:      vcs08Digest("bootstrap"),
			PolicyDigest:         vcs08Digest("runtime-policy"),
			RemoteDecisionID:     "remote-decision:vcs08",
			RemoteDecisionDigest: vcs08Digest("remote-attestation-decision"),
			RemoteVerifiedAt:     now.Add(-20 * time.Second),
			AuthorityID:          "lifecycle-authority:vcs08",
			IssuedAt:             now.Add(-10 * time.Second),
			ExpiresAt:            now.Add(60 * time.Second),
		},
		lifecyclePriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaseDigest, err := kernelfabric.SignedRuntimeTrustLeaseDigest(lease)
	if err != nil {
		t.Fatal(err)
	}

	state := kernelfabric.WorkloadLifecycleState{
		Version:                    kernelfabric.WorkloadLifecycleStateVersion,
		DeviceID:                   activation.Receipt.DeviceID,
		WorkloadID:                 activation.Receipt.WorkloadID,
		Generation:                 1,
		LifecycleEpoch:             1,
		State:                      kernelfabric.LifecycleStateRunning,
		ActivationDigest:           activationDigest,
		RuntimeTrustEpoch:          lease.Lease.LeaseEpoch,
		RuntimeTrustLeaseDigest:    leaseDigest,
		RuntimeTrustExpiresAt:      lease.Lease.ExpiresAt,
		RuntimeTrustBootIDHash:     processObservation.Identity.BootIDHash,
		RuntimeTrustInstalledBootNS: 100,
		RuntimeTrustDeadlineBootNS:  1000,
		RestartWindowStartedAt:     now.Add(-time.Minute),
		UpdatedAt:                  now,
	}
	if err := kernelfabric.ValidateWorkloadLifecycleState(state); err != nil {
		t.Fatalf("fixture lifecycle state invalid: %v", err)
	}

	profile := WorkloadPerformanceProfile{
		WorkloadID:             activation.Receipt.WorkloadID,
		WorkloadDigest:         workloadSpecDigest,
		ArtifactDigest:         artifactDigest,
		BenchmarkProfileDigest: vcs08Digest("benchmark-profile"),
		RuntimeConfigDigest:    vcs08Digest("runtime-config"),
		InputProfileDigest:     vcs08Digest("input-profile"),
	}

	return vcs08LiveFixture{
		now:          now,
		state:        state,
		activation:   activation,
		runtimeLease: lease,
		observation: AegisRuntimeObservation{
			ProcessIdentity:          processObservation.Identity,
			CgroupID:                 processObservation.ObservedCgroupID,
			ExecutableArtifactDigest: artifactDigest,
		},
		profile: profile,
		trust: AegisExecutionRootTrust{
			HostAttestorPublicKey:       hostPub,
			LifecycleAuthorityPublicKey: lifecyclePub,
		},
	}
}

func vcs08Digest(label string) string {
	sum := sha256.Sum256([]byte("vcs08:" + label))
	return "sha256:" + hex.EncodeToString(sum[:])
}
