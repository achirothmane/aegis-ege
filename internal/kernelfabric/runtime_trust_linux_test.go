//go:build linux

package kernelfabric

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyRuntimeTrustLeaseAdvancesLedgerEpochAndRejectsReplay(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	base := f.recovery.state
	base.LifecycleEpoch = 1
	if err := store.withLockedState(
		base.DeviceID,
		base.WorkloadID,
		func(path string, _ WorkloadLifecycleState, exists bool) error {
			if exists {
				t.Fatal("unexpected pre-existing lifecycle state")
			}
			return writeLifecycleState(path, base)
		},
	); err != nil {
		t.Fatal(err)
	}

	state, err := ApplyRuntimeTrustLease(
		store,
		f.lease,
		f.recovery.lifecyclePub,
		f.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SignedRuntimeTrustLeaseDigest(f.lease)
	if err != nil {
		t.Fatal(err)
	}
	if state.RuntimeTrustEpoch != 1 ||
		state.RuntimeTrustLeaseDigest != digest ||
		!state.RuntimeTrustExpiresAt.Equal(f.lease.Lease.ExpiresAt) {
		t.Fatalf("runtime trust lease not persisted: %+v", state)
	}

	_, err = ApplyRuntimeTrustLease(
		store,
		f.lease,
		f.recovery.lifecyclePub,
		f.now,
	)
	if err == nil {
		t.Fatal("runtime trust lease replay was accepted")
	}
}

func TestRuntimeTrustRevocationRaisesKernelFenceBeforeQuarantineEvidence(t *testing.T) {
	now := time.Now().UTC()
	current, err := ObserveLinuxProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !current.Exists {
		t.Fatal("test process is unexpectedly absent")
	}

	hostPub, hostPriv := admissionTestKeys(t)
	lifecyclePub, lifecyclePriv := admissionTestKeys(t)
	identity := current.Identity
	activation, err := SignWorkloadActivationReceipt(
		WorkloadActivationReceipt{
			Version:            WorkloadActivationReceiptVersionV2,
			ActivationID:       "runtime-live-activation",
			GrantID:            "runtime-grant",
			GrantDigest:        "sha256:" + strings.Repeat("a", 64),
			DeviceID:           "runtime-device",
			WorkloadID:         "runtime-workload",
			WorkloadSpecDigest: "sha256:" + strings.Repeat("b", 64),
			TargetCgroup:       filepath.Clean(current.ObservedCgroup),
			TargetCgroupID:     current.ObservedCgroupID,
			ProcessID:          os.Getpid(),
			ProcessIdentity:    &identity,
			StartedAt:          now.Add(-time.Second),
		},
		hostPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		t.Fatal(err)
	}
	leaseDigest := "sha256:" + strings.Repeat("c", 64)
	state := WorkloadLifecycleState{
		Version:                 WorkloadLifecycleStateVersion,
		DeviceID:                "runtime-device",
		WorkloadID:              "runtime-workload",
		Generation:              1,
		LifecycleEpoch:          1,
		State:                   LifecycleStateRunning,
		ActivationDigest:        activationDigest,
		RuntimeTrustEpoch:       1,
		RuntimeTrustLeaseDigest: leaseDigest,
		RuntimeTrustExpiresAt:   now.Add(time.Minute),
		RestartWindowStartedAt:  now.Add(-time.Minute),
		UpdatedAt:               now.Add(-time.Second),
	}
	decision, err := SignRuntimeTrustDecision(
		RuntimeTrustDecision{
			Version:            RuntimeTrustDecisionVersion,
			DecisionID:         "runtime-revoke-1",
			DeviceID:           state.DeviceID,
			WorkloadID:         state.WorkloadID,
			Generation:         state.Generation,
			LifecycleEpoch:     state.LifecycleEpoch,
			ActivationDigest:   activationDigest,
			RuntimeLeaseDigest: leaseDigest,
			RuntimeLeaseEpoch:  state.RuntimeTrustEpoch,
			PolicyDigest:       "sha256:" + strings.Repeat("d", 64),
			TargetCgroup:       filepath.Clean(current.ObservedCgroup),
			TargetCgroupID:     current.ObservedCgroupID,
			Outcome:            RuntimeTrustRevoke,
			ReasonCodes:        []string{"RUNTIME_TRUST_LEASE_EXPIRED"},
			DecidedAt:          now,
			AuthorityID:        "lifecycle-authority",
		},
		lifecyclePriv,
	)
	if err != nil {
		t.Fatal(err)
	}

	var boot [32]byte
	boot[0] = 1
	kernelStore := &recordingKernelStore{
		fence: ScopeFenceState{
			BootIDHash:      boot,
			AuthorityTerm:   3,
			DecisionEpoch:   9,
			RevocationEpoch: 11,
		},
	}
	observation, nextFence, err := ContainRuntimeTrustRevocation(
		context.Background(),
		Installer{Store: kernelStore},
		state,
		activation,
		decision,
		lifecyclePub,
		hostPriv,
		now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if nextFence.RevocationEpoch != 12 {
		t.Fatalf("revocation epoch=%d want=12", nextFence.RevocationEpoch)
	}
	if len(kernelStore.ops) != 2 ||
		kernelStore.ops[0] != "get-fence" ||
		kernelStore.ops[1] != "fence" {
		t.Fatalf("unsafe kernel containment ordering: %v", kernelStore.ops)
	}
	if observation.Observation.State != RecoveryObservationRuntimeTrustRevoked {
		t.Fatalf("unexpected runtime recovery state: %+v", observation.Observation)
	}
	runtimeDigest, err := SignedRuntimeTrustDecisionDigest(decision)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Observation.RuntimeTrustDecisionDigest != runtimeDigest {
		t.Fatalf("runtime decision digest not bound to observation")
	}

	quarantine, err := EvaluateRuntimeTrustReconciliation(
		state,
		activation,
		observation,
		decision,
		hostPub,
		lifecyclePriv,
		"lifecycle-authority",
		now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if quarantine.Decision.Outcome != ReconciliationQuarantine {
		t.Fatalf("runtime revocation did not become standard quarantine: %+v", quarantine.Decision)
	}
	if err := VerifySignedWorkloadReconciliationDecision(
		quarantine,
		lifecyclePub,
	); err != nil {
		t.Fatalf("runtime quarantine decision signature rejected: %v", err)
	}
}
