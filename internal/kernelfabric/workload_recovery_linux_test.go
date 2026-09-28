//go:build linux

package kernelfabric

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserveLinuxProcessCapturesPersistentIdentity(t *testing.T) {
	obs, err := ObserveLinuxProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Exists {
		t.Fatal("current process unexpectedly absent")
	}
	if err := ValidateLinuxProcessIdentity(obs.Identity); err != nil {
		t.Fatalf("invalid captured identity: %v", err)
	}
	if obs.ObservedCgroupID == 0 || obs.ObservedCgroup == "" {
		t.Fatalf("missing cgroup observation: %+v", obs)
	}
	identity, err := CaptureLinuxProcessIdentity(os.Getpid(), obs.ObservedCgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if identity != obs.Identity {
		t.Fatalf("capture identity mismatch: got=%+v want=%+v", identity, obs.Identity)
	}
}

func TestApplyReconciliationMarksExitedUnknown(t *testing.T) {
	f := newRecoveryFixture(t)
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		f.state.DeviceID,
		f.state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, f.state)
		},
	); err != nil {
		t.Fatal(err)
	}
	obs := f.signedObservation(t, RecoveryObservationAbsent, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ApplyWorkloadReconciliation(store, decision, f.lifecyclePub)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != LifecycleStateExitedUnknown ||
		updated.RecoveryDigest == "" ||
		updated.ExitDigest != "" {
		t.Fatalf("unexpected reconciled state: %+v", updated)
	}
	readBack, exists, err := store.Read(f.state.DeviceID, f.state.WorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || readBack.RecoveryDigest != updated.RecoveryDigest {
		t.Fatalf("reconciled state was not durable: %+v", readBack)
	}
}

func TestApplyReconciliationQuarantinesCgroupMismatch(t *testing.T) {
	f := newRecoveryFixture(t)
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		f.state.DeviceID,
		f.state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, f.state)
		},
	); err != nil {
		t.Fatal(err)
	}
	obs := f.signedObservation(t, RecoveryObservationCgroupMismatch, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ApplyWorkloadReconciliation(store, decision, f.lifecyclePub)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != LifecycleStateQuarantined ||
		updated.RecoveryDigest == "" {
		t.Fatalf("expected quarantined lifecycle state: %+v", updated)
	}
}

func TestApplyKeepRunningPreservesRunningState(t *testing.T) {
	f := newRecoveryFixture(t)
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		f.state.DeviceID,
		f.state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, f.state)
		},
	); err != nil {
		t.Fatal(err)
	}
	obs := f.signedObservation(t, RecoveryObservationMatchRunning, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ApplyWorkloadReconciliation(store, decision, f.lifecyclePub)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != LifecycleStateRunning ||
		updated.RecoveryDigest != "" ||
		updated.ActivationDigest != f.state.ActivationDigest {
		t.Fatalf("KEEP_RUNNING mutated lineage unexpectedly: %+v", updated)
	}
}

func TestLifecycleValidatorAcceptsRecoveredStates(t *testing.T) {
	base := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	for _, stateName := range []string{LifecycleStateExitedUnknown, LifecycleStateQuarantined} {
		state := WorkloadLifecycleState{
			Version:                WorkloadLifecycleStateVersion,
			DeviceID:               "device-1",
			WorkloadID:             "workload-1",
			Generation:             1,
			State:                  stateName,
			ActivationDigest:       "sha256:" + repeatHex("a", 64),
			RecoveryDigest:         "sha256:" + repeatHex("b", 64),
			RestartWindowStartedAt: base,
			UpdatedAt:              base,
		}
		if err := ValidateWorkloadLifecycleState(state); err != nil {
			t.Fatalf("%s rejected: %v", stateName, err)
		}
	}
}
