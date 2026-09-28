
package kernelfabric

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func signedRuntimeExpiryFixture(
	t *testing.T,
	processState string,
) (runtimeTrustFixture, SignedRuntimeTrustExpiryEvidence) {
	t.Helper()
	f := newRuntimeTrustFixture(t)
	expected := *f.recovery.activation.Receipt.ProcessIdentity
	e := RuntimeTrustExpiryEvidence{
		Version:                       RuntimeTrustExpiryEvidenceVersion,
		EvidenceID:                    "expiry-evidence-1",
		DeviceID:                      f.state.DeviceID,
		WorkloadID:                    f.state.WorkloadID,
		Generation:                    f.state.Generation,
		LifecycleEpoch:                EffectiveLifecycleEpoch(f.state),
		ActivationDigest:              f.state.ActivationDigest,
		RuntimeTrustLeaseDigest:       f.state.RuntimeTrustLeaseDigest,
		RuntimeTrustLeaseEpoch:        f.state.RuntimeTrustEpoch,
		RuntimeTrustExpiresAt:         f.state.RuntimeTrustExpiresAt,
		RuntimeTrustBootIDHash:        f.state.RuntimeTrustBootIDHash,
		RuntimeTrustInstalledBootNS:   f.state.RuntimeTrustInstalledBootNS,
		RuntimeTrustDeadlineBootNS:    f.state.RuntimeTrustDeadlineBootNS,
		ObservedBootIDHash:            f.state.RuntimeTrustBootIDHash,
		ObservedBootNS:                f.state.RuntimeTrustDeadlineBootNS,
		TargetCgroup:                  f.recovery.activation.Receipt.TargetCgroup,
		TargetCgroupID:                f.recovery.activation.Receipt.TargetCgroupID,
		ActionClass:                   ActionClassNetworkConnect,
		KernelFenceBootIDHash:         f.state.RuntimeTrustBootIDHash,
		KernelAuthorityTerm:           7,
		KernelDecisionEpoch:           31,
		KernelPreviousRevocationEpoch: 4,
		KernelRevocationEpoch:         5,
		ProcessID:                     f.recovery.activation.Receipt.ProcessID,
		ExpectedProcessIdentity:       &expected,
		ProcessState:                  processState,
		ObservedAt:                    f.now.Add(time.Minute),
	}
	switch processState {
	case RuntimeExpiryProcessRunning:
		observed := expected
		e.ObservedProcessIdentity = &observed
		e.ObservedCgroup = f.recovery.activation.Receipt.TargetCgroup
		e.ObservedCgroupID = f.recovery.activation.Receipt.TargetCgroupID
	case RuntimeExpiryProcessAbsent:
	case RuntimeExpiryProcessPIDReused:
		observed := expected
		observed.ProcessStartTimeTicks++
		e.ObservedProcessIdentity = &observed
		e.ObservedCgroup = f.recovery.activation.Receipt.TargetCgroup
		e.ObservedCgroupID = f.recovery.activation.Receipt.TargetCgroupID
	case RuntimeExpiryProcessCgroupMismatch:
		observed := expected
		e.ObservedProcessIdentity = &observed
		e.ObservedCgroup = "/sys/fs/cgroup/other"
		e.ObservedCgroupID = f.recovery.activation.Receipt.TargetCgroupID + 1
	default:
		t.Fatalf("unsupported process state %s", processState)
	}
	signed, err := SignRuntimeTrustExpiryEvidence(e, f.recovery.hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	return f, signed
}

func TestRuntimeTrustExpiryEvidenceSignatureCoversKernelTransition(t *testing.T) {
	f, signed := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessRunning)
	if err := VerifySignedRuntimeTrustExpiryEvidence(
		signed,
		f.recovery.hostPub,
	); err != nil {
		t.Fatalf("valid expiry evidence rejected: %v", err)
	}
	tampered := signed
	tampered.Evidence.KernelRevocationEpoch++
	if err := VerifySignedRuntimeTrustExpiryEvidence(
		tampered,
		f.recovery.hostPub,
	); err == nil {
		t.Fatal("tampered kernel revocation transition was accepted")
	}
}

func TestRuntimeTrustExpiryEvidenceRejectsPreDeadlineObservation(t *testing.T) {
	f, signed := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessRunning)
	e := signed.Evidence
	e.ObservedBootNS = e.RuntimeTrustDeadlineBootNS - 1
	_, err := SignRuntimeTrustExpiryEvidence(e, f.recovery.hostPriv)
	if err == nil {
		t.Fatal("pre-deadline expiry evidence was accepted")
	}
}

func TestRuntimeTrustExpiryReconciliationRunningQuarantines(t *testing.T) {
	f, expiry := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessRunning)
	decision, err := EvaluateRuntimeTrustExpiryReconciliation(
		f.state,
		f.recovery.activation,
		f.lease,
		expiry,
		f.recovery.hostPub,
		f.recovery.lifecyclePriv,
		"lifecycle-authority",
		f.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationQuarantine {
		t.Fatalf("running expired workload did not quarantine: %+v", decision.Decision)
	}
	if err := VerifySignedWorkloadReconciliationDecision(
		decision,
		f.recovery.lifecyclePub,
	); err != nil {
		t.Fatalf("signed reconciliation decision rejected: %v", err)
	}
}

func TestRuntimeTrustExpiryReconciliationAbsentMarksExitedUnknown(t *testing.T) {
	f, expiry := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessAbsent)
	decision, err := EvaluateRuntimeTrustExpiryReconciliation(
		f.state,
		f.recovery.activation,
		f.lease,
		expiry,
		f.recovery.hostPub,
		f.recovery.lifecyclePriv,
		"lifecycle-authority",
		f.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationMarkExitedUnknown {
		t.Fatalf("absent expired workload did not become EXITED_UNKNOWN: %+v", decision.Decision)
	}
}

func TestRuntimeTrustExpiryReconciliationPIDReuseMarksExitedUnknown(t *testing.T) {
	f, expiry := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessPIDReused)
	decision, err := EvaluateRuntimeTrustExpiryReconciliation(
		f.state,
		f.recovery.activation,
		f.lease,
		expiry,
		f.recovery.hostPub,
		f.recovery.lifecyclePriv,
		"lifecycle-authority",
		f.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationMarkExitedUnknown {
		t.Fatalf("PID-reused expired workload did not become EXITED_UNKNOWN: %+v", decision.Decision)
	}
}

func TestRuntimeTrustExpiryReconciliationCgroupMismatchQuarantines(t *testing.T) {
	f, expiry := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessCgroupMismatch)
	decision, err := EvaluateRuntimeTrustExpiryReconciliation(
		f.state,
		f.recovery.activation,
		f.lease,
		expiry,
		f.recovery.hostPub,
		f.recovery.lifecyclePriv,
		"lifecycle-authority",
		f.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationQuarantine {
		t.Fatalf("cgroup mismatch did not quarantine: %+v", decision.Decision)
	}
}

func TestRuntimeTrustExpiryReconciliationRejectsLeaseMismatch(t *testing.T) {
	f, expiry := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessRunning)
	other := f.lease
	other.Lease.LeaseID = "different-lease"
	var err error
	other, err = SignRuntimeTrustLease(other.Lease, f.recovery.lifecyclePriv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = EvaluateRuntimeTrustExpiryReconciliation(
		f.state,
		f.recovery.activation,
		other,
		expiry,
		f.recovery.hostPub,
		f.recovery.lifecyclePriv,
		"lifecycle-authority",
		f.now.Add(2*time.Minute),
	)
	if !errors.Is(err, ErrLifecycleInvalidLineage) {
		t.Fatalf("mismatched signed lease was not rejected: %v", err)
	}
}

func TestRuntimeTrustExpiryEvidenceRejectsWrongActionClass(t *testing.T) {
	f, signed := signedRuntimeExpiryFixture(t, RuntimeExpiryProcessRunning)
	e := signed.Evidence
	e.ActionClass = 99
	_, err := SignRuntimeTrustExpiryEvidence(e, f.recovery.hostPriv)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("wrong action class was not rejected: %v", err)
	}
}
