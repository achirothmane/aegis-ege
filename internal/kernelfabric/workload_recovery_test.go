package kernelfabric

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type recoveryFixture struct {
	base          time.Time
	spec          WorkloadLaunchSpec
	bootstrap     string
	hostPub       ed25519.PublicKey
	hostPriv      ed25519.PrivateKey
	lifecyclePub  ed25519.PublicKey
	lifecyclePriv ed25519.PrivateKey
	verifierPub   ed25519.PublicKey
	verifierPriv  ed25519.PrivateKey
	issuerPub     ed25519.PublicKey
	issuerPriv    ed25519.PrivateKey
	priorGrant    SignedWorkloadAdmissionGrant
	activation    SignedWorkloadActivationReceipt
	state         WorkloadLifecycleState
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	base := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	hostPub, hostPriv := admissionTestKeys(t)
	lifecyclePub, lifecyclePriv := admissionTestKeys(t)
	verifierPub, verifierPriv := admissionTestKeys(t)
	issuerPub, issuerPriv := admissionTestKeys(t)
	spec := admissionTestSpec()
	bootstrap := "sha256:" + strings.Repeat("a", 64)

	remote := admissionTestRemoteDecision(
		t, base, "ALLOW", "device-1", bootstrap, verifierPriv,
	)
	req, err := NewWorkloadAdmissionRequest(
		"device-1",
		"workload-1",
		spec,
		"/sys/fs/cgroup/aegis-workload",
		4242,
		bootstrap,
		base,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := IssueWorkloadAdmissionGrant(
		req,
		remote,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: verifierPub,
			AdmissionIssuerKey:      issuerPriv,
			AdmissionIssuerID:       "admission-authority",
			MaxAttestationAge:       10 * time.Minute,
			GrantTTL:                time.Minute,
			Now:                     func() time.Time { return base },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest, err := SignedWorkloadAdmissionGrantDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	identity := LinuxProcessIdentity{
		BootIDHash:            "sha256:" + strings.Repeat("b", 64),
		ProcessStartTimeTicks: 1001,
		ExecutableDevice:      11,
		ExecutableInode:       22,
	}
	activation, err := SignWorkloadActivationReceipt(
		WorkloadActivationReceipt{
			Version:            WorkloadActivationReceiptVersionV2,
			ActivationID:       "activation-recovery-1",
			GrantID:            grant.Grant.GrantID,
			GrantDigest:        grantDigest,
			DeviceID:           "device-1",
			WorkloadID:         "workload-1",
			WorkloadSpecDigest: grant.Grant.WorkloadSpecDigest,
			TargetCgroup:       grant.Grant.TargetCgroup,
			TargetCgroupID:     grant.Grant.TargetCgroupID,
			ProcessID:          3210,
			ProcessIdentity:    &identity,
			StartedAt:          base.Add(time.Second),
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
	state := WorkloadLifecycleState{
		Version:                WorkloadLifecycleStateVersion,
		DeviceID:               "device-1",
		WorkloadID:             "workload-1",
		Generation:             1,
		State:                  LifecycleStateRunning,
		ActivationDigest:       activationDigest,
		RestartCountInWindow:   0,
		RestartWindowStartedAt: base,
		UpdatedAt:              base.Add(time.Second),
	}
	return recoveryFixture{
		base: base, spec: spec, bootstrap: bootstrap,
		hostPub: hostPub, hostPriv: hostPriv,
		lifecyclePub: lifecyclePub, lifecyclePriv: lifecyclePriv,
		verifierPub: verifierPub, verifierPriv: verifierPriv,
		issuerPub: issuerPub, issuerPriv: issuerPriv,
		priorGrant: grant, activation: activation, state: state,
	}
}

func (f recoveryFixture) signedObservation(
	t *testing.T,
	state string,
	observedAt time.Time,
) SignedWorkloadRecoveryObservation {
	t.Helper()
	expected := *f.activation.Receipt.ProcessIdentity
	obs := WorkloadRecoveryObservation{
		Version:                 WorkloadRecoveryObservationVersion,
		ObservationID:           "observation-1",
		DeviceID:                f.state.DeviceID,
		WorkloadID:              f.state.WorkloadID,
		Generation:              f.state.Generation,
		ActivationID:            f.activation.Receipt.ActivationID,
		ActivationDigest:        f.state.ActivationDigest,
		ProcessID:               f.activation.Receipt.ProcessID,
		ExpectedProcessIdentity: &expected,
		CurrentBootIDHash:       expected.BootIDHash,
		ExpectedCgroup:          f.activation.Receipt.TargetCgroup,
		ExpectedCgroupID:        f.activation.Receipt.TargetCgroupID,
		State:                   state,
		ObservedAt:              observedAt,
	}
	switch state {
	case RecoveryObservationMatchRunning:
		observed := expected
		obs.ObservedProcessIdentity = &observed
		obs.ObservedCgroupID = f.activation.Receipt.TargetCgroupID
		obs.ObservedCgroup = f.activation.Receipt.TargetCgroup
	case RecoveryObservationPIDReused:
		observed := expected
		observed.ProcessStartTimeTicks++
		obs.ObservedProcessIdentity = &observed
		obs.ObservedCgroupID = f.activation.Receipt.TargetCgroupID
	case RecoveryObservationCgroupMismatch:
		observed := expected
		obs.ObservedProcessIdentity = &observed
		obs.ObservedCgroupID = f.activation.Receipt.TargetCgroupID + 1
	case RecoveryObservationAbsent:
	case RecoveryObservationBootChanged:
		obs.CurrentBootIDHash = "sha256:" + strings.Repeat("c", 64)
	default:
		t.Fatalf("unsupported fixture observation state %s", state)
	}
	signed, err := SignWorkloadRecoveryObservation(obs, f.hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestActivationReceiptV2BindsPersistentProcessIdentity(t *testing.T) {
	f := newRecoveryFixture(t)
	if err := VerifySignedWorkloadActivationReceipt(f.activation, f.hostPub); err != nil {
		t.Fatalf("valid v2 activation receipt rejected: %v", err)
	}
	tampered := f.activation
	copyIdentity := *tampered.Receipt.ProcessIdentity
	copyIdentity.ProcessStartTimeTicks++
	tampered.Receipt.ProcessIdentity = &copyIdentity
	if err := VerifySignedWorkloadActivationReceipt(tampered, f.hostPub); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered process identity was not rejected: %v", err)
	}
}

func TestReconciliationKeepsExactRunningProcess(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationMatchRunning, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationKeepRunning {
		t.Fatalf("expected KEEP_RUNNING, got %+v", decision.Decision)
	}
}

func TestReconciliationMarksAbsentProcessExitedUnknown(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationAbsent, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationMarkExitedUnknown {
		t.Fatalf("expected MARK_EXITED_UNKNOWN, got %+v", decision.Decision)
	}
}

func TestReconciliationTreatsPIDReuseAsOriginalExit(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationPIDReused, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationMarkExitedUnknown {
		t.Fatalf("expected unknown exit after PID reuse, got %+v", decision.Decision)
	}
}

func TestReconciliationQuarantinesLiveCgroupMismatch(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationCgroupMismatch, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationQuarantine {
		t.Fatalf("expected QUARANTINE, got %+v", decision.Decision)
	}
}

func TestRecoveredRestartRequiresPostRecoveryAttestation(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationAbsent, f.base.Add(5*time.Second))
	reconciliation, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	recoveryDigest, err := SignedWorkloadReconciliationDecisionDigest(reconciliation)
	if err != nil {
		t.Fatal(err)
	}
	state := f.state
	state.State = LifecycleStateExitedUnknown
	state.RecoveryDigest = recoveryDigest
	state.UpdatedAt = reconciliation.Decision.DecidedAt

	oldRemote := admissionTestRemoteDecision(
		t, f.base.Add(4*time.Second), "ALLOW", "device-1", f.bootstrap, f.verifierPriv,
	)
	policy := WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               time.Minute,
		ReattestAfter:            2 * time.Minute,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    f.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  f.verifierPub,
		AdmissionIssuerPublicKey: f.issuerPub,
		HostAttestorPublicKey:    f.hostPub,
		Now:                      func() time.Time { return f.base.Add(7 * time.Second) },
	}
	decision, err := EvaluateRecoveredWorkloadRestart(
		state, f.priorGrant, f.activation, reconciliation, oldRemote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireReattestation {
		t.Fatalf("expected post-recovery re-attestation, got %+v", decision.Decision)
	}

	freshRemote := admissionTestRemoteDecision(
		t, f.base.Add(6500*time.Millisecond), "ALLOW", "device-1", f.bootstrap, f.verifierPriv,
	)
	decision, err = EvaluateRecoveredWorkloadRestart(
		state, f.priorGrant, f.activation, reconciliation, freshRemote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireFreshGrant ||
		decision.Decision.PreviousRecoveryDigest != recoveryDigest ||
		decision.Decision.PreviousExitDigest != "" {
		t.Fatalf("expected recovery-bound fresh grant path, got %+v", decision.Decision)
	}
}

func TestRecoveredRestartGrantValidatesRecoveryLineage(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationAbsent, f.base.Add(5*time.Second))
	reconciliation, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	recoveryDigest, _ := SignedWorkloadReconciliationDecisionDigest(reconciliation)
	state := f.state
	state.State = LifecycleStateExitedUnknown
	state.RecoveryDigest = recoveryDigest
	state.UpdatedAt = reconciliation.Decision.DecidedAt
	freshRemote := admissionTestRemoteDecision(
		t, f.base.Add(6500*time.Millisecond), "ALLOW", "device-1", f.bootstrap, f.verifierPriv,
	)
	evalNow := f.base.Add(7 * time.Second)
	policy := WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               time.Minute,
		ReattestAfter:            2 * time.Minute,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    f.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  f.verifierPub,
		AdmissionIssuerPublicKey: f.issuerPub,
		HostAttestorPublicKey:    f.hostPub,
		Now:                      func() time.Time { return evalNow },
	}
	restart, err := EvaluateRecoveredWorkloadRestart(
		state, f.priorGrant, f.activation, reconciliation, freshRemote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	issueAt := restart.Decision.NotBefore.Add(time.Millisecond)
	req, err := NewWorkloadAdmissionRequest(
		state.DeviceID, state.WorkloadID, f.spec,
		f.priorGrant.Grant.TargetCgroup,
		f.priorGrant.Grant.TargetCgroupID,
		f.bootstrap,
		issueAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := IssueRestartWorkloadAdmissionGrant(
		req, freshRemote, restart, f.lifecyclePub,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: f.verifierPub,
			AdmissionIssuerKey:      f.issuerPriv,
			AdmissionIssuerID:       "admission-authority",
			MaxAttestationAge:       2 * time.Minute,
			GrantTTL:                20 * time.Second,
			Now:                     func() time.Time { return issueAt },
		},
		issueAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRestartForLifecycleState(
		state, grant, restart, f.lifecyclePub, issueAt,
	); err != nil {
		t.Fatalf("recovered restart lineage rejected: %v", err)
	}
}


func TestRecoveryObservationRejectsInconsistentRunningLabel(t *testing.T) {
	f := newRecoveryFixture(t)
	expected := *f.activation.Receipt.ProcessIdentity
	observed := expected
	_, err := SignWorkloadRecoveryObservation(
		WorkloadRecoveryObservation{
			Version:                 WorkloadRecoveryObservationVersion,
			ObservationID:           "bad-running-observation",
			DeviceID:                f.state.DeviceID,
			WorkloadID:              f.state.WorkloadID,
			Generation:              f.state.Generation,
			ActivationID:            f.activation.Receipt.ActivationID,
			ActivationDigest:        f.state.ActivationDigest,
			ProcessID:               f.activation.Receipt.ProcessID,
			ExpectedProcessIdentity: &expected,
			ObservedProcessIdentity: &observed,
			CurrentBootIDHash:       expected.BootIDHash,
			ExpectedCgroup:          f.activation.Receipt.TargetCgroup,
			ExpectedCgroupID:        f.activation.Receipt.TargetCgroupID,
			ObservedCgroupID:        f.activation.Receipt.TargetCgroupID + 1,
			State:                   RecoveryObservationMatchRunning,
			ObservedAt:              f.base.Add(5 * time.Second),
		},
		f.hostPriv,
	)
	if !errors.Is(err, ErrRecoveryObservationInvalid) {
		t.Fatalf("inconsistent MATCH_RUNNING label accepted: %v", err)
	}
}

func TestReconciliationBootChangeMarksExitedUnknown(t *testing.T) {
	f := newRecoveryFixture(t)
	obs := f.signedObservation(t, RecoveryObservationBootChanged, f.base.Add(5*time.Second))
	decision, err := EvaluateWorkloadReconciliation(
		f.state, f.activation, obs, f.hostPub,
		f.lifecyclePriv, "lifecycle-authority", f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != ReconciliationMarkExitedUnknown {
		t.Fatalf("expected boot change to mark unknown exit, got %+v", decision.Decision)
	}
}
