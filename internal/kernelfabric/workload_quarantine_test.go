
package kernelfabric

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type quarantineFixture struct {
	recovery      recoveryFixture
	state         WorkloadLifecycleState
	quarantine    SignedWorkloadReconciliationDecision
	clearance     SignedWorkloadRecoveryObservation
	remote        SignedRemoteAttestationDecision
	operatorPub   ed25519.PublicKey
	operatorPriv  ed25519.PrivateKey
	approval      SignedQuarantineOperatorApproval
	release       SignedQuarantineReleaseDecision
}

func newQuarantineFixture(t *testing.T) quarantineFixture {
	t.Helper()
	f := newRecoveryFixture(t)
	qObs := f.signedObservation(
		t,
		RecoveryObservationCgroupMismatch,
		f.base.Add(5*time.Second),
	)
	quarantine, err := EvaluateWorkloadReconciliation(
		f.state,
		f.activation,
		qObs,
		f.hostPub,
		f.lifecyclePriv,
		"lifecycle-authority",
		f.base.Add(6*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if quarantine.Decision.Outcome != ReconciliationQuarantine {
		t.Fatalf("fixture did not quarantine: %+v", quarantine.Decision)
	}
	qDigest, err := SignedWorkloadReconciliationDecisionDigest(quarantine)
	if err != nil {
		t.Fatal(err)
	}
	state := f.state
	state.State = LifecycleStateQuarantined
	state.LifecycleEpoch = 1
	state.RecoveryDigest = qDigest
	state.UpdatedAt = quarantine.Decision.DecidedAt

	expected := *f.activation.Receipt.ProcessIdentity
	clearanceObs := WorkloadRecoveryObservation{
		Version:                 WorkloadRecoveryObservationVersion,
		ObservationID:           "clearance-observation-1",
		DeviceID:                state.DeviceID,
		WorkloadID:              state.WorkloadID,
		Generation:              state.Generation,
		ActivationID:            f.activation.Receipt.ActivationID,
		ActivationDigest:        state.ActivationDigest,
		PriorRecoveryDigest:     state.RecoveryDigest,
		ProcessID:               f.activation.Receipt.ProcessID,
		ExpectedProcessIdentity: &expected,
		CurrentBootIDHash:       expected.BootIDHash,
		ExpectedCgroup:          f.activation.Receipt.TargetCgroup,
		ExpectedCgroupID:        f.activation.Receipt.TargetCgroupID,
		State:                   RecoveryObservationAbsent,
		ObservedAt:              f.base.Add(8*time.Second),
	}
	clearance, err := SignWorkloadRecoveryObservation(clearanceObs, f.hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	remote := admissionTestRemoteDecision(
		t,
		f.base.Add(9*time.Second),
		"ALLOW",
		state.DeviceID,
		f.bootstrap,
		f.verifierPriv,
	)
	operatorPub, operatorPriv := admissionTestKeys(t)

	trust := QuarantineReleaseTrust{
		LifecycleAuthorityPublicKey: f.lifecyclePub,
		HostAttestorPublicKey:       f.hostPub,
		RemoteVerifierPublicKey:     f.verifierPub,
		AdmissionIssuerPublicKey:    f.issuerPub,
	}
	approval, err := IssueQuarantineOperatorApproval(
		state,
		f.priorGrant,
		f.activation,
		quarantine,
		clearance,
		remote,
		trust,
		operatorPriv,
		"operator-1",
		"INC-2026-001",
		"process remediated and host re-attested",
		5*time.Minute,
		f.base.Add(10*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	trust.OperatorPublicKey = operatorPub
	release, err := EvaluateQuarantineRelease(
		state,
		f.priorGrant,
		f.activation,
		quarantine,
		clearance,
		remote,
		approval,
		trust,
		f.lifecyclePriv,
		"lifecycle-authority",
		time.Minute,
		f.base.Add(11*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	return quarantineFixture{
		recovery: f,
		state: state,
		quarantine: quarantine,
		clearance: clearance,
		remote: remote,
		operatorPub: operatorPub,
		operatorPriv: operatorPriv,
		approval: approval,
		release: release,
	}
}

func (q quarantineFixture) trust() QuarantineReleaseTrust {
	return QuarantineReleaseTrust{
		LifecycleAuthorityPublicKey: q.recovery.lifecyclePub,
		HostAttestorPublicKey:       q.recovery.hostPub,
		RemoteVerifierPublicKey:     q.recovery.verifierPub,
		AdmissionIssuerPublicKey:    q.recovery.issuerPub,
		OperatorPublicKey:           q.operatorPub,
	}
}

func TestQuarantineOperatorApprovalRequiresInactiveOriginalProcess(t *testing.T) {
	q := newQuarantineFixture(t)
	expected := *q.recovery.activation.Receipt.ProcessIdentity
	observed := expected
	liveObs := WorkloadRecoveryObservation{
		Version:                 WorkloadRecoveryObservationVersion,
		ObservationID:           "still-live",
		DeviceID:                q.state.DeviceID,
		WorkloadID:              q.state.WorkloadID,
		Generation:              q.state.Generation,
		ActivationID:            q.recovery.activation.Receipt.ActivationID,
		ActivationDigest:        q.state.ActivationDigest,
		PriorRecoveryDigest:     q.state.RecoveryDigest,
		ProcessID:               q.recovery.activation.Receipt.ProcessID,
		ExpectedProcessIdentity: &expected,
		ObservedProcessIdentity: &observed,
		CurrentBootIDHash:       expected.BootIDHash,
		ExpectedCgroup:          q.recovery.activation.Receipt.TargetCgroup,
		ExpectedCgroupID:        q.recovery.activation.Receipt.TargetCgroupID,
		ObservedCgroup:          q.recovery.activation.Receipt.TargetCgroup,
		ObservedCgroupID:        q.recovery.activation.Receipt.TargetCgroupID,
		State:                   RecoveryObservationMatchRunning,
		ObservedAt:              q.recovery.base.Add(8*time.Second),
	}
	live, err := SignWorkloadRecoveryObservation(liveObs, q.recovery.hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = IssueQuarantineOperatorApproval(
		q.state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.quarantine,
		live,
		q.remote,
		QuarantineReleaseTrust{
			LifecycleAuthorityPublicKey: q.recovery.lifecyclePub,
			HostAttestorPublicKey:       q.recovery.hostPub,
			RemoteVerifierPublicKey:     q.recovery.verifierPub,
			AdmissionIssuerPublicKey:    q.recovery.issuerPub,
		},
		q.operatorPriv,
		"operator-1",
		"INC-live",
		"should not release",
		time.Minute,
		q.recovery.base.Add(10*time.Second),
	)
	if !errors.Is(err, ErrQuarantineClearanceUnsafe) {
		t.Fatalf("live process clearance was accepted: %v", err)
	}
}

func TestQuarantineReleaseRequiresAttestationAfterClearance(t *testing.T) {
	q := newQuarantineFixture(t)
	oldRemote := admissionTestRemoteDecision(
		t,
		q.recovery.base.Add(7*time.Second),
		"ALLOW",
		q.state.DeviceID,
		q.recovery.bootstrap,
		q.recovery.verifierPriv,
	)
	_, err := IssueQuarantineOperatorApproval(
		q.state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.quarantine,
		q.clearance,
		oldRemote,
		QuarantineReleaseTrust{
			LifecycleAuthorityPublicKey: q.recovery.lifecyclePub,
			HostAttestorPublicKey:       q.recovery.hostPub,
			RemoteVerifierPublicKey:     q.recovery.verifierPub,
			AdmissionIssuerPublicKey:    q.recovery.issuerPub,
		},
		q.operatorPriv,
		"operator-1",
		"INC-old-attestation",
		"attestation predates clearance",
		time.Minute,
		q.recovery.base.Add(10*time.Second),
	)
	if !errors.Is(err, ErrQuarantineReleaseRejected) {
		t.Fatalf("pre-clearance attestation was accepted: %v", err)
	}
}

func TestQuarantineOperatorApprovalTamperRejected(t *testing.T) {
	q := newQuarantineFixture(t)
	if err := VerifySignedQuarantineOperatorApproval(
		q.approval,
		q.operatorPub,
		q.recovery.base.Add(11*time.Second),
	); err != nil {
		t.Fatalf("valid operator approval rejected: %v", err)
	}
	tampered := q.approval
	tampered.Approval.Reason = "different reason"
	if err := VerifySignedQuarantineOperatorApproval(
		tampered,
		q.operatorPub,
		q.recovery.base.Add(11*time.Second),
	); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered operator approval was not rejected: %v", err)
	}
}

func TestQuarantineReleaseAdvancesExactlyOneEpoch(t *testing.T) {
	q := newQuarantineFixture(t)
	d := q.release.Decision
	if d.Outcome != QuarantineReleaseOutcome ||
		d.PreviousLifecycleEpoch != 1 ||
		d.NewLifecycleEpoch != 2 {
		t.Fatalf("unexpected release epoch transition: %+v", d)
	}
	if err := VerifySignedQuarantineReleaseDecision(
		q.release,
		q.recovery.lifecyclePub,
		q.recovery.base.Add(12*time.Second),
	); err != nil {
		t.Fatalf("valid release decision rejected: %v", err)
	}
}

func TestQuarantineReleaseRejectsDifferentLifecycleSigner(t *testing.T) {
	q := newQuarantineFixture(t)
	_, wrongPriv := admissionTestKeys(t)
	_, err := EvaluateQuarantineRelease(
		q.state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.quarantine,
		q.clearance,
		q.remote,
		q.approval,
		q.trust(),
		wrongPriv,
		"lifecycle-authority",
		time.Minute,
		q.recovery.base.Add(11*time.Second),
	)
	if err == nil || !strings.Contains(err.Error(), "does not match trusted public key") {
		t.Fatalf("wrong lifecycle signer was not rejected: %v", err)
	}
}

func TestReleasedQuarantineRequiresFreshGrantInNewEpoch(t *testing.T) {
	q := newQuarantineFixture(t)
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(q.release)
	if err != nil {
		t.Fatal(err)
	}
	state := q.state
	state.State = LifecycleStateExitedUnknown
	state.LifecycleEpoch = q.release.Decision.NewLifecycleEpoch
	state.RecoveryDigest = releaseDigest
	state.UpdatedAt = q.release.Decision.DecidedAt

	now := q.recovery.base.Add(12 * time.Second)
	policy := WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               time.Minute,
		ReattestAfter:            2 * time.Minute,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    q.recovery.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  q.recovery.verifierPub,
		AdmissionIssuerPublicKey: q.recovery.issuerPub,
		HostAttestorPublicKey:    q.recovery.hostPub,
		Now:                      func() time.Time { return now },
	}
	restart, err := EvaluateQuarantineReleasedRestart(
		state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.release,
		q.remote,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Decision.Outcome != RestartOutcomeRequireFreshGrant ||
		restart.Decision.LifecycleEpoch != 2 ||
		restart.Decision.PreviousRecoveryDigest != releaseDigest {
		t.Fatalf("unexpected released restart decision: %+v", restart.Decision)
	}

	issueAt := restart.Decision.NotBefore.Add(time.Millisecond)
	req, err := NewWorkloadAdmissionRequest(
		state.DeviceID,
		state.WorkloadID,
		q.recovery.spec,
		q.recovery.priorGrant.Grant.TargetCgroup,
		q.recovery.priorGrant.Grant.TargetCgroupID,
		q.recovery.bootstrap,
		issueAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := IssueRestartWorkloadAdmissionGrant(
		req,
		q.remote,
		restart,
		q.recovery.lifecyclePub,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: q.recovery.verifierPub,
			AdmissionIssuerKey:      q.recovery.issuerPriv,
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
		state,
		grant,
		restart,
		q.recovery.lifecyclePub,
		issueAt,
	); err != nil {
		t.Fatalf("released restart lineage rejected: %v", err)
	}

	oldEpoch := restart
	oldEpoch.Decision.LifecycleEpoch = 1
	oldEpoch, err = SignWorkloadRestartDecision(oldEpoch.Decision, q.recovery.lifecyclePriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRestartForLifecycleState(
		state,
		grant,
		oldEpoch,
		q.recovery.lifecyclePub,
		issueAt,
	); !errors.Is(err, ErrLifecycleInvalidLineage) {
		t.Fatalf("old lifecycle epoch restart was not rejected: %v", err)
	}
}


func TestReleasedQuarantineAcceptsFreshPostReleaseReattestation(t *testing.T) {
	q := newQuarantineFixture(t)
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(q.release)
	if err != nil {
		t.Fatal(err)
	}
	state := q.state
	state.State = LifecycleStateExitedUnknown
	state.LifecycleEpoch = q.release.Decision.NewLifecycleEpoch
	state.RecoveryDigest = releaseDigest
	state.UpdatedAt = q.release.Decision.DecidedAt

	freshRemote := admissionTestRemoteDecision(
		t,
		q.release.Decision.DecidedAt.Add(time.Second),
		"ALLOW",
		state.DeviceID,
		q.recovery.bootstrap,
		q.recovery.verifierPriv,
	)
	now := q.release.Decision.DecidedAt.Add(2 * time.Second)
	policy := WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               time.Minute,
		ReattestAfter:            2 * time.Minute,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    q.recovery.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  q.recovery.verifierPub,
		AdmissionIssuerPublicKey: q.recovery.issuerPub,
		HostAttestorPublicKey:    q.recovery.hostPub,
		Now:                      func() time.Time { return now },
	}
	restart, err := EvaluateQuarantineReleasedRestart(
		state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.release,
		freshRemote,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Decision.Outcome != RestartOutcomeRequireFreshGrant {
		t.Fatalf("fresh post-release re-attestation was not accepted: %+v", restart.Decision)
	}
	newDigest, err := SignedRemoteAttestationDecisionDigest(freshRemote)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Decision.CurrentRemoteDecisionDigest != newDigest {
		t.Fatalf("restart decision did not bind replacement attestation: %+v", restart.Decision)
	}
}

func TestReleasedQuarantineRejectsDifferentPreReleaseAttestation(t *testing.T) {
	q := newQuarantineFixture(t)
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(q.release)
	if err != nil {
		t.Fatal(err)
	}
	state := q.state
	state.State = LifecycleStateExitedUnknown
	state.LifecycleEpoch = q.release.Decision.NewLifecycleEpoch
	state.RecoveryDigest = releaseDigest
	state.UpdatedAt = q.release.Decision.DecidedAt

	otherOldRemote := admissionTestRemoteDecision(
		t,
		q.release.Decision.DecidedAt.Add(-time.Second),
		"ALLOW",
		state.DeviceID,
		q.recovery.bootstrap,
		q.recovery.verifierPriv,
	)
	now := q.release.Decision.DecidedAt.Add(2 * time.Second)
	policy := WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               time.Minute,
		ReattestAfter:            2 * time.Minute,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    q.recovery.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  q.recovery.verifierPub,
		AdmissionIssuerPublicKey: q.recovery.issuerPub,
		HostAttestorPublicKey:    q.recovery.hostPub,
		Now:                      func() time.Time { return now },
	}
	restart, err := EvaluateQuarantineReleasedRestart(
		state,
		q.recovery.priorGrant,
		q.recovery.activation,
		q.release,
		otherOldRemote,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Decision.Outcome != RestartOutcomeRequireReattestation {
		t.Fatalf("different pre-release attestation should not be accepted: %+v", restart.Decision)
	}
}
