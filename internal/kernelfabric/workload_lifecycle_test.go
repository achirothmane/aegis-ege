package kernelfabric

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type lifecycleFixture struct {
	base          time.Time
	evalNow       time.Time
	bootstrap     string
	spec          WorkloadLaunchSpec
	state         WorkloadLifecycleState
	priorGrant    SignedWorkloadAdmissionGrant
	activation    SignedWorkloadActivationReceipt
	exit          SignedWorkloadExitReceipt
	remote        SignedRemoteAttestationDecision
	verifierPub   ed25519.PublicKey
	verifierPriv  ed25519.PrivateKey
	issuerPub     ed25519.PublicKey
	issuerPriv    ed25519.PrivateKey
	hostPub       ed25519.PublicKey
	hostPriv      ed25519.PrivateKey
	lifecyclePub  ed25519.PublicKey
	lifecyclePriv ed25519.PrivateKey
}

func newLifecycleFixture(
	t *testing.T,
	exitClass string,
	currentRemoteVerifiedAt time.Time,
	restartCount uint32,
) lifecycleFixture {
	t.Helper()
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	if currentRemoteVerifiedAt.IsZero() {
		currentRemoteVerifiedAt = base
	}
	bootstrap := "sha256:" + strings.Repeat("a", 64)
	spec := admissionTestSpec()
	verifierPub, verifierPriv := admissionTestKeys(t)
	issuerPub, issuerPriv := admissionTestKeys(t)
	hostPub, hostPriv := admissionTestKeys(t)
	lifecyclePub, lifecyclePriv := admissionTestKeys(t)

	initialRemote := admissionTestRemoteDecision(
		t,
		base,
		"ALLOW",
		"device-1",
		bootstrap,
		verifierPriv,
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
	priorGrant, err := IssueWorkloadAdmissionGrant(
		req,
		initialRemote,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: verifierPub,
			AdmissionIssuerKey:      issuerPriv,
			AdmissionIssuerID:       "admission-authority",
			MaxAttestationAge:       5 * time.Minute,
			GrantTTL:                time.Minute,
			Now:                     func() time.Time { return base },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest, err := SignedWorkloadAdmissionGrantDigest(priorGrant)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := base.Add(time.Second)
	activation, err := SignWorkloadActivationReceipt(
		WorkloadActivationReceipt{
			Version:            WorkloadActivationReceiptVersion,
			ActivationID:       "activation-1",
			GrantID:            priorGrant.Grant.GrantID,
			GrantDigest:        grantDigest,
			DeviceID:           priorGrant.Grant.DeviceID,
			WorkloadID:         priorGrant.Grant.WorkloadID,
			WorkloadSpecDigest: priorGrant.Grant.WorkloadSpecDigest,
			TargetCgroup:       priorGrant.Grant.TargetCgroup,
			TargetCgroupID:     priorGrant.Grant.TargetCgroupID,
			ProcessID:          4321,
			StartedAt:          startedAt,
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
	exitedAt := base.Add(4 * time.Second)
	exitCode := 0
	signal := 0
	switch exitClass {
	case ExitClassClean:
	case ExitClassNonZero:
		exitCode = 2
	case ExitClassSignal:
		exitCode = 137
		signal = 9
	default:
		t.Fatalf("unsupported fixture exit class %s", exitClass)
	}
	exit, err := SignWorkloadExitReceipt(
		WorkloadExitReceipt{
			Version:            WorkloadExitReceiptVersion,
			ExitID:             "exit-1",
			ActivationID:       activation.Receipt.ActivationID,
			ActivationDigest:   activationDigest,
			GrantID:            activation.Receipt.GrantID,
			GrantDigest:        activation.Receipt.GrantDigest,
			DeviceID:           activation.Receipt.DeviceID,
			WorkloadID:         activation.Receipt.WorkloadID,
			WorkloadSpecDigest: activation.Receipt.WorkloadSpecDigest,
			TargetCgroup:       activation.Receipt.TargetCgroup,
			TargetCgroupID:     activation.Receipt.TargetCgroupID,
			ProcessID:          activation.Receipt.ProcessID,
			ExitClass:          exitClass,
			ExitCode:           exitCode,
			Signal:             signal,
			StartedAt:          activation.Receipt.StartedAt,
			ExitedAt:           exitedAt,
		},
		hostPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	exitDigest, err := SignedWorkloadExitReceiptDigest(exit)
	if err != nil {
		t.Fatal(err)
	}
	state := WorkloadLifecycleState{
		Version:                WorkloadLifecycleStateVersion,
		DeviceID:               "device-1",
		WorkloadID:             "workload-1",
		Generation:             1,
		State:                  LifecycleStateExited,
		ActivationDigest:       activationDigest,
		ExitDigest:             exitDigest,
		RestartCountInWindow:   restartCount,
		RestartWindowStartedAt: base,
		UpdatedAt:              exitedAt,
	}
	currentRemote := admissionTestRemoteDecision(
		t,
		currentRemoteVerifiedAt,
		"ALLOW",
		"device-1",
		bootstrap,
		verifierPriv,
	)
	return lifecycleFixture{
		base:          base,
		evalNow:       base.Add(6 * time.Second),
		bootstrap:     bootstrap,
		spec:          spec,
		state:         state,
		priorGrant:    priorGrant,
		activation:    activation,
		exit:          exit,
		remote:        currentRemote,
		verifierPub:   verifierPub,
		verifierPriv:  verifierPriv,
		issuerPub:     issuerPub,
		issuerPriv:    issuerPriv,
		hostPub:       hostPub,
		hostPriv:      hostPriv,
		lifecyclePub:  lifecyclePub,
		lifecyclePriv: lifecyclePriv,
	}
}

func (f lifecycleFixture) policy() WorkloadRestartPolicy {
	return WorkloadRestartPolicy{
		MaxRestartsPerWindow:     3,
		RestartWindow:            10 * time.Minute,
		BaseBackoff:              time.Second,
		MaxBackoff:               30 * time.Second,
		ReattestAfter:            2 * time.Minute,
		ReattestOnNonZero:        true,
		ReattestOnSignal:         true,
		AllowCleanExitRestart:    false,
		DecisionTTL:              time.Minute,
		LifecycleAuthorityKey:    f.lifecyclePriv,
		LifecycleAuthorityID:     "lifecycle-authority",
		RemoteVerifierPublicKey:  f.verifierPub,
		AdmissionIssuerPublicKey: f.issuerPub,
		HostAttestorPublicKey:    f.hostPub,
		Now:                      func() time.Time { return f.evalNow },
	}
}

func TestSignedWorkloadExitReceiptRoundTrip(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassNonZero, time.Time{}, 0)
	if err := VerifySignedWorkloadExitReceipt(f.exit, f.hostPub); err != nil {
		t.Fatalf("valid exit receipt rejected: %v", err)
	}
	tampered := f.exit
	tampered.Receipt.ExitCode = 3
	if err := VerifySignedWorkloadExitReceipt(tampered, f.hostPub); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered exit receipt was not rejected: %v", err)
	}
}

func TestRestartCleanExitBlockedByDefault(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassClean, time.Time{}, 0)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeBlock {
		t.Fatalf("expected BLOCK, got %+v", decision.Decision)
	}
}

func TestRestartNonZeroRequiresPostExitReattestation(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassNonZero, time.Time{}, 0)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireReattestation {
		t.Fatalf("expected re-attestation, got %+v", decision.Decision)
	}
}

func TestRestartPostExitReattestationAllowsFreshGrantPath(t *testing.T) {
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	f := newLifecycleFixture(t, ExitClassNonZero, base.Add(5*time.Second), 0)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireFreshGrant {
		t.Fatalf("expected fresh grant path, got %+v", decision.Decision)
	}
	if !decision.Decision.NotBefore.Equal(f.evalNow.Add(time.Second)) {
		t.Fatalf("unexpected restart backoff: %s", decision.Decision.NotBefore)
	}
}

func TestRestartBudgetExhaustionBlocks(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassNonZero, time.Date(2026, 9, 28, 1, 0, 5, 0, time.UTC), 3)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeBlock {
		t.Fatalf("expected budget BLOCK, got %+v", decision.Decision)
	}
}

func TestRestartWindowResetClearsBudgetAndBackoff(t *testing.T) {
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	f := newLifecycleFixture(t, ExitClassClean, base.Add(5*time.Second), 3)
	f.state.RestartWindowStartedAt = base.Add(-20 * time.Minute)
	policy := f.policy()
	policy.AllowCleanExitRestart = true
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireFreshGrant ||
		decision.Decision.RestartCountInWindow != 0 ||
		!decision.Decision.RestartWindowStartedAt.Equal(f.evalNow) ||
		!decision.Decision.NotBefore.Equal(f.evalNow.Add(time.Second)) {
		t.Fatalf("window did not reset correctly: %+v", decision.Decision)
	}
}

func TestRestartBootstrapChangeBlocksLifecycle(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassClean, time.Time{}, 0)
	policy := f.policy()
	policy.AllowCleanExitRestart = true
	f.remote = admissionTestRemoteDecision(
		t,
		f.evalNow,
		"ALLOW",
		"device-1",
		"sha256:"+strings.Repeat("c", 64),
		f.verifierPriv,
	)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeBlock {
		t.Fatalf("bootstrap change should block lifecycle continuation: %+v", decision.Decision)
	}
}

func TestRestartDecisionSignatureCoversLineage(t *testing.T) {
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	f := newLifecycleFixture(t, ExitClassClean, base.Add(5*time.Second), 0)
	policy := f.policy()
	policy.AllowCleanExitRestart = true
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifyAt := decision.Decision.NotBefore.Add(time.Millisecond)
	if err := VerifySignedWorkloadRestartDecision(decision, f.lifecyclePub, verifyAt); err != nil {
		t.Fatalf("valid restart decision rejected: %v", err)
	}
	decision.Decision.PreviousGeneration++
	if err := VerifySignedWorkloadRestartDecision(decision, f.lifecyclePub, verifyAt); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered restart lineage was not rejected: %v", err)
	}
}

func TestIssueRestartGrantRequiresMatchingFreshRestartDecision(t *testing.T) {
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	f := newLifecycleFixture(t, ExitClassNonZero, base.Add(5*time.Second), 0)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireFreshGrant {
		t.Fatalf("unexpected restart outcome: %+v", decision.Decision)
	}
	issueAt := decision.Decision.NotBefore.Add(time.Millisecond)
	req, err := NewWorkloadAdmissionRequest(
		"device-1",
		"workload-1",
		f.spec,
		f.priorGrant.Grant.TargetCgroup,
		f.priorGrant.Grant.TargetCgroupID,
		f.bootstrap,
		issueAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := IssueRestartWorkloadAdmissionGrant(
		req,
		f.remote,
		decision,
		f.lifecyclePub,
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
	if err := VerifySignedWorkloadAdmissionGrant(grant, f.issuerPub, issueAt); err != nil {
		t.Fatalf("fresh restart grant rejected: %v", err)
	}
	if err := ValidateRestartForLifecycleState(
		f.state,
		grant,
		decision,
		f.lifecyclePub,
		issueAt,
	); err != nil {
		t.Fatalf("restart grant did not satisfy lifecycle state: %v", err)
	}
}

func TestIssueRestartGrantRejectsReattestationOutcome(t *testing.T) {
	f := newLifecycleFixture(t, ExitClassNonZero, time.Time{}, 0)
	decision, err := EvaluateWorkloadRestart(
		f.state, f.priorGrant, f.activation, f.exit, f.remote, f.policy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RestartOutcomeRequireReattestation {
		t.Fatalf("fixture did not require re-attestation: %+v", decision.Decision)
	}
	issueAt := decision.Decision.NotBefore.Add(time.Millisecond)
	req, err := NewWorkloadAdmissionRequest(
		"device-1",
		"workload-1",
		f.spec,
		f.priorGrant.Grant.TargetCgroup,
		f.priorGrant.Grant.TargetCgroupID,
		f.bootstrap,
		issueAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = IssueRestartWorkloadAdmissionGrant(
		req,
		f.remote,
		decision,
		f.lifecyclePub,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: f.verifierPub,
			AdmissionIssuerKey:      f.issuerPriv,
			AdmissionIssuerID:       "issuer",
			Now:                     func() time.Time { return issueAt },
		},
		issueAt,
	)
	if !errors.Is(err, ErrRestartDecisionRejected) {
		t.Fatalf("expected restart decision rejection, got %v", err)
	}
}

func TestBoundedRestartBackoffCapsWithoutOverflow(t *testing.T) {
	if got := boundedRestartBackoff(time.Second, 30*time.Second, 0); got != time.Second {
		t.Fatalf("count 0 backoff=%s", got)
	}
	if got := boundedRestartBackoff(time.Second, 30*time.Second, 4); got != 16*time.Second {
		t.Fatalf("count 4 backoff=%s", got)
	}
	if got := boundedRestartBackoff(time.Second, 30*time.Second, 1000); got != 30*time.Second {
		t.Fatalf("large count did not cap: %s", got)
	}
}
