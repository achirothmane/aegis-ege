
package kernelfabric

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type runtimeTrustFixture struct {
	recovery recoveryFixture
	policyDigest string
	remote SignedRemoteAttestationDecision
	lease SignedRuntimeTrustLease
	state WorkloadLifecycleState
	now time.Time
}

func newRuntimeTrustFixture(t *testing.T) runtimeTrustFixture {
	t.Helper()
	f := newRecoveryFixture(t)
	policyDigest := "sha256:" + strings.Repeat("d", 64)
	remote := admissionTestRemoteDecision(
		t,
		f.base.Add(2*time.Second),
		"ALLOW",
		f.state.DeviceID,
		f.bootstrap,
		f.verifierPriv,
	)
	now := f.base.Add(3 * time.Second)
	lease, err := IssueRuntimeTrustLease(
		f.state,
		f.priorGrant,
		f.activation,
		remote,
		nil,
		RuntimeTrustPolicy{
			LifecycleAuthorityKey:    f.lifecyclePriv,
			LifecycleAuthorityID:     "lifecycle-authority",
			RemoteVerifierPublicKey:  f.verifierPub,
			AdmissionIssuerPublicKey: f.issuerPub,
			HostAttestorPublicKey:    f.hostPub,
			PolicyDigest:             policyDigest,
			MaxAttestationAge:        2 * time.Minute,
			LeaseTTL:                 30 * time.Second,
			Now:                      func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SignedRuntimeTrustLeaseDigest(lease)
	if err != nil {
		t.Fatal(err)
	}
	state := f.state
	state.RuntimeTrustEpoch = lease.Lease.LeaseEpoch
	state.RuntimeTrustLeaseDigest = digest
	state.RuntimeTrustExpiresAt = lease.Lease.ExpiresAt
	state.UpdatedAt = now
	return runtimeTrustFixture{
		recovery: f,
		policyDigest: policyDigest,
		remote: remote,
		lease: lease,
		state: state,
		now: now,
	}
}

func (f runtimeTrustFixture) evalPolicy(now time.Time) RuntimeTrustEvaluationPolicy {
	return RuntimeTrustEvaluationPolicy{
		LifecycleAuthorityKey:   f.recovery.lifecyclePriv,
		LifecycleAuthorityID:    "lifecycle-authority",
		RemoteVerifierPublicKey: f.recovery.verifierPub,
		HostAttestorPublicKey:   f.recovery.hostPub,
		PolicyDigest:            f.policyDigest,
		Now:                     func() time.Time { return now },
	}
}

func TestIssueRuntimeTrustLeaseBindsRunningGeneration(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	l := f.lease.Lease
	if l.LeaseEpoch != 1 ||
		l.DeviceID != f.state.DeviceID ||
		l.WorkloadID != f.state.WorkloadID ||
		l.Generation != f.state.Generation ||
		l.LifecycleEpoch != EffectiveLifecycleEpoch(f.state) ||
		l.ActivationDigest != f.state.ActivationDigest ||
		l.PolicyDigest != f.policyDigest ||
		l.TargetCgroupID != f.recovery.activation.Receipt.TargetCgroupID {
		t.Fatalf("runtime trust lease lost lineage: %+v", l)
	}
	if err := VerifySignedRuntimeTrustLease(
		f.lease,
		f.recovery.lifecyclePub,
		f.now,
	); err != nil {
		t.Fatalf("valid runtime trust lease rejected: %v", err)
	}
}

func TestRuntimeTrustLeaseExpiryCappedByRemoteAttestation(t *testing.T) {
	f := newRecoveryFixture(t)
	remoteAt := f.base.Add(2 * time.Second)
	remote := admissionTestRemoteDecision(
		t, remoteAt, "ALLOW", f.state.DeviceID, f.bootstrap, f.verifierPriv,
	)
	now := f.base.Add(3 * time.Second)
	lease, err := IssueRuntimeTrustLease(
		f.state,
		f.priorGrant,
		f.activation,
		remote,
		nil,
		RuntimeTrustPolicy{
			LifecycleAuthorityKey:    f.lifecyclePriv,
			LifecycleAuthorityID:     "lifecycle-authority",
			RemoteVerifierPublicKey:  f.verifierPub,
			AdmissionIssuerPublicKey: f.issuerPub,
			HostAttestorPublicKey:    f.hostPub,
			PolicyDigest:             "sha256:" + strings.Repeat("d", 64),
			MaxAttestationAge:        10 * time.Second,
			LeaseTTL:                 time.Minute,
			Now:                      func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := remoteAt.Add(10 * time.Second)
	if !lease.Lease.ExpiresAt.Equal(want) {
		t.Fatalf("lease expiry=%s want remote freshness deadline=%s", lease.Lease.ExpiresAt, want)
	}
}

func TestRuntimeTrustRenewalRequiresNewerRemoteEvidence(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	_, err := IssueRuntimeTrustLease(
		f.state,
		f.recovery.priorGrant,
		f.recovery.activation,
		f.remote,
		&f.lease,
		RuntimeTrustPolicy{
			LifecycleAuthorityKey:    f.recovery.lifecyclePriv,
			LifecycleAuthorityID:     "lifecycle-authority",
			RemoteVerifierPublicKey:  f.recovery.verifierPub,
			AdmissionIssuerPublicKey: f.recovery.issuerPub,
			HostAttestorPublicKey:    f.recovery.hostPub,
			PolicyDigest:             f.policyDigest,
			MaxAttestationAge:        2 * time.Minute,
			LeaseTTL:                 30 * time.Second,
			Now:                      func() time.Time { return f.now.Add(time.Second) },
		},
	)
	if err == nil {
		t.Fatal("same remote attestation renewed runtime trust")
	}

	newRemote := admissionTestRemoteDecision(
		t,
		f.remote.Decision.VerifiedAt.Add(time.Second),
		"ALLOW",
		f.state.DeviceID,
		f.recovery.bootstrap,
		f.recovery.verifierPriv,
	)
	renewed, err := IssueRuntimeTrustLease(
		f.state,
		f.recovery.priorGrant,
		f.recovery.activation,
		newRemote,
		&f.lease,
		RuntimeTrustPolicy{
			LifecycleAuthorityKey:    f.recovery.lifecyclePriv,
			LifecycleAuthorityID:     "lifecycle-authority",
			RemoteVerifierPublicKey:  f.recovery.verifierPub,
			AdmissionIssuerPublicKey: f.recovery.issuerPub,
			HostAttestorPublicKey:    f.recovery.hostPub,
			PolicyDigest:             f.policyDigest,
			MaxAttestationAge:        2 * time.Minute,
			LeaseTTL:                 30 * time.Second,
			Now:                      func() time.Time { return f.now.Add(2 * time.Second) },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Lease.LeaseEpoch != f.lease.Lease.LeaseEpoch+1 {
		t.Fatalf("renewed lease epoch=%d", renewed.Lease.LeaseEpoch)
	}
}

func TestRuntimeTrustEvaluationKeepsValidLease(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		nil,
		f.evalPolicy(f.now.Add(time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RuntimeTrustKeepRunning {
		t.Fatalf("valid lease outcome=%s", decision.Decision.Outcome)
	}
}

func TestRuntimeTrustEvaluationRevokesExpiredLease(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		nil,
		f.evalPolicy(f.lease.Lease.ExpiresAt.Add(time.Nanosecond)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RuntimeTrustRevoke ||
		len(decision.Decision.ReasonCodes) == 0 ||
		decision.Decision.ReasonCodes[0] != "RUNTIME_TRUST_LEASE_EXPIRED" {
		t.Fatalf("expired lease did not revoke: %+v", decision.Decision)
	}
}

func TestRuntimeTrustEvaluationRevokesPolicySupersession(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	policy := f.evalPolicy(f.now.Add(time.Second))
	policy.PolicyDigest = "sha256:" + strings.Repeat("e", 64)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		nil,
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RuntimeTrustRevoke ||
		decision.Decision.ReasonCodes[0] != "RUNTIME_POLICY_SUPERSEDED" {
		t.Fatalf("policy supersession did not revoke: %+v", decision.Decision)
	}
}

func TestRuntimeTrustEvaluationRevokesRemoteBlock(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	blocked := admissionTestRemoteDecision(
		t,
		f.now.Add(time.Second),
		"BLOCK",
		f.state.DeviceID,
		f.recovery.bootstrap,
		f.recovery.verifierPriv,
	)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		&blocked,
		f.evalPolicy(f.now.Add(2*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RuntimeTrustRevoke {
		t.Fatalf("remote BLOCK did not revoke: %+v", decision.Decision)
	}
}

func TestRuntimeTrustEvaluationRequestsRenewalForNewerAllow(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	newRemote := admissionTestRemoteDecision(
		t,
		f.now.Add(time.Second),
		"ALLOW",
		f.state.DeviceID,
		f.recovery.bootstrap,
		f.recovery.verifierPriv,
	)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		&newRemote,
		f.evalPolicy(f.now.Add(2*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Outcome != RuntimeTrustRenewRequired {
		t.Fatalf("newer ALLOW did not request renewal: %+v", decision.Decision)
	}
}

func TestRuntimeTrustEvaluationRejectsLeaseRollback(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	state := f.state
	state.RuntimeTrustEpoch++
	_, err := EvaluateRuntimeTrust(
		state,
		f.recovery.activation,
		f.lease,
		nil,
		f.evalPolicy(f.now.Add(time.Second)),
	)
	if !errors.Is(err, ErrRuntimeTrustRollback) {
		t.Fatalf("lease rollback was not rejected: %v", err)
	}
}

func TestRuntimeTrustDecisionSignatureCoversOutcome(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	decision, err := EvaluateRuntimeTrust(
		f.state,
		f.recovery.activation,
		f.lease,
		nil,
		f.evalPolicy(f.now.Add(time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedRuntimeTrustDecision(
		decision,
		f.recovery.lifecyclePub,
	); err != nil {
		t.Fatalf("valid runtime decision rejected: %v", err)
	}
	decision.Decision.Outcome = RuntimeTrustRevoke
	if err := VerifySignedRuntimeTrustDecision(
		decision,
		f.recovery.lifecyclePub,
	); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered runtime trust decision was not rejected: %v", err)
	}
}
