package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func admissionTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func admissionTestSpec() WorkloadLaunchSpec {
	return WorkloadLaunchSpec{
		Executable: "/bin/echo",
		Args:       []string{"hello"},
		WorkingDir: "/",
		Environment: []WorkloadEnvironmentVariable{
			{Name: "B", Value: "2"},
			{Name: "A", Value: "1"},
		},
	}
}

func admissionTestRemoteDecision(
	t *testing.T,
	now time.Time,
	decisionValue string,
	deviceID string,
	bootstrapDigest string,
	verifierPrivateKey ed25519.PrivateKey,
) SignedRemoteAttestationDecision {
	t.Helper()
	signed, err := signRemoteDecision(
		RemoteAttestationDecision{
			Version:         RemoteAttestationDecisionVersion,
			DecisionID:      "remote-decision-1",
			ChallengeID:     "challenge-1",
			DeviceID:        deviceID,
			Decision:        decisionValue,
			BootstrapDigest: bootstrapDigest,
			AKPublicSHA256:  "sha256:" + strings.Repeat("b", 64),
			VerifiedAt:      now.UTC(),
		},
		RemoteAttestationPolicy{
			VerifierKey: verifierPrivateKey,
			VerifierID:  "remote-verifier",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func admissionTestGrant(
	t *testing.T,
	now time.Time,
) (SignedWorkloadAdmissionGrant, WorkloadLaunchSpec, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	verifierPub, verifierPriv := admissionTestKeys(t)
	issuerPub, issuerPriv := admissionTestKeys(t)
	bootstrap := "sha256:" + strings.Repeat("a", 64)
	spec := admissionTestSpec()
	req, err := NewWorkloadAdmissionRequest(
		"device-1",
		"workload-1",
		spec,
		"/sys/fs/cgroup/aegis-workload",
		4242,
		bootstrap,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := admissionTestRemoteDecision(
		t, now, "ALLOW", req.DeviceID, bootstrap, verifierPriv,
	)
	grant, err := IssueWorkloadAdmissionGrant(
		req,
		decision,
		WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: verifierPub,
			AdmissionIssuerKey:      issuerPriv,
			AdmissionIssuerID:       "admission-authority",
			MaxAttestationAge:       time.Minute,
			GrantTTL:                20 * time.Second,
			Now:                     func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return grant, spec, issuerPub, issuerPriv
}

func TestWorkloadSpecDigestNormalizesEnvironmentOrder(t *testing.T) {
	first := admissionTestSpec()
	second := admissionTestSpec()
	second.Environment[0], second.Environment[1] = second.Environment[1], second.Environment[0]

	d1, err := WorkloadLaunchSpecDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := WorkloadLaunchSpecDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("environment ordering changed digest: %s != %s", d1, d2)
	}
}

func TestIssueAdmissionGrantBindsFreshRemoteAllow(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	grant, _, issuerPub, _ := admissionTestGrant(t, now)
	if err := VerifySignedWorkloadAdmissionGrant(grant, issuerPub, now.Add(time.Second)); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	if grant.Grant.TargetCgroupID != 4242 ||
		grant.Grant.DeviceID != "device-1" ||
		grant.Grant.WorkloadID != "workload-1" {
		t.Fatalf("grant lost admission bindings: %+v", grant.Grant)
	}
}

func TestIssueAdmissionGrantRejectsBlockDecision(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	verifierPub, verifierPriv := admissionTestKeys(t)
	_, issuerPriv := admissionTestKeys(t)
	bootstrap := "sha256:" + strings.Repeat("a", 64)
	req, err := NewWorkloadAdmissionRequest(
		"device-1", "workload-1", admissionTestSpec(),
		"/sys/fs/cgroup/x", 9, bootstrap, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := admissionTestRemoteDecision(t, now, "BLOCK", "device-1", bootstrap, verifierPriv)
	_, err = IssueWorkloadAdmissionGrant(req, decision, WorkloadAdmissionPolicy{
		RemoteVerifierPublicKey: verifierPub,
		AdmissionIssuerKey:      issuerPriv,
		AdmissionIssuerID:       "issuer",
		Now:                     func() time.Time { return now },
	})
	if !errors.Is(err, ErrAdmissionRemoteDecisionRejected) {
		t.Fatalf("expected remote decision rejection, got %v", err)
	}
}

func TestIssueAdmissionGrantRejectsStaleAttestation(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 3, 0, 0, time.UTC)
	verifiedAt := now.Add(-3 * time.Minute)
	verifierPub, verifierPriv := admissionTestKeys(t)
	_, issuerPriv := admissionTestKeys(t)
	bootstrap := "sha256:" + strings.Repeat("a", 64)
	req, err := NewWorkloadAdmissionRequest(
		"device-1", "workload-1", admissionTestSpec(),
		"/sys/fs/cgroup/x", 9, bootstrap, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := admissionTestRemoteDecision(t, verifiedAt, "ALLOW", "device-1", bootstrap, verifierPriv)
	_, err = IssueWorkloadAdmissionGrant(req, decision, WorkloadAdmissionPolicy{
		RemoteVerifierPublicKey: verifierPub,
		AdmissionIssuerKey:      issuerPriv,
		AdmissionIssuerID:       "issuer",
		MaxAttestationAge:       2 * time.Minute,
		Now:                     func() time.Time { return now },
	})
	if !errors.Is(err, ErrAdmissionRemoteDecisionStale) {
		t.Fatalf("expected stale attestation rejection, got %v", err)
	}
}

func TestIssueAdmissionGrantRejectsBootstrapMismatch(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	verifierPub, verifierPriv := admissionTestKeys(t)
	_, issuerPriv := admissionTestKeys(t)
	reqBootstrap := "sha256:" + strings.Repeat("a", 64)
	decisionBootstrap := "sha256:" + strings.Repeat("c", 64)
	req, err := NewWorkloadAdmissionRequest(
		"device-1", "workload-1", admissionTestSpec(),
		"/sys/fs/cgroup/x", 9, reqBootstrap, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := admissionTestRemoteDecision(t, now, "ALLOW", "device-1", decisionBootstrap, verifierPriv)
	_, err = IssueWorkloadAdmissionGrant(req, decision, WorkloadAdmissionPolicy{
		RemoteVerifierPublicKey: verifierPub,
		AdmissionIssuerKey:      issuerPriv,
		AdmissionIssuerID:       "issuer",
		Now:                     func() time.Time { return now },
	})
	if !errors.Is(err, ErrAdmissionBindingMismatch) {
		t.Fatalf("expected bootstrap binding rejection, got %v", err)
	}
}

func TestAdmissionGrantSignatureCoversTargetCgroupIdentity(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	grant, _, issuerPub, _ := admissionTestGrant(t, now)
	grant.Grant.TargetCgroupID++
	if err := VerifySignedWorkloadAdmissionGrant(grant, issuerPub, now); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered cgroup identity was not rejected: %v", err)
	}
}

func TestAdmissionGrantConsumptionAllowsExactlyOneWinner(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	grant, spec, issuerPub, _ := admissionTestGrant(t, now)
	dir := t.TempDir()

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ConsumeWorkloadAdmissionGrant(
				dir,
				grant,
				issuerPub,
				spec,
				grant.Grant.TargetCgroup,
				grant.Grant.TargetCgroupID,
				grant.Grant.DeviceID,
				now.Add(time.Second),
			)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAdmissionGrantReplay):
			replays++
		default:
			t.Fatalf("unexpected consumption result: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("expected one winner/one replay, got success=%d replay=%d", successes, replays)
	}
}

func TestAdmissionGrantConsumptionRejectsSpecMismatchBeforeClaim(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	grant, spec, issuerPub, _ := admissionTestGrant(t, now)
	spec.Args = []string{"different"}
	_, err := ConsumeWorkloadAdmissionGrant(
		t.TempDir(),
		grant,
		issuerPub,
		spec,
		grant.Grant.TargetCgroup,
		grant.Grant.TargetCgroupID,
		grant.Grant.DeviceID,
		now.Add(time.Second),
	)
	if !errors.Is(err, ErrAdmissionBindingMismatch) {
		t.Fatalf("expected spec binding mismatch, got %v", err)
	}
}

func TestActivationReceiptSignatureRoundTrip(t *testing.T) {
	pub, priv := admissionTestKeys(t)
	receipt := WorkloadActivationReceipt{
		Version:            WorkloadActivationReceiptVersion,
		ActivationID:       "activation-1",
		GrantID:            "grant-1",
		GrantDigest:        "sha256:" + strings.Repeat("a", 64),
		DeviceID:           "device-1",
		WorkloadID:         "workload-1",
		WorkloadSpecDigest: "sha256:" + strings.Repeat("b", 64),
		TargetCgroup:       "/sys/fs/cgroup/workload",
		TargetCgroupID:     42,
		ProcessID:          1234,
		StartedAt:          time.Date(2026, 9, 28, 0, 0, 1, 0, time.UTC),
	}
	signed, err := SignWorkloadActivationReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedWorkloadActivationReceipt(signed, pub); err != nil {
		t.Fatalf("valid activation receipt rejected: %v", err)
	}
	signed.Receipt.ProcessID++
	if err := VerifySignedWorkloadActivationReceipt(signed, pub); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered activation receipt was not rejected: %v", err)
	}
}
