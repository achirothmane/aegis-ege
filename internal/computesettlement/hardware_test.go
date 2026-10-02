package computesettlement

import (
	"context"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestVCS03StaleReceiptCannotSettleAfterFreshHardwareSubstitution(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 2, 20, 45, 0, 0, time.UTC)

	lease, receipt, admission, originalCompletion := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-a",
		"sha256:topology-a",
	)
	_ = originalCompletion

	freshCompletion := vcs03SignAttestation(
		t,
		authority,
		2,
		lease.Subject,
		"sha256:hardware-set-b",
		"sha256:topology-a",
		receipt.FinishedAt.Add(time.Second),
	)

	evidenceAt := freshCompletion.Attestation.ObservedAt
	result := ReconcileAttestedExecution(
		context.Background(),
		authority,
		lease,
		receipt,
		admission,
		freshCompletion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs03-stale-receipt",
		lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(evidenceAt, "true", "true"),
		vcs02Sources(evidenceAt, false),
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("stale receipt must not settle against a fresh substituted hardware attestation: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.HardwareContinuityEstablished {
		t.Fatal("hardware continuity must not be established for stale receipt substitution")
	}
}

func TestVCS03ReceiptUpdatedToSubstitutedHardwareStillCannotReuseOldLease(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 2, 20, 45, 0, 0, time.UTC)

	lease, receipt, admission, completion := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-b",
		"sha256:topology-a",
	)
	completionDigest, err := HardwareIdentityAttestationDigest(completion)
	if err != nil {
		t.Fatal(err)
	}
	receipt.CompletionAttestationDigest = completionDigest

	evidenceAt := completion.Attestation.ObservedAt
	result := ReconcileAttestedExecution(
		context.Background(),
		authority,
		lease,
		receipt,
		admission,
		completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs03-rebound-receipt",
		lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(evidenceAt, "true", "true"),
		vcs02Sources(evidenceAt, false),
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("substituted hardware must not inherit an old lease: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.HardwareContinuityEstablished {
		t.Fatal("old lease must not establish continuity for substituted hardware")
	}
}

func TestVCS03TopologySubstitutionCannotSilentlySettle(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 2, 20, 45, 0, 0, time.UTC)

	lease, receipt, admission, completion := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-a",
		"sha256:topology-b",
	)
	completionDigest, err := HardwareIdentityAttestationDigest(completion)
	if err != nil {
		t.Fatal(err)
	}
	receipt.CompletionAttestationDigest = completionDigest

	evidenceAt := completion.Attestation.ObservedAt
	result := ReconcileAttestedExecution(
		context.Background(),
		authority,
		lease,
		receipt,
		admission,
		completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs03-topology",
		lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(evidenceAt, "true", "true"),
		vcs02Sources(evidenceAt, false),
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("topology substitution must not silently settle: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS03StableAttestedHardwareCanReachSettlement(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 2, 20, 45, 0, 0, time.UTC)

	lease, receipt, admission, completion := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-a",
		"sha256:topology-a",
	)

	evidenceAt := completion.Attestation.ObservedAt
	result := ReconcileAttestedExecution(
		context.Background(),
		authority,
		lease,
		receipt,
		admission,
		completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs03-positive",
		lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(evidenceAt, "true", "true"),
		vcs02Sources(evidenceAt, false),
		vcs02Requirement(),
	)

	if result.Disposition != Settled {
		t.Fatalf("stable attested hardware with independent matching evidence should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.HardwareContinuityEstablished {
		t.Fatal("expected hardware continuity to be established")
	}
}

func TestVCS03CompletionObservationTooFarFromExecutionRemainsUnknown(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 2, 20, 45, 0, 0, time.UTC)

	lease, receipt, admission, _ := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-a",
		"sha256:topology-a",
	)
	lateCompletion := vcs03SignAttestation(
		t,
		authority,
		2,
		lease.Subject,
		lease.HardwareSetDigest,
		lease.TopologyDigest,
		receipt.FinishedAt.Add(2*time.Minute),
	)
	lateDigest, err := HardwareIdentityAttestationDigest(lateCompletion)
	if err != nil {
		t.Fatal(err)
	}
	receipt.CompletionAttestationDigest = lateDigest

	evidenceAt := lateCompletion.Attestation.ObservedAt
	result := ReconcileAttestedExecution(
		context.Background(),
		authority,
		lease,
		receipt,
		admission,
		lateCompletion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs03-late-probe",
		lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(evidenceAt, "true", "true"),
		vcs02Sources(evidenceAt, false),
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("late hardware observation must not prove execution-time continuity: got %s", result.Disposition)
	}
}

func vcs03Fixture(
	t *testing.T,
	authority egeproto.PermitAuthority,
	start time.Time,
	completionHardware string,
	completionTopology string,
) (
	HardwareLeaseBinding,
	ComputeExecutionReceipt,
	SignedHardwareIdentityAttestation,
	SignedHardwareIdentityAttestation,
) {
	t.Helper()

	subject := "compute.execution/lease-64h100"
	admission := vcs03SignAttestation(
		t,
		authority,
		1,
		subject,
		"sha256:hardware-set-a",
		"sha256:topology-a",
		start.Add(-10*time.Second),
	)
	admissionDigest, err := HardwareIdentityAttestationDigest(admission)
	if err != nil {
		t.Fatal(err)
	}

	lease := HardwareLeaseBinding{
		LeaseID:                    "lease:vcs03",
		Subject:                    subject,
		ContractDigest:             "sha256:compute-contract-v0",
		HardwareSetDigest:          "sha256:hardware-set-a",
		TopologyDigest:             "sha256:topology-a",
		AdmissionAttestationDigest: admissionDigest,
		StartsAt:                   start,
		EndsAt:                     start.Add(time.Hour),
	}
	receipt := ComputeExecutionReceipt{
		ReceiptID:                  "receipt:vcs03",
		LeaseID:                    lease.LeaseID,
		ContractDigest:             lease.ContractDigest,
		HardwareSetDigest:          lease.HardwareSetDigest,
		TopologyDigest:             lease.TopologyDigest,
		AdmissionAttestationDigest: admissionDigest,
		StartedAt:                  start.Add(time.Second),
		FinishedAt:                 start.Add(30 * time.Second),
	}

	completion := vcs03SignAttestation(
		t,
		authority,
		2,
		subject,
		completionHardware,
		completionTopology,
		receipt.FinishedAt.Add(time.Second),
	)
	completionDigest, err := HardwareIdentityAttestationDigest(completion)
	if err != nil {
		t.Fatal(err)
	}
	receipt.CompletionAttestationDigest = completionDigest

	return lease, receipt, admission, completion
}

func vcs03SignAttestation(
	t *testing.T,
	authority egeproto.PermitAuthority,
	sequence uint64,
	subject string,
	hardware string,
	topology string,
	observedAt time.Time,
) SignedHardwareIdentityAttestation {
	t.Helper()
	signed, err := SignHardwareIdentityAttestation(
		context.Background(),
		authority,
		HardwareIdentityAttestation{
			Version:           HardwareIdentityAttestationVersion,
			AttestationID:     "attestation:vcs03:" + observedAt.Format(time.RFC3339Nano),
			Sequence:          sequence,
			Subject:           subject,
			HardwareSetDigest: hardware,
			TopologyDigest:    topology,
			EvidenceDigest:    "sha256:evidence:" + observedAt.Format("150405.000000000"),
			VerifierID:        "verifier:vcs03",
			ObservedAt:        observedAt,
			ValidUntil:        observedAt.Add(5 * time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func vcs03HardwarePolicy() HardwareContinuityPolicy {
	return HardwareContinuityPolicy{
		MaxAdmissionAge:       30 * time.Second,
		MaxCompletionProbeLag: 30 * time.Second,
	}
}
