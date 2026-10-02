package computesettlement

import (
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/outcome"
)

func TestVCS01ContradictoryComputeEvidenceIsDisputed(t *testing.T) {
	now := time.Date(2026, time.October, 2, 19, 30, 0, 0, time.UTC)
	contract := map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}

	result := Reconcile(
		"compute-execution/vcs01",
		"sha256:compute-contract-v0",
		contract,
		[]Observation{
			{
				Source:         "provider-control-plane",
				EvidenceDigest: "sha256:provider-observation",
				Facts: map[string]string{
					"capacity.available": "true",
					"hardware.identity":  "valid",
					"metering.running":   "true",
				},
				Contributors: []outcome.Contributor{{
					Kind: outcome.ContributorSource,
					ID:   "provider-control-plane",
				}},
				ObservedAt: now,
			},
			{
				Source:         "tenant-independent-observer",
				EvidenceDigest: "sha256:tenant-observation",
				Facts: map[string]string{
					"capacity.available": "false",
					"hardware.identity":  "valid",
					"metering.running":   "true",
				},
				Contributors: []outcome.Contributor{{
					Kind: outcome.ContributorSource,
					ID:   "tenant-independent-observer",
				}},
				ObservedAt: now,
			},
		},
	)

	if result.Disposition != Disputed {
		t.Fatalf("VCS-01 must not settle contradictory execution evidence: got %s (%s)", result.Disposition, result.Detail)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected two source-bound outcome records, got %d", len(result.Records))
	}
	if result.Records[0].Verdict != outcome.Match {
		t.Fatalf("provider observation should match contract fixture, got %s", result.Records[0].Verdict)
	}
	if result.Records[1].Verdict != outcome.Diverged {
		t.Fatalf("tenant observation should diverge from contract fixture, got %s", result.Records[1].Verdict)
	}
}

func TestVCS01AgreementOnDeliveryCanSettle(t *testing.T) {
	now := time.Date(2026, time.October, 2, 19, 30, 0, 0, time.UTC)
	contract := map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}
	delivered := map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}

	result := Reconcile(
		"compute-execution/vcs01-positive",
		"sha256:compute-contract-v0",
		contract,
		[]Observation{
			{
				Source:         "provider-control-plane",
				EvidenceDigest: "sha256:provider-positive",
				Facts:          delivered,
				ObservedAt:     now,
			},
			{
				Source:         "tenant-independent-observer",
				EvidenceDigest: "sha256:tenant-positive",
				Facts:          delivered,
				ObservedAt:     now,
			},
		},
	)

	if result.Disposition != Settled {
		t.Fatalf("convergent matching observations should settle: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS01AgreementOnSameBreachCanProduceCreditDue(t *testing.T) {
	now := time.Date(2026, time.October, 2, 19, 30, 0, 0, time.UTC)
	contract := map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}
	degraded := map[string]string{
		"capacity.available": "false",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}

	result := Reconcile(
		"compute-execution/vcs01-credit",
		"sha256:compute-contract-v0",
		contract,
		[]Observation{
			{
				Source:         "provider-control-plane",
				EvidenceDigest: "sha256:provider-credit",
				Facts:          degraded,
				ObservedAt:     now,
			},
			{
				Source:         "tenant-independent-observer",
				EvidenceDigest: "sha256:tenant-credit",
				Facts:          degraded,
				ObservedAt:     now,
			},
		},
	)

	if result.Disposition != CreditDue {
		t.Fatalf("convergent evidence of the same breach should produce CREDIT_DUE: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS01MissingContractFactRemainsUnknown(t *testing.T) {
	now := time.Date(2026, time.October, 2, 19, 30, 0, 0, time.UTC)
	contract := map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}

	result := Reconcile(
		"compute-execution/vcs01-unknown",
		"sha256:compute-contract-v0",
		contract,
		[]Observation{
			{
				Source:         "provider-control-plane",
				EvidenceDigest: "sha256:provider-unknown",
				Facts: map[string]string{
					"capacity.available": "true",
					"hardware.identity":  "valid",
					"metering.running":   "true",
				},
				ObservedAt: now,
			},
			{
				Source:         "tenant-independent-observer",
				EvidenceDigest: "sha256:tenant-unknown",
				Facts: map[string]string{
					"hardware.identity": "valid",
					"metering.running":  "true",
				},
				ObservedAt: now,
			},
		},
	)

	if result.Disposition != Unknown {
		t.Fatalf("missing delivery evidence must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}
