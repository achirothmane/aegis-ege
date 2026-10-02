package computesettlement

import (
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestVCS02SharedProviderUpstreamCannotManufactureIndependentSettlement(t *testing.T) {
	now := time.Date(2026, time.October, 2, 20, 30, 0, 0, time.UTC)
	contract := vcs02Contract()
	observations := vcs02Observations(now, "true", "true")
	sources := vcs02Sources(now, true)

	result := ReconcileWithEvidence(
		"compute-execution/vcs02-dependent",
		"sha256:compute-contract-v0",
		contract,
		observations,
		sources,
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("shared material upstream must not produce conclusive settlement: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceDependent {
		t.Fatalf("overall independence=%s want DEPENDENT", result.EvidenceComposition.OverallIndependence)
	}
	if result.EvidenceComposition.IndependentSourceCount != 1 {
		t.Fatalf("independent source count=%d want 1", result.EvidenceComposition.IndependentSourceCount)
	}
	if len(result.EvidenceComposition.PairAssessments) != 1 ||
		result.EvidenceComposition.PairAssessments[0].Status != egeproto.EvidenceIndependenceDependent {
		t.Fatalf("unexpected pair assessment: %+v", result.EvidenceComposition.PairAssessments)
	}
}

func TestVCS02DistinctFailureDomainsCanSettleMatchingDelivery(t *testing.T) {
	now := time.Date(2026, time.October, 2, 20, 30, 0, 0, time.UTC)
	result := ReconcileWithEvidence(
		"compute-execution/vcs02-independent",
		"sha256:compute-contract-v0",
		vcs02Contract(),
		vcs02Observations(now, "true", "true"),
		vcs02Sources(now, false),
		vcs02Requirement(),
	)

	if result.Disposition != Settled {
		t.Fatalf("independent matching evidence should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceAsserted ||
		result.EvidenceComposition.IndependentSourceCount != 2 {
		t.Fatalf("unexpected independence assessment: %+v", result.EvidenceComposition)
	}
}

func TestVCS02IndependentContradictionRemainsDisputed(t *testing.T) {
	now := time.Date(2026, time.October, 2, 20, 30, 0, 0, time.UTC)
	result := ReconcileWithEvidence(
		"compute-execution/vcs02-disputed",
		"sha256:compute-contract-v0",
		vcs02Contract(),
		vcs02Observations(now, "true", "false"),
		vcs02Sources(now, false),
		vcs02Requirement(),
	)

	if result.Disposition != Disputed {
		t.Fatalf("independent contradictory evidence must remain DISPUTED: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS02MissingDeclarationCannotBecomeIndependentByLabel(t *testing.T) {
	now := time.Date(2026, time.October, 2, 20, 30, 0, 0, time.UTC)
	sources := vcs02Sources(now, false)
	sources[1].Declaration = nil

	result := ReconcileWithEvidence(
		"compute-execution/vcs02-unknown",
		"sha256:compute-contract-v0",
		vcs02Contract(),
		vcs02Observations(now, "true", "true"),
		sources,
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("missing independence declaration must remain UNKNOWN, got %s", result.Disposition)
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceUnknown {
		t.Fatalf("overall independence=%s want UNKNOWN", result.EvidenceComposition.OverallIndependence)
	}
}

func TestVCS02ObservationDigestMustMatchAssessedEvidence(t *testing.T) {
	now := time.Date(2026, time.October, 2, 20, 30, 0, 0, time.UTC)
	observations := vcs02Observations(now, "true", "true")
	observations[1].EvidenceDigest = "sha256:unassessed-replacement"

	result := ReconcileWithEvidence(
		"compute-execution/vcs02-substitution",
		"sha256:compute-contract-v0",
		vcs02Contract(),
		observations,
		vcs02Sources(now, false),
		vcs02Requirement(),
	)

	if result.Disposition != Unknown {
		t.Fatalf("unbound evidence substitution must remain UNKNOWN, got %s", result.Disposition)
	}
}

func vcs02Requirement() EvidenceRequirement {
	return EvidenceRequirement{
		Subject: "compute.execution/lease-64h100",
		Independence: egeproto.EvidenceIndependenceRequirement{
			RequiredIndependence:    egeproto.EvidenceIndependenceAsserted,
			MinIndependentSources:   2,
			RequiredDependencyKinds: []string{"administrative", "credential", "upstream"},
		},
	}
}

func vcs02Contract() map[string]string {
	return map[string]string{
		"capacity.available": "true",
		"hardware.identity":  "valid",
		"metering.running":   "true",
	}
}

func vcs02Observations(now time.Time, providerAvailable, tenantAvailable string) []Observation {
	return []Observation{
		{
			Source:         "provider-control-plane",
			EvidenceDigest: "sha256:provider-vcs02",
			Facts: map[string]string{
				"capacity.available": providerAvailable,
				"hardware.identity":  "valid",
				"metering.running":   "true",
			},
			ObservedAt: now,
		},
		{
			Source:         "tenant-observer",
			EvidenceDigest: "sha256:tenant-vcs02",
			Facts: map[string]string{
				"capacity.available": tenantAvailable,
				"hardware.identity":  "valid",
				"metering.running":   "true",
			},
			ObservedAt: now,
		},
	}
}

func vcs02Sources(now time.Time, sharedProviderUpstream bool) []egeproto.EvidenceSource {
	tenantUpstream := "upstream:tenant-telemetry-store"
	if sharedProviderUpstream {
		tenantUpstream = "upstream:provider-metering-api"
	}
	return []egeproto.EvidenceSource{
		{
			Name:        "provider-control-plane",
			TrustDomain: "provider",
			Digest:      "sha256:provider-vcs02",
			ObservedAt:  now,
			Classes:     []string{"compute.delivery", "compute.metering"},
			Declaration: &egeproto.EvidenceSourceDeclaration{
				ProducerID:         "producer:provider-control-plane",
				Subject:            "compute.execution/lease-64h100",
				ObservationPath:    "path:provider-metering-api",
				DependencyCoverage: []string{"administrative", "credential", "facility", "upstream"},
				Dependencies: []egeproto.EvidenceDependency{
					{Kind: "administrative", ID: "admin:provider", Material: true},
					{Kind: "credential", ID: "credential:provider-metering", Material: true},
					{Kind: "facility", ID: "facility:gpu-cluster-a", Material: false},
					{Kind: "upstream", ID: "upstream:provider-metering-api", Material: true},
				},
				Assurance: egeproto.EvidenceDeclarationAsserted,
			},
		},
		{
			Name:        "tenant-observer",
			TrustDomain: "tenant",
			Digest:      "sha256:tenant-vcs02",
			ObservedAt:  now,
			Classes:     []string{"compute.delivery", "tenant.telemetry"},
			Declaration: &egeproto.EvidenceSourceDeclaration{
				ProducerID:         "producer:tenant-observer",
				Subject:            "compute.execution/lease-64h100",
				ObservationPath:    "path:tenant-sidecar-telemetry",
				DependencyCoverage: []string{"administrative", "credential", "facility", "upstream"},
				Dependencies: []egeproto.EvidenceDependency{
					{Kind: "administrative", ID: "admin:tenant", Material: true},
					{Kind: "credential", ID: "credential:tenant-observer", Material: true},
					{Kind: "facility", ID: "facility:gpu-cluster-a", Material: false},
					{Kind: "upstream", ID: tenantUpstream, Material: true},
				},
				Assurance: egeproto.EvidenceDeclarationAsserted,
			},
		},
	}
}
