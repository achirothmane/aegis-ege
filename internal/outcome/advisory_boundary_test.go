package outcome_test

import (
	"testing"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/outcome"
)

func TestDegradedReliabilityAdvisoryDoesNotMutateDecisionPolicy(t *testing.T) {
	source := outcome.Contributor{
		Kind: outcome.ContributorSource,
		ID:   "prometheus-http",
	}
	ledger := outcome.NewLedger(outcome.AdvisoryPolicy{
		MinResolvedSamples: 2,
		MaxDivergenceRate:  0.25,
	})
	ledger.Record(outcome.Record{
		Verdict:      outcome.Diverged,
		Attribution:  outcome.AttributionContributors,
		Contributors: []outcome.Contributor{source},
	})
	ledger.Record(outcome.Record{
		Verdict:      outcome.Diverged,
		Attribution:  outcome.AttributionContributors,
		Contributors: []outcome.Contributor{source},
	})

	snapshot := ledger.Snapshot(source)
	if snapshot.Status != outcome.AdvisoryDegraded {
		t.Fatalf("expected degraded advisory, got %+v", snapshot)
	}

	now := time.Date(2026, 9, 23, 18, 20, 0, 0, time.UTC)
	result := decision.Evaluate(decision.Request{
		ActionID:         "act-boundary",
		Action:           "drain",
		Target:           "node/node-7",
		ResourceVersion:  "200",
		RequestedAt:      now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge:   30 * time.Second,
		Evidence: []decision.EvidenceObservation{{
			Claim:      "node_health",
			Source:     "prometheus-http",
			Value:      "healthy",
			ObservedAt: now,
		}},
	})

	if result.Decision != decision.Allow {
		t.Fatalf(
			"advisory calibration must not silently mutate production decision policy; got %s reasons=%v",
			result.Decision,
			result.ReasonCodes,
		)
	}
}
