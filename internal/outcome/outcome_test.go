package outcome

import (
	"testing"
	"time"
)

func TestCompareDetectsMatchDivergenceAndUnknown(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 10, 0, 0, time.UTC)
	expected := map[string]string{
		"node_unschedulable": "true",
		"pod/p1_absent":      "true",
	}

	match := Compare(
		"a1", "e1", "p1",
		expected,
		map[string]string{"node_unschedulable": "true", "pod/p1_absent": "true"},
		nil,
		now,
	)
	if match.Verdict != Match {
		t.Fatalf("expected MATCH, got %+v", match)
	}

	diverged := Compare(
		"a1", "e1", "p1",
		expected,
		map[string]string{"node_unschedulable": "false", "pod/p1_absent": "true"},
		nil,
		now,
	)
	if diverged.Verdict != Diverged {
		t.Fatalf("expected DIVERGED, got %+v", diverged)
	}

	unknown := Compare(
		"a1", "e1", "p1",
		expected,
		map[string]string{"node_unschedulable": "true"},
		nil,
		now,
	)
	if unknown.Verdict != Unknown {
		t.Fatalf("expected UNKNOWN, got %+v", unknown)
	}
}

func TestReliabilityLedgerDegradesAfterRepeatedDivergence(t *testing.T) {
	policy := AdvisoryPolicy{
		MinResolvedSamples: 5,
		MaxDivergenceRate:  0.20,
	}
	ledger := NewLedger(policy)
	source := Contributor{Kind: ContributorSource, ID: "prometheus-http"}
	assumption := Contributor{Kind: ContributorAssumption, ID: "A-DRAIN-SAFE"}

	for i := 0; i < 4; i++ {
		ledger.Record(Record{
			ActionID:     "match",
			Verdict:      Match,
			Attribution:  AttributionContributors,
			Contributors: []Contributor{source, assumption},
		})
	}
	ledger.Record(Record{
		ActionID:     "divergence-1",
		Verdict:      Diverged,
		Attribution:  AttributionContributors,
		Contributors: []Contributor{source, assumption},
	})
	ledger.Record(Record{
		ActionID:     "divergence-2",
		Verdict:      Diverged,
		Attribution:  AttributionContributors,
		Contributors: []Contributor{source, assumption},
	})

	got := ledger.Snapshot(source)
	if got.Status != AdvisoryDegraded {
		t.Fatalf("expected degraded advisory after repeated divergence, got %+v", got)
	}
	if got.ResolvedSamples != 6 || got.Divergences != 2 {
		t.Fatalf("unexpected calibration counts: %+v", got)
	}
	if got.DivergenceRate <= policy.MaxDivergenceRate {
		t.Fatalf("expected divergence rate above threshold, got %+v", got)
	}

	assumptionSnapshot := ledger.Snapshot(assumption)
	if assumptionSnapshot.Status != AdvisoryDegraded {
		t.Fatalf("expected assumption contributor to receive same advisory signal, got %+v", assumptionSnapshot)
	}
}

func TestReliabilityLedgerRequiresMinimumHistory(t *testing.T) {
	ledger := NewLedger(AdvisoryPolicy{
		MinResolvedSamples: 5,
		MaxDivergenceRate:  0.20,
	})
	source := Contributor{Kind: ContributorSource, ID: "kubernetes-api"}

	for i := 0; i < 2; i++ {
		ledger.Record(Record{
			Verdict:      Diverged,
			Contributors: []Contributor{source},
		})
	}

	got := ledger.Snapshot(source)
	if got.Status != AdvisoryInsufficientHistory {
		t.Fatalf("small samples must remain insufficient history, got %+v", got)
	}
}

func TestUnknownOutcomesDoNotImproveReliability(t *testing.T) {
	ledger := NewLedger(AdvisoryPolicy{
		MinResolvedSamples: 2,
		MaxDivergenceRate:  0.25,
	})
	source := Contributor{Kind: ContributorSource, ID: "prometheus-http"}

	ledger.Record(Record{Verdict: Match, Attribution: AttributionContributors, Contributors: []Contributor{source}})
	ledger.Record(Record{Verdict: Diverged, Attribution: AttributionContributors, Contributors: []Contributor{source}})
	for i := 0; i < 20; i++ {
		ledger.Record(Record{Verdict: Unknown, Attribution: AttributionContributors, Contributors: []Contributor{source}})
	}

	got := ledger.Snapshot(source)
	if got.ResolvedSamples != 2 || got.Unknowns != 20 {
		t.Fatalf("unexpected counts: %+v", got)
	}
	if got.Reliability != 0.5 {
		t.Fatalf("unknown outcomes must not inflate reliability, got %+v", got)
	}
	if got.Status != AdvisoryDegraded {
		t.Fatalf("expected degraded based on resolved outcomes only, got %+v", got)
	}
}

func TestDuplicateContributorInRecordCountsOnce(t *testing.T) {
	ledger := NewLedger(AdvisoryPolicy{MinResolvedSamples: 1, MaxDivergenceRate: 1})
	source := Contributor{Kind: ContributorSource, ID: "kubernetes-api"}

	ledger.Record(Record{
		Verdict:      Match,
		Contributors: []Contributor{source, source},
	})

	got := ledger.Snapshot(source)
	if got.Matches != 1 {
		t.Fatalf("duplicate contributor should count once per outcome, got %+v", got)
	}
}

func TestUnattributedDivergenceDoesNotDegradeContributor(t *testing.T) {
	ledger := NewLedger(AdvisoryPolicy{
		MinResolvedSamples: 1,
		MaxDivergenceRate:  0,
	})
	source := Contributor{Kind: ContributorSource, ID: "kubernetes-api"}

	ledger.Record(Record{
		Verdict:      Diverged,
		Attribution:  AttributionUnattributed,
		Contributors: []Contributor{source},
	})

	got := ledger.Snapshot(source)
	if got.Status != AdvisoryInsufficientHistory {
		t.Fatalf("unattributed divergence must not calibrate reliability, got %+v", got)
	}
	if got.ResolvedSamples != 0 || got.Unattributed != 1 {
		t.Fatalf("expected one unattributed outcome and zero resolved calibration samples, got %+v", got)
	}
}
