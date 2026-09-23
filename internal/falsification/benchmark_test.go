package falsification

import (
	"testing"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestCorpusV1FixedSizeAndCategories(t *testing.T) {
	corpus := CorpusV1()
	if len(corpus) != 40 {
		t.Fatalf("expected 40 scenarios, got %d", len(corpus))
	}

	counts := map[string]int{}
	for _, scenario := range corpus {
		counts[scenario.Category]++
	}

	want := map[string]int{
		"safe_control":                    8,
		"static_policy":                   4,
		"critical_temporal_staleness":     4,
		"event_invalidation":              4,
		"dependency_propagation":          4,
		"independent_contradiction":       4,
		"active_evidence_safe_resolution": 3,
		"active_evidence_refutation":      3,
		"toctou":                          4,
		"postflight_divergence":           2,
	}
	for category, expected := range want {
		if counts[category] != expected {
			t.Fatalf("category %s: expected %d cases, got %d", category, expected, counts[category])
		}
	}
}

func TestMoatFalsificationBenchmarkV1(t *testing.T) {
	comparison := EvaluateCorpus(CorpusV1())

	// The baseline is intentionally non-trivial: it must catch ordinary static
	// policy denials. If this changes, the comparison is no longer the agreed
	// live-lookup + TTL + policy baseline.
	if comparison.Baseline.Blocks < 4 {
		t.Fatalf("baseline became too weak: %+v", comparison.Baseline)
	}

	if comparison.Baseline.UnsafeAllows != 19 {
		t.Fatalf(
			"benchmark fixture drift: expected baseline unsafe allows=19, got %+v",
			comparison.Baseline,
		)
	}
	if comparison.Baseline.UnknownAllows != 4 {
		t.Fatalf(
			"benchmark fixture drift: expected baseline unknown allows=4, got %+v",
			comparison.Baseline,
		)
	}

	// Primary falsification target: if StateLatch still allows a scenario labeled
	// unsafe or unresolved, the current M0-M5 safety thesis fails this corpus.
	if comparison.StateLatch.UnsafeAllows != 0 {
		t.Fatalf("StateLatch unsafe allow(s) detected: %+v", comparison.StateLatch)
	}
	if comparison.StateLatch.UnknownAllows != 0 {
		t.Fatalf("StateLatch unresolved/unknown allow(s) detected: %+v", comparison.StateLatch)
	}

	// Complexity is not useful if it simply blocks known-safe controls.
	if comparison.StateLatch.SafeBlocks != 0 {
		t.Fatalf("StateLatch false block(s) on safe corpus: %+v", comparison.StateLatch)
	}
	if comparison.StateLatch.SafeEscalations != 0 {
		t.Fatalf("StateLatch unnecessary escalation(s) on safe corpus: %+v", comparison.StateLatch)
	}

	if comparison.StateLatch.OutcomeDivergencesDetected != 2 {
		t.Fatalf(
			"expected both postflight divergences to be detected, got %+v",
			comparison.StateLatch,
		)
	}
	if comparison.Baseline.OutcomeDivergencesDetected != 0 {
		t.Fatalf(
			"request-time baseline unexpectedly gained postflight detection: %+v",
			comparison.Baseline,
		)
	}

	if comparison.StateLatch.ProbeAttempts != 6 {
		t.Fatalf(
			"expected six bounded active probe attempts, got %+v",
			comparison.StateLatch,
		)
	}
}

func TestEveryUnsafeOrUnknownBaselineAllowHasStateLatchCountermeasure(t *testing.T) {
	comparison := EvaluateCorpus(CorpusV1())

	for _, result := range comparison.Cases {
		if result.GroundTruth == GroundSafe || result.Baseline.Decision != decision.Allow {
			continue
		}
		if result.StateLatch.Decision == decision.Allow {
			t.Errorf(
				"%s (%s): baseline and StateLatch both ALLOW ground truth %s",
				result.Name,
				result.Category,
				result.GroundTruth,
			)
		}
	}
}

func TestSafeControlsRemainUsable(t *testing.T) {
	comparison := EvaluateCorpus(CorpusV1())

	for _, result := range comparison.Cases {
		if result.GroundTruth != GroundSafe {
			continue
		}
		if result.StateLatch.Decision != decision.Allow {
			t.Errorf(
				"%s (%s): expected safe case ALLOW, got %s reasons=%v",
				result.Name,
				result.Category,
				result.StateLatch.Decision,
				result.StateLatch.Reasons,
			)
		}
	}
}
