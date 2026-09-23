package assurance

import (
	"testing"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/epistemic"
)

func TestTemporalGateBlocksCriticalActionBaselineWouldAllow(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	now := evaluatedAt.Add(20 * time.Second)

	req := decision.Request{
		ActionID:         "act-critical",
		Action:           "drain",
		Target:           "node/node-7",
		ResourceVersion:  "101",
		RequestedAt:      now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge:   60 * time.Second,
		Evidence: []decision.EvidenceObservation{{
			Claim:      "node_health",
			Source:     "kubernetes-api",
			Value:      "healthy",
			ObservedAt: evaluatedAt,
		}},
	}

	baseline := decision.Evaluate(req)
	if baseline.Decision != decision.Allow {
		t.Fatalf("fixed evidence-age baseline should ALLOW, got %s reasons=%v", baseline.Decision, baseline.ReasonCodes)
	}

	assumption := epistemic.Assumption{
		ID:          "A-DRAIN-SAFE",
		Status:      epistemic.AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
	policy := epistemic.TemporalPolicy{
		LowMaxAge:      60 * time.Second,
		MediumMaxAge:   30 * time.Second,
		HighMaxAge:     10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}

	got := EvaluateWithTemporalAssumption(
		req,
		assumption,
		now,
		epistemic.SensitivityCritical,
		policy,
	)

	if got.Decision.Decision != decision.Block {
		t.Fatalf("critical temporal gate should BLOCK, got %s reasons=%v", got.Decision.Decision, got.Decision.ReasonCodes)
	}
	if len(got.Decision.ReasonCodes) != 1 || got.Decision.ReasonCodes[0] != decision.AssumptionExpired {
		t.Fatalf("expected %s, got %v", decision.AssumptionExpired, got.Decision.ReasonCodes)
	}
}

func TestTemporalGateAllowsLowSensitivitySameEvidence(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	now := evaluatedAt.Add(20 * time.Second)

	req := validRequest(now, evaluatedAt)
	assumption := epistemic.Assumption{
		ID:          "A-LOW-RISK",
		Status:      epistemic.AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
	policy := epistemic.TemporalPolicy{
		LowMaxAge:      60 * time.Second,
		MediumMaxAge:   30 * time.Second,
		HighMaxAge:     10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}

	got := EvaluateWithTemporalAssumption(
		req,
		assumption,
		now,
		epistemic.SensitivityLow,
		policy,
	)
	if got.Decision.Decision != decision.Allow {
		t.Fatalf("low-sensitivity gate should ALLOW same 20s-old assumption, got %s reasons=%v", got.Decision.Decision, got.Decision.ReasonCodes)
	}
}

func TestTemporalGateBlocksEventInvalidatedAssumptionRegardlessOfAge(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	invalidatedAt := evaluatedAt.Add(time.Millisecond)

	req := validRequest(evaluatedAt.Add(2*time.Millisecond), evaluatedAt)
	assumption := epistemic.Assumption{
		ID:          "A-DRAIN-SAFE",
		Status:      epistemic.AssumptionInvalidated,
		EvaluatedAt: evaluatedAt,
		InvalidatedAt: &invalidatedAt,
		Invalidation: &epistemic.Invalidation{
			Cause: epistemic.CauseUpstreamAssumptionInvalidated,
		},
	}
	policy := epistemic.TemporalPolicy{
		CriticalMaxAge: 5 * time.Second,
	}

	got := EvaluateWithTemporalAssumption(
		req,
		assumption,
		evaluatedAt.Add(2*time.Millisecond),
		epistemic.SensitivityCritical,
		policy,
	)
	if got.Decision.Decision != decision.Block {
		t.Fatalf("event-invalidated assumption must BLOCK, got %s reasons=%v", got.Decision.Decision, got.Decision.ReasonCodes)
	}
	if got.Decision.ReasonCodes[0] != decision.AssumptionInvalidated {
		t.Fatalf("expected %s, got %v", decision.AssumptionInvalidated, got.Decision.ReasonCodes)
	}
}

func TestTemporalGateEscalatesWhenValidityCannotBeEstablished(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	req := validRequest(now, now)
	assumption := epistemic.Assumption{
		ID:     "A-UNKNOWN",
		Status: epistemic.AssumptionSupported,
	}

	got := EvaluateWithTemporalAssumption(
		req,
		assumption,
		now,
		epistemic.SensitivityCritical,
		epistemic.TemporalPolicy{CriticalMaxAge: 5 * time.Second},
	)
	if got.Decision.Decision != decision.Escalate {
		t.Fatalf("unknown temporal validity should ESCALATE, got %s reasons=%v", got.Decision.Decision, got.Decision.ReasonCodes)
	}
	if got.Decision.ReasonCodes[0] != decision.AssumptionValidityUnknown {
		t.Fatalf("expected %s, got %v", decision.AssumptionValidityUnknown, got.Decision.ReasonCodes)
	}
}

func validRequest(now, observedAt time.Time) decision.Request {
	return decision.Request{
		ActionID:         "act",
		Action:           "drain",
		Target:           "node/node-7",
		ResourceVersion:  "101",
		RequestedAt:      now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge:   60 * time.Second,
		Evidence: []decision.EvidenceObservation{{
			Claim:      "node_health",
			Source:     "kubernetes-api",
			Value:      "healthy",
			ObservedAt: observedAt,
		}},
	}
}
