package decision

import (
	"slices"
	"testing"
	"time"

	"github.com/achirothmane/easl"
)

func TestEvaluateAllowsWhenEASLStateIsValid(t *testing.T) {
	now := time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)

	req := validEASLGatedRequest(now)
	req.EpistemicSnapshot = &easl.Snapshot{
		At: now,
		Evidence: []easl.Evidence{{
			ID:         "cluster-health",
			ObservedAt: now.Add(-time.Second),
			ExpiresAt:  &expires,
		}},
		Assumptions: []easl.Assumption{{
			ID:       "safe-to-execute",
			Requires: []easl.EvidenceID{"cluster-health"},
		}},
	}

	got := Evaluate(req)
	if got.Decision != Allow {
		t.Fatalf("expected %s for valid EASL state, got %s with reasons %v", Allow, got.Decision, got.ReasonCodes)
	}
	if got.Authorization == nil {
		t.Fatal("expected authorization after valid EASL gate")
	}
}

func TestEvaluateBlocksContradictedEASLState(t *testing.T) {
	now := time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC)

	req := validEASLGatedRequest(now)
	req.EpistemicSnapshot = &easl.Snapshot{
		At: now,
		Evidence: []easl.Evidence{{
			ID:          "regression-signal",
			ObservedAt:  now,
			Contradicts: []easl.AssumptionID{"safe-to-execute"},
		}},
		Assumptions: []easl.Assumption{{ID: "safe-to-execute"}},
	}

	got := Evaluate(req)
	if got.Decision != Block {
		t.Fatalf("expected %s for contradicted EASL state, got %s", Block, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, EvidenceContradicted) {
		t.Fatalf("expected %s, got %v", EvidenceContradicted, got.ReasonCodes)
	}
	if got.Authorization != nil {
		t.Fatal("contradicted EASL state must not mint an authorization")
	}
}

func TestEvaluateEscalatesMissingEASLEvidence(t *testing.T) {
	now := time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC)

	req := validEASLGatedRequest(now)
	req.EpistemicSnapshot = &easl.Snapshot{
		At: now,
		Assumptions: []easl.Assumption{{
			ID:       "safe-to-execute",
			Requires: []easl.EvidenceID{"required-signal"},
		}},
	}

	got := Evaluate(req)
	if got.Decision != Escalate {
		t.Fatalf("expected %s for missing EASL evidence, got %s", Escalate, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, InsufficientEvidence) {
		t.Fatalf("expected %s, got %v", InsufficientEvidence, got.ReasonCodes)
	}
}

func TestEvaluateEscalatesMalformedEASLSnapshot(t *testing.T) {
	now := time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC)

	req := validEASLGatedRequest(now)
	req.EpistemicSnapshot = &easl.Snapshot{
		At: now,
		Assumptions: []easl.Assumption{
			{ID: "a", DependsOn: []easl.AssumptionID{"b"}},
			{ID: "b", DependsOn: []easl.AssumptionID{"a"}},
		},
	}

	got := Evaluate(req)
	if got.Decision != Escalate {
		t.Fatalf("expected %s for malformed EASL snapshot, got %s", Escalate, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, AssumptionValidityUnknown) {
		t.Fatalf("expected %s, got %v", AssumptionValidityUnknown, got.ReasonCodes)
	}
}

func TestEvaluateEscalatesDegradedEASLState(t *testing.T) {
	now := time.Date(2026, 9, 27, 2, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Second)

	req := validEASLGatedRequest(now)
	req.EpistemicSnapshot = &easl.Snapshot{
		At: now,
		Evidence: []easl.Evidence{{
			ID:         "non-required-old-signal",
			ObservedAt: now.Add(-time.Minute),
			ExpiresAt:  &expired,
		}},
		Assumptions: []easl.Assumption{{ID: "safe-to-execute"}},
	}

	got := Evaluate(req)
	if got.Decision != Escalate {
		t.Fatalf("expected %s for degraded EASL state, got %s", Escalate, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, EvidenceStale) {
		t.Fatalf("expected %s, got %v", EvidenceStale, got.ReasonCodes)
	}
}

func validEASLGatedRequest(now time.Time) Request {
	return Request{
		ActionID:         "act-1",
		Action:           "drain",
		Target:           "node/node-7",
		ResourceVersion:  "928441",
		RequestedAt:      now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge:   10 * time.Second,
		Evidence: []EvidenceObservation{{
			Claim:      "node-health",
			Source:     "kubernetes-api",
			Value:      "healthy",
			ObservedAt: now.Add(-time.Second),
		}},
	}
}
