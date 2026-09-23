package decision

import (
	"slices"
	"testing"
	"time"
)

func TestStaleEvidenceBlocks(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	req := Request{
		ActionID:       "act-drain-node-7",
		Target:         "node/node-7",
		RequestedAt:    now,
		MaxEvidenceAge: 10 * time.Second,
		Evidence: []EvidenceObservation{
			{
				Source:     "prometheus-a",
				Value:      "unhealthy",
				ObservedAt: now.Add(-72 * time.Second),
			},
		},
	}

	got := Evaluate(req)

	if got.Decision != Block {
		t.Fatalf("expected %s for stale evidence, got %s", Block, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, EvidenceStale) {
		t.Fatalf("expected reason code %s, got %v", EvidenceStale, got.ReasonCodes)
	}
}

func TestContradictoryRequiredEvidenceBlocks(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	req := Request{
		ActionID:       "act-drain-node-7",
		Target:         "node/node-7",
		RequestedAt:    now,
		MaxEvidenceAge: 10 * time.Second,
		Evidence: []EvidenceObservation{
			{
				Source:     "prometheus-a",
				Value:      "unhealthy",
				ObservedAt: now.Add(-2 * time.Second),
			},
			{
				Source:     "prometheus-b",
				Value:      "healthy",
				ObservedAt: now.Add(-2 * time.Second),
			},
		},
	}

	got := Evaluate(req)

	if got.Decision != Block {
		t.Fatalf("expected %s for contradictory evidence, got %s", Block, got.Decision)
	}
	if !slices.Contains(got.ReasonCodes, EvidenceContradicted) {
		t.Fatalf("expected reason code %s, got %v", EvidenceContradicted, got.ReasonCodes)
	}
}
