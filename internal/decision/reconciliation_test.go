package decision

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReconcileContradictionUsesFreshEpochAndAllowsOnlyAfterAgreement(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	req := contradictedRequest(now)

	kube := &fakeProbe{
		name:     "kubernetes-live",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{
			ResourceVersion: "101",
			Evidence: []EvidenceObservation{{
				Claim:      "node_health",
				Source:     "kubernetes-live",
				Value:      "healthy",
				ObservedAt: now.Add(time.Second),
			}},
		},
	}
	prom := &fakeProbe{
		name:     "prometheus-live",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{
			Evidence: []EvidenceObservation{{
				Claim:      "node_health",
				Source:     "prometheus-live",
				Value:      "healthy",
				ObservedAt: now.Add(2 * time.Second),
			}},
		},
	}

	got := ReconcileContradiction(
		context.Background(),
		req,
		[]EvidenceProbe{kube, prom},
		2,
	)

	if got.Initial.Decision != Block {
		t.Fatalf("expected initial contradiction BLOCK, got %s", got.Initial.Decision)
	}
	if got.Final.Decision != Allow {
		t.Fatalf("expected reconciled ALLOW, got %s reasons=%v", got.Final.Decision, got.Final.ReasonCodes)
	}
	if got.Final.Authorization == nil {
		t.Fatal("expected authorization only after fresh agreement")
	}
	if len(got.EffectiveRequest.Evidence) != 2 {
		t.Fatalf("expected fresh evidence epoch of two observations, got %+v", got.EffectiveRequest.Evidence)
	}
	for _, observation := range got.EffectiveRequest.Evidence {
		if observation.Source == "old-kubernetes" || observation.Source == "old-prometheus" {
			t.Fatalf("historical contradictory evidence leaked into fresh epoch: %+v", got.EffectiveRequest.Evidence)
		}
	}
}

func TestReconcileContradictionKeepsFreshContradictionBlocked(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	req := contradictedRequest(now)

	kube := &fakeProbe{
		name:     "kubernetes-live",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{Evidence: []EvidenceObservation{{
			Claim: "node_health", Source: "kubernetes-live", Value: "healthy", ObservedAt: now.Add(time.Second),
		}}},
	}
	prom := &fakeProbe{
		name:     "prometheus-live",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{Evidence: []EvidenceObservation{{
			Claim: "node_health", Source: "prometheus-live", Value: "unhealthy", ObservedAt: now.Add(2 * time.Second),
		}}},
	}

	got := ReconcileContradiction(context.Background(), req, []EvidenceProbe{kube, prom}, 2)

	if got.Final.Decision != Block {
		t.Fatalf("expected fresh contradiction to remain BLOCK, got %s reasons=%v", got.Final.Decision, got.Final.ReasonCodes)
	}
	if got.Final.Authorization != nil {
		t.Fatal("fresh contradiction must never mint authorization")
	}
}

func TestReconcileContradictionProbeFailureBecomesUnknownEscalation(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	req := contradictedRequest(now)

	kube := &fakeProbe{
		name:     "kubernetes-live",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{Evidence: []EvidenceObservation{{
			Claim: "node_health", Source: "kubernetes-live", Value: "healthy", ObservedAt: now.Add(time.Second),
		}}},
	}
	prom := &fakeProbe{
		name:     "prometheus-live",
		safety:   ProbeReadOnly,
		supports: true,
		err:      errors.New("metrics unavailable"),
	}

	got := ReconcileContradiction(context.Background(), req, []EvidenceProbe{kube, prom}, 2)

	if got.Final.Decision != Escalate {
		t.Fatalf("expected incomplete reconciliation to ESCALATE, got %s reasons=%v", got.Final.Decision, got.Final.ReasonCodes)
	}
	if got.Final.Authorization != nil {
		t.Fatal("incomplete reconciliation must not mint authorization")
	}
}

func contradictedRequest(now time.Time) Request {
	return Request{
		ActionID:            "act-reconcile",
		Action:              "drain",
		Target:              "node/node-7",
		ResourceVersion:     "100",
		RequestedAt:         now,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []EvidenceObservation{
			{
				Claim: "node_health", Source: "old-kubernetes", Value: "healthy", ObservedAt: now,
			},
			{
				Claim: "node_health", Source: "old-prometheus", Value: "unhealthy", ObservedAt: now,
			},
		},
	}
}
