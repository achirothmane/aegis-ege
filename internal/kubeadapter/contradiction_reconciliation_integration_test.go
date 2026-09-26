//go:build integration

package kubeadapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/prometheusprobe"
)

func TestKindContradictionReconciliationFreshAgreementAllows(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2b-agree")
	server := prometheusHealthServer(t, observedAt.Add(2*time.Second), "1")
	defer server.Close()

	req := m2ContradictedRequest(env.nodeName, node.ResourceVersion, observedAt)
	if initial := decision.Evaluate(req); initial.Decision != decision.Block {
		t.Fatalf("expected initial contradiction BLOCK, got %s reasons=%v", initial.Decision, initial.ReasonCodes)
	}

	kubeProbe := NewNodeHealthProbe(NewClientGoReader(env.client), func() time.Time {
		return observedAt.Add(time.Second)
	})
	promProbe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())

	reconciled := decision.ReconcileContradiction(
		context.Background(),
		req,
		[]decision.EvidenceProbe{kubeProbe, promProbe},
		2,
	)

	if reconciled.Final.Decision != decision.Allow {
		t.Fatalf(
			"expected fresh independent agreement to ALLOW, got %s reasons=%v attempts=%+v",
			reconciled.Final.Decision,
			reconciled.Final.ReasonCodes,
			reconciled.Attempts,
		)
	}
	if reconciled.Final.Authorization == nil {
		t.Fatal("fresh reconciliation agreement must mint authorization")
	}
	if len(reconciled.EffectiveRequest.Evidence) != 2 {
		t.Fatalf("expected two fresh observations, got %+v", reconciled.EffectiveRequest.Evidence)
	}
	for _, observation := range reconciled.EffectiveRequest.Evidence {
		if observation.Source == "historical-kubernetes" || observation.Source == "historical-prometheus" {
			t.Fatalf("historical contradictory evidence leaked into fresh epoch: %+v", reconciled.EffectiveRequest.Evidence)
		}
	}
	if reconciled.Final.Authorization.ResourceVersion != reconciled.EffectiveRequest.ResourceVersion {
		t.Fatalf(
			"authorization binding %q differs from fresh state binding %q",
			reconciled.Final.Authorization.ResourceVersion,
			reconciled.EffectiveRequest.ResourceVersion,
		)
	}
}

func TestKindContradictionReconciliationFreshConflictBlocks(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2b-conflict")
	server := prometheusHealthServer(t, observedAt.Add(2*time.Second), "0")
	defer server.Close()

	req := m2ContradictedRequest(env.nodeName, node.ResourceVersion, observedAt)
	kubeProbe := NewNodeHealthProbe(NewClientGoReader(env.client), func() time.Time {
		return observedAt.Add(time.Second)
	})
	promProbe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())

	reconciled := decision.ReconcileContradiction(
		context.Background(),
		req,
		[]decision.EvidenceProbe{kubeProbe, promProbe},
		2,
	)

	if reconciled.Final.Decision != decision.Block {
		t.Fatalf(
			"expected fresh contradiction to remain BLOCK, got %s reasons=%v attempts=%+v",
			reconciled.Final.Decision,
			reconciled.Final.ReasonCodes,
			reconciled.Attempts,
		)
	}
	if len(reconciled.Final.ReasonCodes) != 1 ||
		reconciled.Final.ReasonCodes[0] != decision.EvidenceContradicted {
		t.Fatalf("expected %s, got %v", decision.EvidenceContradicted, reconciled.Final.ReasonCodes)
	}
	if reconciled.Final.Authorization != nil {
		t.Fatal("fresh contradiction must not mint authorization")
	}
}

func TestKindContradictionReconciliationMissingSourceEscalates(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2b-missing")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	req := m2ContradictedRequest(env.nodeName, node.ResourceVersion, observedAt)
	kubeProbe := NewNodeHealthProbe(NewClientGoReader(env.client), func() time.Time {
		return observedAt.Add(time.Second)
	})
	promProbe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())

	reconciled := decision.ReconcileContradiction(
		context.Background(),
		req,
		[]decision.EvidenceProbe{kubeProbe, promProbe},
		2,
	)

	if reconciled.Final.Decision != decision.Escalate {
		t.Fatalf(
			"expected incomplete fresh epoch to ESCALATE, got %s reasons=%v attempts=%+v",
			reconciled.Final.Decision,
			reconciled.Final.ReasonCodes,
			reconciled.Attempts,
		)
	}
	if reconciled.Final.Authorization != nil {
		t.Fatal("incomplete reconciliation must not mint authorization")
	}
}

func m2ContradictedRequest(
	nodeName string,
	resourceVersion string,
	observedAt time.Time,
) decision.Request {
	return decision.Request{
		ActionID:            "act-kind-m2b",
		Action:              "drain",
		Target:              "node/" + nodeName,
		ResourceVersion:     resourceVersion,
		RequestedAt:         observedAt,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []decision.EvidenceObservation{
			{
				Claim:      nodeHealthClaim,
				Source:     "historical-kubernetes",
				Value:      "healthy",
				ObservedAt: observedAt,
			},
			{
				Claim:      nodeHealthClaim,
				Source:     "historical-prometheus",
				Value:      "unhealthy",
				ObservedAt: observedAt,
			},
		},
	}
}
