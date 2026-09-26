//go:build integration

package kubeadapter

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestKindUnknownAcquiresLiveReadOnlyEvidenceAndReevaluates(t *testing.T) {
	env := newKindIntegrationEnv(t, "m1-acquisition")
	ctx := context.Background()

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get synthetic node: %v", err)
	}
	now := metav1.Now()
	node.Status.Conditions = []corev1.NodeCondition{{
		Type:               corev1.NodeReady,
		Status:             corev1.ConditionTrue,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}}
	node, err = env.client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("mark synthetic node Ready: %v", err)
	}

	probeClock := time.Now().UTC()
	req := decision.Request{
		ActionID:            "act-kind-m1",
		Action:              "drain",
		Target:              "node/" + env.nodeName,
		ResourceVersion:     node.ResourceVersion,
		RequestedAt:         probeClock,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []decision.EvidenceObservation{{
			Claim:      nodeHealthClaim,
			Source:     "epistemic-state-cache",
			Value:      "healthy",
			ObservedAt: probeClock,
		}},
	}

	initial := decision.Evaluate(req)
	if initial.Decision != decision.Escalate {
		t.Fatalf("expected initial ESCALATE/UNKNOWN, got %s reasons=%v", initial.Decision, initial.ReasonCodes)
	}

	probe := NewNodeHealthProbe(NewClientGoReader(env.client), func() time.Time {
		return probeClock.Add(time.Second)
	})
	resolved := decision.ResolveUnknown(
		ctx,
		req,
		[]decision.EvidenceProbe{probe},
		1,
	)

	if resolved.Final.Decision != decision.Allow {
		t.Fatalf(
			"expected live read-only probe to resolve UNKNOWN to ALLOW, got %s reasons=%v attempts=%+v",
			resolved.Final.Decision,
			resolved.Final.ReasonCodes,
			resolved.Attempts,
		)
	}
	if resolved.Final.Authorization == nil {
		t.Fatal("expected re-evaluation to mint authorization")
	}
	if len(resolved.Attempts) != 1 {
		t.Fatalf("expected exactly one probe attempt, got %+v", resolved.Attempts)
	}
	attempt := resolved.Attempts[0]
	if attempt.ProbeName != "kubernetes-live-node-health" ||
		attempt.SafetyClass != decision.ProbeReadOnly ||
		attempt.ObservationCount != 1 {
		t.Fatalf("unexpected probe audit record: %+v", attempt)
	}
	if resolved.Final.Authorization.ResourceVersion != resolved.EffectiveRequest.ResourceVersion {
		t.Fatalf(
			"authorization resourceVersion %q does not match refreshed binding %q",
			resolved.Final.Authorization.ResourceVersion,
			resolved.EffectiveRequest.ResourceVersion,
		)
	}
	if resolved.Final.Authorization.ResourceVersion == "" {
		t.Fatal("expected probe to refresh state binding")
	}
}
