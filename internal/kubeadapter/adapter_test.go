package kubeadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/state-latch/internal/decision"
)

type stubReader struct {
	node    *corev1.Node
	pods    []corev1.Pod
	pdbs    []PodDisruptionBudgetView
	nodeErr error
	podsErr error
	pdbErr  error
}

func (s stubReader) GetNode(context.Context, string) (*corev1.Node, error) {
	if s.nodeErr != nil {
		return nil, s.nodeErr
	}
	return s.node, nil
}

func (s stubReader) ListPodsOnNode(context.Context, string) ([]corev1.Pod, error) {
	if s.podsErr != nil {
		return nil, s.podsErr
	}
	return s.pods, nil
}

func (s stubReader) ListPodDisruptionBudgets(context.Context) ([]PodDisruptionBudgetView, error) {
	if s.pdbErr != nil {
		return nil, s.pdbErr
	}
	return s.pdbs, nil
}

func TestInspectNodeDrainDerivesResourceVersionHealthAndActivePods(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	reader := stubReader{
		node: readyNode("node-7", "928441", corev1.ConditionTrue),
		pods: []corev1.Pod{
			managedPod("running", corev1.PodRunning),
			managedPod("pending", corev1.PodPending),
			managedPod("done", corev1.PodSucceeded),
			managedPod("failed", corev1.PodFailed),
		},
	}

	adapter := NewWithClock(reader, func() time.Time { return now })
	got, err := adapter.InspectNodeDrain(context.Background(), "node-7")
	if err != nil {
		t.Fatalf("InspectNodeDrain returned error: %v", err)
	}

	if got.ResourceVersion != "928441" {
		t.Fatalf("expected resourceVersion 928441, got %q", got.ResourceVersion)
	}
	if got.NodeHealth != "healthy" {
		t.Fatalf("expected healthy node, got %q", got.NodeHealth)
	}
	if got.ActivePods != 2 {
		t.Fatalf("expected 2 active pods, got %d", got.ActivePods)
	}
	if !got.ObservedAt.Equal(now) {
		t.Fatalf("expected observedAt %v, got %v", now, got.ObservedAt)
	}
}

func TestEvaluateNodeDrainUsesPreflightEvictableBlastRadiusAndBlocks(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	reader := stubReader{
		node: readyNode("node-7", "928441", corev1.ConditionFalse),
		pods: []corev1.Pod{
			managedPod("api-1", corev1.PodRunning),
			managedPod("api-2", corev1.PodRunning),
			managedPod("api-3", corev1.PodPending),
		},
	}

	adapter := NewWithClock(reader, func() time.Time { return now })
	result, snapshot, err := adapter.EvaluateNodeDrain(
		context.Background(),
		"act-drain-node-7",
		"node-7",
		NodeDrainPolicy{
			MaxEvidenceAge:      10 * time.Second,
			RequiredSourceCount: 1,
			MaxBlastRadius:      2,
			AuthorizationTTL:    5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("EvaluateNodeDrain returned error: %v", err)
	}

	if snapshot.ActivePods != 3 {
		t.Fatalf("expected observed active pods 3, got %d", snapshot.ActivePods)
	}
	if result.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", result.Decision)
	}
	if !hasReason(result.ReasonCodes, decision.BlastRadiusExceeded) {
		t.Fatalf("expected %s, got %v", decision.BlastRadiusExceeded, result.ReasonCodes)
	}
}

func TestEvaluateNodeDrainMintsAuthorizationBoundToObservedResourceVersion(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	reader := stubReader{
		node: readyNode("node-7", "928441", corev1.ConditionFalse),
		pods: []corev1.Pod{
			managedPod("api-1", corev1.PodRunning),
		},
	}

	adapter := NewWithClock(reader, func() time.Time { return now })
	result, _, err := adapter.EvaluateNodeDrain(
		context.Background(),
		"act-drain-node-7",
		"node-7",
		NodeDrainPolicy{
			MaxEvidenceAge:      10 * time.Second,
			RequiredSourceCount: 1,
			MaxBlastRadius:      5,
			AuthorizationTTL:    5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("EvaluateNodeDrain returned error: %v", err)
	}

	if result.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s with reasons %v", result.Decision, result.ReasonCodes)
	}
	if result.Authorization == nil {
		t.Fatal("expected state-bound authorization")
	}
	if result.Authorization.ResourceVersion != "928441" {
		t.Fatalf("expected authorization bound to resourceVersion 928441, got %q", result.Authorization.ResourceVersion)
	}
	if result.Authorization.Target != "node/node-7" {
		t.Fatalf("expected target node/node-7, got %q", result.Authorization.Target)
	}
}

func TestEvaluateNodeDrainStopsAtPreflightBlocker(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	reader := stubReader{
		node: readyNode("node-7", "928441", corev1.ConditionTrue),
		pods: []corev1.Pod{
			daemonSetPod("agent"),
		},
	}

	adapter := NewWithClock(reader, func() time.Time { return now })
	result, _, err := adapter.EvaluateNodeDrain(
		context.Background(),
		"act-drain-node-7",
		"node-7",
		NodeDrainPolicy{
			MaxEvidenceAge:      10 * time.Second,
			RequiredSourceCount: 1,
			MaxBlastRadius:      100,
			AuthorizationTTL:    5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("EvaluateNodeDrain returned error: %v", err)
	}

	if result.Decision != decision.Block {
		t.Fatalf("expected preflight BLOCK, got %s", result.Decision)
	}
	if !hasReason(result.ReasonCodes, decision.ReasonCode(FindingDaemonSetRequiresIgnore)) {
		t.Fatalf("expected %s, got %v", FindingDaemonSetRequiresIgnore, result.ReasonCodes)
	}
	if result.Authorization != nil {
		t.Fatal("preflight blocker must not mint authorization")
	}
}

func TestInspectNodeDrainPropagatesNodeReadFailure(t *testing.T) {
	adapter := New(stubReader{nodeErr: errors.New("forbidden")})

	_, err := adapter.InspectNodeDrain(context.Background(), "node-7")
	if err == nil {
		t.Fatal("expected node read error")
	}
}

func readyNode(name, resourceVersion string, ready corev1.ConditionStatus) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: resourceVersion,
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: ready,
				},
			},
		},
	}
}

func managedPod(name string, phase corev1.PodPhase) corev1.Pod {
	controller := true
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       "ReplicaSet",
					Name:       "api",
					Controller: &controller,
				},
			},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func daemonSetPod(name string) corev1.Pod {
	controller := true
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       "DaemonSet",
					Name:       "node-agent",
					Controller: &controller,
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func hasReason(reasons []decision.ReasonCode, want decision.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
