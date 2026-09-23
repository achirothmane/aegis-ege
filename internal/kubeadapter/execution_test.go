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

type stubDryRunExecutor struct {
	cordonNode            string
	cordonResourceVersion string
	evictedPods           []PodStateRef
	cordonErr             error
	evictionErrByPod      map[string]error
}

func (s *stubDryRunExecutor) DryRunCordonNode(_ context.Context, nodeName, resourceVersion string) error {
	s.cordonNode = nodeName
	s.cordonResourceVersion = resourceVersion
	return s.cordonErr
}

func (s *stubDryRunExecutor) DryRunEvictPod(_ context.Context, pod PodStateRef) error {
	s.evictedPods = append(s.evictedPods, pod)
	if s.evictionErrByPod == nil {
		return nil
	}
	return s.evictionErrByPod[pod.Namespace+"/"+pod.Name]
}

func TestBuildDrainExecutionPlanIsDeterministicAndStateBound(t *testing.T) {
	snapshot := NodeDrainSnapshot{
		NodeName:        "node-7",
		ResourceVersion: "928441",
	}
	preflight := DrainPreflightReport{
		Decision:      decision.Allow,
		EvictablePods: 2,
		EvictionCandidates: []PodStateRef{
			{Namespace: "default", Name: "api-a", UID: "uid-a", ResourceVersion: "201"},
			{Namespace: "default", Name: "api-b", UID: "uid-b", ResourceVersion: "202"},
		},
	}

	plan := BuildDrainExecutionPlan("act-1", snapshot, preflight)

	if len(plan.Steps) != 3 {
		t.Fatalf("expected 3 plan steps, got %d", len(plan.Steps))
	}
	if plan.Steps[0].Kind != DrainStepCordonNode {
		t.Fatalf("expected first step to cordon node, got %s", plan.Steps[0].Kind)
	}
	if plan.Steps[0].ResourceVersion != "928441" {
		t.Fatalf("expected node resourceVersion binding, got %q", plan.Steps[0].ResourceVersion)
	}
	if plan.Steps[1].Pod == nil || plan.Steps[1].Pod.UID != "uid-a" || plan.Steps[1].Pod.ResourceVersion != "201" {
		t.Fatalf("expected first eviction to be state-bound, got %+v", plan.Steps[1].Pod)
	}
}

func TestPrepareNodeDrainExecutionEscalatesWithoutServerDryRun(t *testing.T) {
	now := time.Date(2026, 9, 23, 14, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	adapter := NewWithClock(reader, func() time.Time { return now })

	got, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}

	if got.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE without server dry-run, got %s", got.Decision)
	}
	if !hasReason(got.ReasonCodes, ReasonServerDryRunUnavailable) {
		t.Fatalf("expected %s, got %v", ReasonServerDryRunUnavailable, got.ReasonCodes)
	}
	if got.Authorization != nil {
		t.Fatal("must not expose execution authorization before server dry-run")
	}
}

func TestPrepareNodeDrainExecutionAllowsOnlyAfterAllDryRunsPass(t *testing.T) {
	now := time.Date(2026, 9, 23, 14, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(reader, executor, func() time.Time { return now })

	got, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}

	if got.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if got.Authorization == nil {
		t.Fatal("expected execution authorization after successful dry-run")
	}
	if got.DryRun == nil || !got.DryRun.Passed {
		t.Fatalf("expected passing dry-run report, got %+v", got.DryRun)
	}
	if executor.cordonNode != "node-7" || executor.cordonResourceVersion != "928441" {
		t.Fatalf("expected cordon dry-run bound to node state, got node=%q rv=%q", executor.cordonNode, executor.cordonResourceVersion)
	}
	if len(executor.evictedPods) != 2 {
		t.Fatalf("expected 2 eviction dry-runs, got %d", len(executor.evictedPods))
	}
	if executor.evictedPods[0].Name != "api-a" || executor.evictedPods[0].UID != "uid-api-a" || executor.evictedPods[0].ResourceVersion != "rv-api-a" {
		t.Fatalf("unexpected first eviction binding: %+v", executor.evictedPods[0])
	}
}

func TestPrepareNodeDrainExecutionBlocksWhenCordonDryRunIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 23, 14, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{cordonErr: errors.New("admission denied")}
	adapter := NewWithClockAndExecutor(reader, executor, func() time.Time { return now })

	got, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}

	if got.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", got.Decision)
	}
	if !hasReason(got.ReasonCodes, ReasonServerDryRunCordonRejected) {
		t.Fatalf("expected %s, got %v", ReasonServerDryRunCordonRejected, got.ReasonCodes)
	}
	if len(executor.evictedPods) != 0 {
		t.Fatal("eviction dry-runs must not execute after cordon dry-run rejection")
	}
	if got.Authorization != nil {
		t.Fatal("dry-run rejection must not expose authorization")
	}
}

func TestPrepareNodeDrainExecutionBlocksWhenAnyEvictionDryRunIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 23, 14, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{
		evictionErrByPod: map[string]error{
			"default/api-b": errors.New("eviction rejected"),
		},
	}
	adapter := NewWithClockAndExecutor(reader, executor, func() time.Time { return now })

	got, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}

	if got.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", got.Decision)
	}
	if !hasReason(got.ReasonCodes, ReasonServerDryRunEvictionRejected) {
		t.Fatalf("expected %s, got %v", ReasonServerDryRunEvictionRejected, got.ReasonCodes)
	}
	if got.DryRun == nil || got.DryRun.Passed {
		t.Fatalf("expected failed dry-run report, got %+v", got.DryRun)
	}
	if got.Authorization != nil {
		t.Fatal("dry-run rejection must not expose authorization")
	}
}

func executionReaderFixture() stubReader {
	return stubReader{
		node: readyNode("node-7", "928441", corev1.ConditionTrue),
		pods: []corev1.Pod{
			executionManagedPod("api-b", "uid-api-b", "rv-api-b"),
			executionManagedPod("api-a", "uid-api-a", "rv-api-a"),
		},
	}
}

func executionManagedPod(name, uid, resourceVersion string) corev1.Pod {
	controller := true
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       "default",
			UID:             types.UID(uid),
			ResourceVersion: resourceVersion,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       "ReplicaSet",
					Name:       "api",
					Controller: &controller,
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func defaultExecutionPolicy() NodeDrainPolicy {
	return NodeDrainPolicy{
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 1,
		MaxBlastRadius:      10,
		AuthorizationTTL:    5 * time.Second,
	}
}
