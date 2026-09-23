package kubeadapter

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestDigestDrainExecutionPlanIsDeterministic(t *testing.T) {
	plan := DrainExecutionPlan{
		ActionID:            "act-1",
		NodeName:            "node-7",
		NodeResourceVersion: "928441",
		Steps: []DrainExecutionStep{
			{
				Kind:            DrainStepCordonNode,
				NodeName:        "node-7",
				ResourceVersion: "928441",
			},
			{
				Kind: DrainStepEvictPod,
				Pod: &PodStateRef{
					Namespace:       "default",
					Name:            "api-a",
					UID:             "uid-a",
					ResourceVersion: "rv-a",
				},
			},
		},
	}

	first := DigestDrainExecutionPlan(plan)
	second := DigestDrainExecutionPlan(plan)

	if first != second {
		t.Fatalf("expected deterministic digest, got %q and %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("expected sha256 digest, got %q", first)
	}
}

func TestDigestDrainExecutionPlanChangesWhenPodStateChanges(t *testing.T) {
	planA := DrainExecutionPlan{
		ActionID:            "act-1",
		NodeName:            "node-7",
		NodeResourceVersion: "928441",
		Steps: []DrainExecutionStep{
			{
				Kind:            DrainStepCordonNode,
				NodeName:        "node-7",
				ResourceVersion: "928441",
			},
			{
				Kind: DrainStepEvictPod,
				Pod: &PodStateRef{
					Namespace:       "default",
					Name:            "api-a",
					UID:             "uid-a",
					ResourceVersion: "rv-a",
				},
			},
		},
	}
	planB := planA
	planB.Steps = append([]DrainExecutionStep(nil), planA.Steps...)
	pod := *planA.Steps[1].Pod
	pod.ResourceVersion = "rv-b"
	planB.Steps[1].Pod = &pod

	if DigestDrainExecutionPlan(planA) == DigestDrainExecutionPlan(planB) {
		t.Fatal("expected pod resourceVersion change to alter plan digest")
	}
}

func TestPrepareNodeDrainExecutionBindsAuthorizationToPlanDigest(t *testing.T) {
	now := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(
		context.Background(),
		"act-1",
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Allow || preparation.Authorization == nil || preparation.Plan == nil {
		t.Fatalf("expected ALLOW with plan-bound authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	want := DigestDrainExecutionPlan(*preparation.Plan)
	if preparation.PlanDigest != want {
		t.Fatalf("expected preparation plan digest %q, got %q", want, preparation.PlanDigest)
	}
	if preparation.Authorization.PlanDigest != want {
		t.Fatalf("expected authorization plan digest %q, got %q", want, preparation.Authorization.PlanDigest)
	}
}

func TestRevalidateNodeDrainAuthorizationAllowsUnchangedLiveState(t *testing.T) {
	now := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	got, err := adapter.RevalidateNodeDrainAuthorization(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("revalidation returned error: %v", err)
	}
	if got.Decision != decision.Allow {
		t.Fatalf("expected ALLOW for unchanged state, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if got.CurrentPlanDigest != preparation.Authorization.PlanDigest {
		t.Fatalf("expected unchanged plan digest %q, got %q", preparation.Authorization.PlanDigest, got.CurrentPlanDigest)
	}
}

func TestRevalidateNodeDrainAuthorizationEscalatesWhenPodStateChanges(t *testing.T) {
	now := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	reader.pods[0].ResourceVersion = "rv-api-b-new"

	got, err := adapter.RevalidateNodeDrainAuthorization(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("revalidation returned error: %v", err)
	}
	if got.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after pod state drift, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if !hasReason(got.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got %v", decision.ExecutionPlanChanged, got.ReasonCodes)
	}
}

func TestRevalidateNodeDrainAuthorizationBlocksWhenCurrentPDBNoLongerAllowsDrain(t *testing.T) {
	now := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	reader.pdbs = []PodDisruptionBudgetView{
		{
			Namespace:          "default",
			Name:               "all-pods",
			Generation:         1,
			ObservedGeneration: 1,
			DisruptionsAllowed: 0,
			Selector:           &metav1.LabelSelector{},
		},
	}

	got, err := adapter.RevalidateNodeDrainAuthorization(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("revalidation returned error: %v", err)
	}
	if got.Decision != decision.Block {
		t.Fatalf("expected BLOCK after PDB change, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if !hasReason(got.ReasonCodes, decision.ReasonCode(FindingPDBDisruptionBlocked)) {
		t.Fatalf("expected %s, got %v", FindingPDBDisruptionBlocked, got.ReasonCodes)
	}
}

func TestRevalidateNodeDrainAuthorizationEscalatesWhenAuthorizationExpires(t *testing.T) {
	current := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(&reader, executor, func() time.Time { return current })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	current = preparation.Authorization.ValidUntil

	got, err := adapter.RevalidateNodeDrainAuthorization(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("revalidation returned error: %v", err)
	}
	if got.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after authorization expiry, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if !hasReason(got.ReasonCodes, decision.AuthorizationExpired) {
		t.Fatalf("expected %s, got %v", decision.AuthorizationExpired, got.ReasonCodes)
	}
}

