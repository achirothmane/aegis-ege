package kubeadapter

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestFileDrainCheckpointStoreRoundTrip(t *testing.T) {
	store, err := NewFileDrainCheckpointStore(filepath.Join(t.TempDir(), "checkpoints"))
	if err != nil {
		t.Fatalf("NewFileDrainCheckpointStore returned error: %v", err)
	}

	checkpoint := DrainExecutionCheckpoint{
		ActionID:           "act-file-roundtrip",
		NodeName:           "node-7",
		NodeUID:            "node-uid",
		NodeHealth:         "healthy",
		OriginalPlanDigest: "sha256:original",
		ActivePlanDigest:   "sha256:active",
		AuthorizedPods: []PodStateRef{
			{Namespace: "default", Name: "api-a", UID: "uid-a", StateDigest: "sha256:a"},
		},
		CompletedPodUIDs: []string{"uid-a"},
		Cordoned:         true,
		Status:           DrainExecutionPaused,
		LastDecision:     decision.Escalate,
		LastReasonCodes:  []decision.ReasonCode{ReasonExecutionEvictionRejected},
		UpdatedAt:        time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC),
	}

	if err := store.Save(context.Background(), checkpoint); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	got, err := store.Load(context.Background(), checkpoint.ActionID)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.ActionID != checkpoint.ActionID ||
		got.Status != checkpoint.Status ||
		!got.Cordoned ||
		len(got.CompletedPodUIDs) != 1 ||
		got.CompletedPodUIDs[0] != "uid-a" {
		t.Fatalf("unexpected checkpoint round trip: %+v", got)
	}
}

func TestCheckpointedExecutionRequiresFreshAuthorizationThenResumesRemainingPod(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	reader.node.UID = types.UID("node-uid")
	store := NewMemoryDrainCheckpointStore()

	evictionCalls := 0
	executor := &stubDryRunExecutor{}
	executor.cordonApply = func(_ string, _ string) error {
		reader.node.Spec.Unschedulable = true
		reader.node.ResourceVersion = "928442"
		return nil
	}
	executor.evictApply = func(target PodStateRef) error {
		evictionCalls++
		if evictionCalls == 2 {
			return assertRecoveryError{}
		}

		remaining := make([]corev1.Pod, 0, len(reader.pods))
		for _, pod := range reader.pods {
			if string(pod.UID) == target.UID {
				continue
			}
			remaining = append(remaining, pod)
		}
		reader.pods = remaining
		return nil
	}

	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })
	policy := defaultExecutionPolicy()

	preparation, err := adapter.PrepareNodeDrainExecution(
		context.Background(),
		"act-recover",
		"node-7",
		policy,
	)
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got decision=%s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	first, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("first execution returned error: %v", err)
	}
	if first.Decision != decision.Escalate {
		t.Fatalf("expected partial execution ESCALATE, got %s reasons=%v", first.Decision, first.ReasonCodes)
	}
	if len(reader.pods) != 1 {
		t.Fatalf("expected one pod to remain after partial failure, got %d", len(reader.pods))
	}

	checkpoint, err := store.Load(context.Background(), "act-recover")
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if checkpoint.Status != DrainExecutionPaused {
		t.Fatalf("expected PAUSED checkpoint, got %s", checkpoint.Status)
	}
	if !checkpoint.Cordoned {
		t.Fatal("expected checkpoint to record successful cordon")
	}
	if len(checkpoint.CompletedPodUIDs) != 1 {
		t.Fatalf("expected one completed pod UID, got %v", checkpoint.CompletedPodUIDs)
	}

	assessment, err := adapter.InspectDrainRecovery(
		context.Background(),
		"act-recover",
		"node-7",
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("InspectDrainRecovery returned error: %v", err)
	}
	if assessment.State != DrainRecoveryReauthorizationNeeded {
		t.Fatalf("expected REAUTHORIZATION_REQUIRED, got %s reasons=%v", assessment.State, assessment.ReasonCodes)
	}
	if len(assessment.RemainingPods) != 1 {
		t.Fatalf("expected one recovery target, got %d", len(assessment.RemainingPods))
	}

	// Recovery never reuses the expired/old plan authorization. Build a fresh
	// authorization from the current one-pod reality.
	now = now.Add(time.Second)
	executor.evictApply = func(target PodStateRef) error {
		remaining := make([]corev1.Pod, 0, len(reader.pods))
		for _, pod := range reader.pods {
			if string(pod.UID) == target.UID {
				continue
			}
			remaining = append(remaining, pod)
		}
		reader.pods = remaining
		return nil
	}

	repreparation, err := adapter.PrepareNodeDrainExecution(
		context.Background(),
		"act-recover",
		"node-7",
		policy,
	)
	if err != nil {
		t.Fatalf("reprepare returned error: %v", err)
	}
	if repreparation.Authorization == nil {
		t.Fatalf("expected fresh recovery authorization, got %s reasons=%v", repreparation.Decision, repreparation.ReasonCodes)
	}

	second, err := adapter.ResumeAuthorizedNodeDrain(
		context.Background(),
		*repreparation.Authorization,
		"node-7",
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("resume returned error: %v", err)
	}
	if second.Decision != decision.Allow {
		t.Fatalf("expected resumed ALLOW, got %s reasons=%v", second.Decision, second.ReasonCodes)
	}
	if len(reader.pods) != 0 {
		t.Fatalf("expected recovery to remove only remaining pod, got %d pods", len(reader.pods))
	}

	checkpoint, err = store.Load(context.Background(), "act-recover")
	if err != nil {
		t.Fatalf("load completed checkpoint: %v", err)
	}
	if checkpoint.Status != DrainExecutionCompleted {
		t.Fatalf("expected COMPLETED checkpoint, got %s", checkpoint.Status)
	}
	if len(checkpoint.CompletedPodUIDs) != 2 {
		t.Fatalf("expected both pod UIDs completed, got %v", checkpoint.CompletedPodUIDs)
	}
	if executor.realCordons != 1 {
		t.Fatalf("resume must not cordon a second time, got %d real cordons", executor.realCordons)
	}
}

func TestInspectDrainRecoveryReconcilesEvictionThatSucceededBeforeCheckpointWrite(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	reader.node.UID = types.UID("node-uid")
	reader.node.Spec.Unschedulable = true
	reader.node.ResourceVersion = "928442"

	authorized := []PodStateRef{
		{
			Namespace:   reader.pods[0].Namespace,
			Name:        reader.pods[0].Name,
			UID:         string(reader.pods[0].UID),
			StateDigest: DigestDrainRelevantPodState(reader.pods[0]),
		},
		{
			Namespace:   reader.pods[1].Namespace,
			Name:        reader.pods[1].Name,
			UID:         string(reader.pods[1].UID),
			StateDigest: DigestDrainRelevantPodState(reader.pods[1]),
		},
	}

	// Simulate: first eviction succeeded in Kubernetes, then the process crashed
	// before persisting the completed UID.
	reader.pods = reader.pods[1:]

	store := NewMemoryDrainCheckpointStore()
	if err := store.Save(context.Background(), DrainExecutionCheckpoint{
		ActionID:           "act-reconcile",
		NodeName:           "node-7",
		NodeUID:            "node-uid",
		NodeHealth:         "healthy",
		OriginalPlanDigest: "sha256:original",
		ActivePlanDigest:   "sha256:original",
		AuthorizedPods:     authorized,
		Cordoned:           true,
		Status:             DrainExecutionRunning,
		LastDecision:       decision.Allow,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	adapter := NewWithClock(&reader, func() time.Time { return now })
	assessment, err := adapter.InspectDrainRecovery(
		context.Background(),
		"act-reconcile",
		"node-7",
		defaultExecutionPolicy(),
		store,
	)
	if err != nil {
		t.Fatalf("InspectDrainRecovery returned error: %v", err)
	}
	if assessment.State != DrainRecoveryReauthorizationNeeded {
		t.Fatalf("expected REAUTHORIZATION_REQUIRED, got %s reasons=%v", assessment.State, assessment.ReasonCodes)
	}
	if len(assessment.ReconciledPodUIDs) != 1 || assessment.ReconciledPodUIDs[0] != authorized[0].UID {
		t.Fatalf("expected missing first UID to be reconciled, got %v", assessment.ReconciledPodUIDs)
	}

	checkpoint, err := store.Load(context.Background(), "act-reconcile")
	if err != nil {
		t.Fatalf("load reconciled checkpoint: %v", err)
	}
	if len(checkpoint.CompletedPodUIDs) != 1 || checkpoint.CompletedPodUIDs[0] != authorized[0].UID {
		t.Fatalf("expected reconciled checkpoint completion, got %v", checkpoint.CompletedPodUIDs)
	}
}

type assertRecoveryError struct{}

func (assertRecoveryError) Error() string {
	return "injected second eviction failure"
}
