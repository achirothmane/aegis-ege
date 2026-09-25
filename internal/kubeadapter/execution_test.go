package kubeadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type stubDryRunExecutor struct {
	cordonNode            string
	cordonResourceVersion string
	evictedPods           []PodStateRef
	cordonErr             error
	evictionErrByPod      map[string]error
	cordonApply           func(nodeName, resourceVersion string) error
	evictApply            func(pod PodStateRef) error
	realCordons           int
	realEvictedPods       []PodStateRef
	lockAcquireErr        error
	lockRenewErr          error
	lockReleaseErr        error
	lockHeld              bool
	lockHolder            string
	lockAcquireCount      int
	lockRenewCount        int
	lockReleaseCount      int
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

func (s *stubDryRunExecutor) CordonNode(_ context.Context, nodeName, resourceVersion string) error {
	s.realCordons++
	if s.cordonApply != nil {
		return s.cordonApply(nodeName, resourceVersion)
	}
	return nil
}

func (s *stubDryRunExecutor) EvictPod(_ context.Context, pod PodStateRef) error {
	s.realEvictedPods = append(s.realEvictedPods, pod)
	if s.evictApply != nil {
		return s.evictApply(pod)
	}
	return nil
}

func (s *stubDryRunExecutor) AcquireExecutionLock(
	_ context.Context,
	namespace string,
	target string,
	holder string,
	_ time.Duration,
) (ExecutionLease, error) {
	s.lockAcquireCount++
	if s.lockAcquireErr != nil {
		return ExecutionLease{}, s.lockAcquireErr
	}
	if s.lockHeld && s.lockHolder != holder {
		return ExecutionLease{}, ErrExecutionLockHeld
	}
	s.lockHeld = true
	s.lockHolder = holder
	return ExecutionLease{
		Namespace: namespace,
		Name:      "stub-lock",
		Target:    target,
		Holder:    holder,
	}, nil
}

func (s *stubDryRunExecutor) RenewExecutionLock(
	_ context.Context,
	lease ExecutionLease,
	_ time.Duration,
) error {
	s.lockRenewCount++
	if s.lockRenewErr != nil {
		return s.lockRenewErr
	}
	if !s.lockHeld || s.lockHolder != lease.Holder {
		return ErrExecutionLockLost
	}
	return nil
}

func (s *stubDryRunExecutor) ReleaseExecutionLock(
	_ context.Context,
	lease ExecutionLease,
) error {
	s.lockReleaseCount++
	if s.lockReleaseErr != nil {
		return s.lockReleaseErr
	}
	if !s.lockHeld || s.lockHolder != lease.Holder {
		return ErrExecutionLockLost
	}
	s.lockHeld = false
	s.lockHolder = ""
	return nil
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

func TestPrepareNodeDrainExecutionEscalatesWhenCordonDryRunDetectsResourceVersionDrift(t *testing.T) {
	now := time.Date(2026, 9, 23, 14, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{
		cordonErr: apierrors.NewConflict(
			schema.GroupResource{Resource: "nodes"},
			"node-7",
			errors.New("resourceVersion changed"),
		),
	}
	adapter := NewWithClockAndExecutor(reader, executor, func() time.Time { return now })

	got, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-1", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}

	if got.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE for optimistic concurrency drift, got %s reasons=%v", got.Decision, got.ReasonCodes)
	}
	if !hasReason(got.ReasonCodes, decision.ResourceVersionChanged) {
		t.Fatalf("expected %s, got %v", decision.ResourceVersionChanged, got.ReasonCodes)
	}
	if got.Authorization != nil {
		t.Fatal("resourceVersion drift must not expose authorization")
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


func TestExecuteAuthorizedNodeDrainIsDisabledByDefault(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExecutor(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-disabled", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE with mutations disabled, got %s", report.Decision)
	}
	if !hasReason(report.ReasonCodes, ReasonRealExecutionUnavailable) {
		t.Fatalf("expected %s, got %v", ReasonRealExecutionUnavailable, report.ReasonCodes)
	}
	if executor.realCordons != 0 || len(executor.realEvictedPods) != 0 {
		t.Fatal("default adapter must not perform real mutations")
	}
}

func TestExecuteAuthorizedNodeDrainEscalatesWhenExecutionLockIsHeld(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{
		lockAcquireErr: ErrExecutionLockHeld,
	}
	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-lock-held", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if !hasReason(report.ReasonCodes, ReasonExecutionLockHeld) {
		t.Fatalf("expected %s, got %v", ReasonExecutionLockHeld, report.ReasonCodes)
	}
	if executor.realCordons != 0 || len(executor.realEvictedPods) != 0 {
		t.Fatal("lock contention must prevent all real mutations")
	}
}

func TestExecuteAuthorizedNodeDrainStopsWhenExecutionLockIsLost(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	executor.cordonApply = func(_ string, _ string) error {
		reader.node.Spec.Unschedulable = true
		reader.node.ResourceVersion = "928442"
		executor.lockRenewErr = ErrExecutionLockLost
		return nil
	}
	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-lock-lost", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after lock loss, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if !hasReason(report.ReasonCodes, ReasonExecutionLockLost) {
		t.Fatalf("expected %s, got %v", ReasonExecutionLockLost, report.ReasonCodes)
	}
	if executor.realCordons != 1 {
		t.Fatalf("expected cordon before injected lock loss, got %d", executor.realCordons)
	}
	if len(executor.realEvictedPods) != 0 {
		t.Fatalf("lock loss must stop before eviction, got %d evictions", len(executor.realEvictedPods))
	}
}

func TestExecuteAuthorizedNodeDrainAppliesCordonAndEvictionsAfterRevalidation(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}

	executor.cordonApply = func(_ string, _ string) error {
		reader.node.Spec.Unschedulable = true
		reader.node.ResourceVersion = "928442"
		return nil
	}
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

	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })
	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-real", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Decision != decision.Allow || preparation.Authorization == nil {
		t.Fatalf("expected prepared ALLOW, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected execution ALLOW, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if executor.realCordons != 1 {
		t.Fatalf("expected one real cordon, got %d", executor.realCordons)
	}
	if len(executor.realEvictedPods) != 2 {
		t.Fatalf("expected two real evictions, got %d", len(executor.realEvictedPods))
	}
	if len(reader.pods) != 0 {
		t.Fatalf("expected all authorized pods removed, got %d", len(reader.pods))
	}
	if len(report.Steps) != 3 {
		t.Fatalf("expected 3 applied mutation steps, got %d", len(report.Steps))
	}
}

func TestExecuteAuthorizedNodeDrainEscalatesWhenRealCordonHitsResourceVersionConflict(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}
	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })

	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-conflict", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	executor.cordonApply = func(_ string, _ string) error {
		return apierrors.NewConflict(
			schema.GroupResource{Resource: "nodes"},
			"node-7",
			errors.New("object modified"),
		)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if !hasReason(report.ReasonCodes, decision.ResourceVersionChanged) {
		t.Fatalf("expected %s, got %v", decision.ResourceVersionChanged, report.ReasonCodes)
	}
	if len(executor.realEvictedPods) != 0 {
		t.Fatalf("expected no eviction after cordon conflict, got %d", len(executor.realEvictedPods))
	}
}

func TestExecuteAuthorizedNodeDrainStopsBeforeEvictionWhenStateDriftsAfterCordon(t *testing.T) {
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	reader := executionReaderFixture()
	executor := &stubDryRunExecutor{}

	executor.cordonApply = func(_ string, _ string) error {
		reader.node.Spec.Unschedulable = true
		reader.node.ResourceVersion = "928442"
		reader.pods[0].Labels = map[string]string{"state-latch.dev/drift": "changed"}
		return nil
	}

	adapter := NewWithClockAndExperimentalMutations(&reader, executor, func() time.Time { return now })
	preparation, err := adapter.PrepareNodeDrainExecution(context.Background(), "act-drift", "node-7", defaultExecutionPolicy())
	if err != nil {
		t.Fatalf("prepare returned error: %v", err)
	}
	if preparation.Authorization == nil {
		t.Fatalf("expected authorization, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		context.Background(),
		*preparation.Authorization,
		"node-7",
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after in-flight drift, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if !hasReason(report.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got %v", decision.ExecutionPlanChanged, report.ReasonCodes)
	}
	if len(executor.realEvictedPods) != 0 {
		t.Fatalf("expected no eviction after drift, got %d", len(executor.realEvictedPods))
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
