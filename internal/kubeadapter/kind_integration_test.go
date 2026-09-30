//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestKindServerDryRunAcceptsPlanWithoutPersistingMutations(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "dryrun")
	policy := integrationExecutionPolicy()

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		context.Background(),
		"act-kind-dryrun",
		env.nodeName,
		policy,
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s reasons=%v dryRun=%+v", preparation.Decision, preparation.ReasonCodes, preparation.DryRun)
	}
	if preparation.Authorization == nil || preparation.PlanDigest == "" {
		t.Fatalf("expected plan-bound authorization, got auth=%v digest=%q", preparation.Authorization, preparation.PlanDigest)
	}
	if preparation.DryRun == nil || !preparation.DryRun.Passed {
		t.Fatalf("expected server dry-run to pass, got %+v", preparation.DryRun)
	}

	node, err := env.client.CoreV1().Nodes().Get(context.Background(), env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after dry-run: %v", err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("server dry-run cordon must not persist spec.unschedulable=true")
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		context.Background(),
		env.podName,
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("server dry-run eviction must leave pod present: %v", err)
	}
}

func TestKindPDBBlocksRealServerDryRunEvictionAndStateLatchPreparation(t *testing.T) {
	env := newKindIntegrationEnv(t, "pdb")
	ctx := context.Background()

	zero := intstr.FromInt(0)
	pdb, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Create(
		ctx,
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-all",
				Namespace: env.namespace,
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &zero,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "state-latch-it"},
				},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("create PDB: %v", err)
	}

	waitForPDBStatus(t, env.client, env.namespace, pdb.Name, func(current *policyv1.PodDisruptionBudget) bool {
		return current.Status.ObservedGeneration == current.Generation &&
			current.Status.DisruptionsAllowed == 0
	})

	pod, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}

	reader := NewClientGoReader(env.client)
	err = reader.DryRunEvictPod(ctx, PodStateRef{
		Namespace:       pod.Namespace,
		Name:            pod.Name,
		UID:             string(pod.UID),
		ResourceVersion: pod.ResourceVersion,
	})
	if err == nil {
		t.Fatal("expected Kubernetes Eviction API to reject dry-run under zero-disruption PDB")
	}
	if !apierrors.IsTooManyRequests(err) {
		t.Fatalf("expected TooManyRequests from PDB-protected eviction, got %v", err)
	}

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		ctx,
		"act-kind-pdb",
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Block {
		t.Fatalf("expected StateLatch BLOCK, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}
	if !hasReason(preparation.ReasonCodes, decision.ReasonCode(FindingPDBDisruptionBlocked)) {
		t.Fatalf("expected %s, got %v", FindingPDBDisruptionBlocked, preparation.ReasonCodes)
	}
	if preparation.Authorization != nil {
		t.Fatal("PDB-blocked preparation must not expose authorization")
	}
}

func TestKindLiveRevalidationDetectsPodSemanticDrift(t *testing.T) {
	env := newKindIntegrationEnv(t, "drift")
	ctx := context.Background()

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		ctx,
		"act-kind-drift",
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Allow || preparation.Authorization == nil {
		t.Fatalf("expected initial ALLOW, got %s reasons=%v dryRun=%+v", preparation.Decision, preparation.ReasonCodes, preparation.DryRun)
	}

	before, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod before drift: %v", err)
	}

	patch := []byte(`{"metadata":{"labels":{"state-latch.dev/drift":"changed"}}}`)
	after, err := env.client.CoreV1().Pods(env.namespace).Patch(
		ctx,
		env.podName,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	if err != nil {
		t.Fatalf("patch pod to create state drift: %v", err)
	}
	if after.ResourceVersion == before.ResourceVersion {
		t.Fatalf("expected pod resourceVersion to change, remained %q", after.ResourceVersion)
	}

	revalidation, err := env.adapter.RevalidateNodeDrainAuthorization(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("RevalidateNodeDrainAuthorization returned error: %v", err)
	}
	if revalidation.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after live pod drift, got %s reasons=%v", revalidation.Decision, revalidation.ReasonCodes)
	}
	if !hasReason(revalidation.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got %v", decision.ExecutionPlanChanged, revalidation.ReasonCodes)
	}
}


func TestKindExecutionLeasePreventsConcurrentDrainOnSameNode(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "lock")
	ctx := context.Background()
	policy := integrationExecutionPolicy()
	policy.ExecutionLockNamespace = env.namespace
	policy.ExecutionLockDuration = 10 * time.Second

	reader := NewClientGoReader(env.client)
	heldLease, err := reader.AcquireExecutionLock(
		ctx,
		policy.ExecutionLockNamespace,
		"node/"+env.nodeName,
		"external-holder",
		policy.ExecutionLockDuration,
	)
	if err != nil {
		t.Fatalf("AcquireExecutionLock returned error: %v", err)
	}

	preparation := prepareKindDrainWithFreshAuthorization(
		t,
		env.adapter,
		"act-kind-lock-contender",
		env.nodeName,
		policy,
	)

	blocked, err := env.adapter.ExecuteAuthorizedNodeDrain(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
	)
	if err != nil {
		t.Fatalf("contending ExecuteAuthorizedNodeDrain returned error: %v", err)
	}
	if blocked.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE under lock contention, got %s reasons=%v", blocked.Decision, blocked.ReasonCodes)
	}
	if !hasReason(blocked.ReasonCodes, ReasonExecutionLockHeld) {
		t.Fatalf("expected %s, got %v", ReasonExecutionLockHeld, blocked.ReasonCodes)
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after blocked contender: %v", err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("lock contender must not cordon the node")
	}
	if _, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{}); err != nil {
		t.Fatalf("lock contender must not evict the pod: %v", err)
	}

	if err := reader.ReleaseExecutionLock(ctx, heldLease); err != nil {
		t.Fatalf("ReleaseExecutionLock returned error: %v", err)
	}

	freshPreparation, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		env.adapter,
		"act-kind-lock-contender",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Allow {
		t.Fatalf("expected ALLOW after lock release, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if report.PlanDigest != freshPreparation.PlanDigest {
		t.Fatalf("expected executed plan digest %q, got %q", freshPreparation.PlanDigest, report.PlanDigest)
	}
}

func TestKindGuardedRealExecutionCordonsAndEvictsAuthorizedPod(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "real")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	preparation, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		env.adapter,
		"act-kind-real",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Allow {
		t.Fatalf("expected execution ALLOW, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if report.PlanDigest != preparation.PlanDigest {
		t.Fatalf("expected executed plan digest %q, got %q", preparation.PlanDigest, report.PlanDigest)
	}
	if len(report.Steps) != 2 {
		t.Fatalf("expected cordon + eviction, got %d steps", len(report.Steps))
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after execution: %v", err)
	}
	if !node.Spec.Unschedulable {
		t.Fatal("expected real execution to persist node cordon")
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected real execution to evict pod, got err=%v", err)
	}
}

func TestKindGuardedRealExecutionStopsOnDriftAfterCordon(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "real-drift")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	reader := NewClientGoReader(env.client)
	executor := &driftAfterCordonExecutor{
		delegate:  reader,
		client:    env.client,
		namespace: env.namespace,
		podName:   env.podName,
	}
	adapter := NewWithExperimentalMutations(reader, executor)

	_, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		adapter,
		"act-kind-real-drift",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after post-cordon drift, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if !hasReason(report.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got reasons=%v steps=%+v", decision.ExecutionPlanChanged, report.ReasonCodes, report.Steps)
	}
	if executor.evictions != 0 {
		t.Fatalf("expected zero real evictions after drift, got %d", executor.evictions)
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must remain after guarded stop: %v", err)
	}

}

type driftAfterCordonExecutor struct {
	delegate  *ClientGoReader
	client    kubernetes.Interface
	namespace string
	podName   string
	evictions int
}

func (e *driftAfterCordonExecutor) DryRunCordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	return e.delegate.DryRunCordonNode(ctx, nodeName, resourceVersion)
}

func (e *driftAfterCordonExecutor) DryRunEvictPod(ctx context.Context, pod PodStateRef) error {
	return e.delegate.DryRunEvictPod(ctx, pod)
}

func (e *driftAfterCordonExecutor) CordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	err := e.delegate.CordonNode(ctx, nodeName, resourceVersion)

	// This retry exists only in the test injector so the scenario deterministically
	// reaches the post-cordon revalidation boundary. Production StateLatch never
	// retries a resourceVersion conflict without a fresh authorization path.
	for attempt := 0; apierrors.IsConflict(err) && attempt < 5; attempt++ {
		node, getErr := e.client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		err = e.delegate.CordonNode(ctx, nodeName, node.ResourceVersion)
	}
	if err != nil {
		return err
	}

	patch := []byte(`{"metadata":{"labels":{"state-latch.dev/in-flight-drift":"changed"}}}`)
	_, err = e.client.CoreV1().Pods(e.namespace).Patch(
		ctx,
		e.podName,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	return err
}

func (e *driftAfterCordonExecutor) EvictPod(ctx context.Context, pod PodStateRef) error {
	e.evictions++
	return e.delegate.EvictPod(ctx, pod)
}


func TestKindPartialFailurePersistsCheckpointAndResumesWithFreshAuthorization(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "recovery")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	zero := int64(0)
	secondPod, err := env.client.CoreV1().Pods(env.namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workload-z",
			Namespace: env.namespace,
			Labels:    map[string]string{"app": "state-latch-real-it"},
		},
		Spec: corev1.PodSpec{
			NodeName:                      env.nodeName,
			ServiceAccountName:            "default",
			TerminationGracePeriodSeconds: &zero,
			Containers: []corev1.Container{
				{
					Name:  "hold",
					Image: "registry.k8s.io/pause:3.10",
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create second recovery pod: %v", err)
	}
	_ = markPodRunningAndReady(t, env.client, *secondPod)

	store, err := NewFileDrainCheckpointStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileDrainCheckpointStore returned error: %v", err)
	}

	reader := NewClientGoReader(env.client)
	failAfterAccepted := &failAfterAcceptedEvictionExecutor{
		delegate: reader,
		client:   env.client,
	}
	partialAdapter := NewWithExperimentalMutations(reader, failAfterAccepted)

	preparation, first := executeCheckpointedKindDrainPastPreMutationDrift(
		t,
		partialAdapter,
		"act-kind-recovery",
		env.nodeName,
		policy,
		store,
	)
	if first.Decision != decision.Escalate {
		t.Fatalf("expected partial execution ESCALATE, got %s reasons=%v", first.Decision, first.ReasonCodes)
	}
	if hasReason(first.ReasonCodes, decision.ResourceVersionChanged) {
		t.Fatalf("expected injected post-eviction interruption, got pre-mutation drift: %v", first.ReasonCodes)
	}

	checkpoint, err := store.Load(ctx, "act-kind-recovery")
	if err != nil {
		t.Fatalf("load partial checkpoint: %v", err)
	}
	if checkpoint.Status != DrainExecutionPaused {
		t.Fatalf("expected PAUSED checkpoint, got %s", checkpoint.Status)
	}
	if len(checkpoint.CompletedPodUIDs) != 0 {
		t.Fatalf("expected simulated interruption before completion checkpoint, got %v", checkpoint.CompletedPodUIDs)
	}

	waitForPodNotFound(t, env.client, env.namespace, env.podName)

	assessment, err := partialAdapter.InspectDrainRecovery(
		ctx,
		"act-kind-recovery",
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("InspectDrainRecovery returned error: %v", err)
	}
	if assessment.State != DrainRecoveryReauthorizationNeeded {
		t.Fatalf("expected REAUTHORIZATION_REQUIRED, got %s reasons=%v", assessment.State, assessment.ReasonCodes)
	}
	if len(assessment.RemainingPods) != 1 || assessment.RemainingPods[0].Name != "workload-z" {
		t.Fatalf("expected only workload-z to remain, got %+v", assessment.RemainingPods)
	}
	if len(assessment.ReconciledPodUIDs) != 1 {
		t.Fatalf("expected one reconciled accepted eviction, got %v", assessment.ReconciledPodUIDs)
	}

	oldAuthResume, err := partialAdapter.ResumeAuthorizedNodeDrain(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("resume with old authorization returned error: %v", err)
	}
	if oldAuthResume.Decision == decision.Allow {
		t.Fatal("old two-Pod authorization must not resume the one-Pod remainder")
	}

	freshPreparation := prepareKindDrainWithFreshAuthorization(
		t,
		env.adapter,
		"act-kind-recovery",
		env.nodeName,
		policy,
	)

	resumed, err := env.adapter.ResumeAuthorizedNodeDrain(
		ctx,
		*freshPreparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("ResumeAuthorizedNodeDrain returned error: %v", err)
	}
	if resumed.Decision != decision.Allow {
		t.Fatalf("expected resumed ALLOW, got %s reasons=%v", resumed.Decision, resumed.ReasonCodes)
	}

	checkpoint, err = store.Load(ctx, "act-kind-recovery")
	if err != nil {
		t.Fatalf("load completed checkpoint: %v", err)
	}
	if checkpoint.Status != DrainExecutionCompleted {
		t.Fatalf("expected COMPLETED checkpoint, got %s", checkpoint.Status)
	}
	if len(checkpoint.CompletedPodUIDs) != 2 {
		t.Fatalf("expected both authorized Pod UIDs completed, got %v", checkpoint.CompletedPodUIDs)
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, "workload-z", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected remaining Pod to be evicted during resume, got err=%v", err)
	}
}

type failAfterAcceptedEvictionExecutor struct {
	delegate *ClientGoReader
	client   kubernetes.Interface
	failed   bool
}

func (e *failAfterAcceptedEvictionExecutor) DryRunCordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	return e.delegate.DryRunCordonNode(ctx, nodeName, resourceVersion)
}

func (e *failAfterAcceptedEvictionExecutor) DryRunEvictPod(ctx context.Context, pod PodStateRef) error {
	return e.delegate.DryRunEvictPod(ctx, pod)
}

func (e *failAfterAcceptedEvictionExecutor) CordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	err := e.delegate.CordonNode(ctx, nodeName, resourceVersion)
	for attempt := 0; apierrors.IsConflict(err) && attempt < 5; attempt++ {
		node, getErr := e.client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		err = e.delegate.CordonNode(ctx, nodeName, node.ResourceVersion)
	}
	return err
}

func (e *failAfterAcceptedEvictionExecutor) EvictPod(ctx context.Context, pod PodStateRef) error {
	if e.failed {
		return e.delegate.EvictPod(ctx, pod)
	}
	if err := e.delegate.EvictPod(ctx, pod); err != nil {
		return err
	}
	e.failed = true
	return fmt.Errorf("injected interruption after Kubernetes accepted eviction")
}

func waitForPodNotFound(
	t *testing.T,
	client kubernetes.Interface,
	namespace string,
	name string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		_, err := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		if err != nil {
			t.Fatalf("get pod while waiting for deletion: %v", err)
		}

		select {
		case <-ctx.Done():
			t.Fatalf("pod %s/%s did not disappear: %v", namespace, name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func prepareKindDrainWithFreshAuthorization(
	t *testing.T,
	adapter *Adapter,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
) NodeDrainPreparation {
	t.Helper()

	for attempt := 0; attempt < 12; attempt++ {
		preparation, err := adapter.PrepareNodeDrainExecution(
			context.Background(),
			actionID,
			nodeName,
			policy,
		)
		if err != nil {
			t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
		}
		if preparation.Decision == decision.Allow && preparation.Authorization != nil {
			return preparation
		}
		if preparation.Decision == decision.Escalate &&
			hasReason(preparation.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf(
			"expected ALLOW or retryable pre-mutation drift, got %s reasons=%v dryRun=%+v",
			preparation.Decision,
			preparation.ReasonCodes,
			preparation.DryRun,
		)
	}

	t.Fatal("could not obtain stable fresh authorization")
	return NodeDrainPreparation{}
}

func executeKindDrainWithFreshAuthorizationRetry(
	t *testing.T,
	adapter *Adapter,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
) (NodeDrainPreparation, GuardedDrainExecutionReport) {
	t.Helper()

	for attempt := 0; attempt < 12; attempt++ {
		preparation := prepareKindDrainWithFreshAuthorization(t, adapter, actionID, nodeName, policy)
		report, err := adapter.ExecuteAuthorizedNodeDrain(
			context.Background(),
			*preparation.Authorization,
			nodeName,
			policy,
		)
		if err != nil {
			t.Fatalf("ExecuteAuthorizedNodeDrain returned error: %v", err)
		}
		if report.Decision == decision.Escalate &&
			hasReason(report.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return preparation, report
	}

	t.Fatal("execution never passed pre-mutation Node drift")
	return NodeDrainPreparation{}, GuardedDrainExecutionReport{}
}

func executeCheckpointedKindDrainPastPreMutationDrift(
	t *testing.T,
	adapter *Adapter,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
) (NodeDrainPreparation, GuardedDrainExecutionReport) {
	t.Helper()

	for attempt := 0; attempt < 12; attempt++ {
		preparation := prepareKindDrainWithFreshAuthorization(t, adapter, actionID, nodeName, policy)
		report, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(
			context.Background(),
			*preparation.Authorization,
			nodeName,
			policy,
			store,
		)
		if err != nil {
			t.Fatalf("ExecuteAuthorizedNodeDrainWithCheckpointStore returned error: %v", err)
		}
		if report.Decision == decision.Escalate &&
			hasReason(report.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return preparation, report
	}

	t.Fatal("checkpointed execution never passed pre-mutation Node drift")
	return NodeDrainPreparation{}, GuardedDrainExecutionReport{}
}

type kindIntegrationEnv struct {
	client    kubernetes.Interface
	adapter   *Adapter
	namespace string
	nodeName  string
	podName   string
}

func newKindIntegrationEnv(t *testing.T, suffix string) kindIntegrationEnv {
	t.Helper()

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required for KinD integration tests")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}
	adapter, err := NewForConfig(config)
	if err != nil {
		t.Fatalf("build StateLatch adapter: %v", err)
	}

	namespace := "sl-it-" + suffix
	nodeName := "sl-it-node-" + suffix

	ctx := context.Background()
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := client.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create synthetic node: %v", err)
	}

	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: namespace},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create default service account: %v", err)
	}

	replicas := int32(1)
	rs, err := client.AppsV1().ReplicaSets(namespace).Create(ctx, &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workload-owner",
			Namespace: namespace,
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "state-latch-it"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "state-latch-it"},
				},
				Spec: corev1.PodSpec{
					NodeName:           nodeName,
					ServiceAccountName: "default",
					Containers: []corev1.Container{
						{
							Name:  "hold",
							Image: "registry.k8s.io/pause:3.10",
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create ReplicaSet: %v", err)
	}

	pod := waitForReplicaSetPod(t, client, namespace, rs.UID)
	pod = markPodRunningAndReady(t, client, pod)

	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
		_ = client.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
	})

	return kindIntegrationEnv{
		client:    client,
		adapter:   adapter,
		namespace: namespace,
		nodeName:  nodeName,
		podName:   pod.Name,
	}
}

func waitForReplicaSetPod(
	t *testing.T,
	client kubernetes.Interface,
	namespace string,
	ownerUID types.UID,
) corev1.Pod {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=state-latch-it",
		})
		if err == nil {
			for _, pod := range pods.Items {
				for _, owner := range pod.OwnerReferences {
					if owner.UID == ownerUID && owner.Controller != nil && *owner.Controller {
						return pod
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			t.Fatalf("ReplicaSet did not create test pod: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func markPodRunningAndReady(
	t *testing.T,
	client kubernetes.Interface,
	pod corev1.Pod,
) corev1.Pod {
	t.Helper()

	now := metav1.Now()
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{
		{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: now,
		},
	}

	updated, err := client.CoreV1().Pods(pod.Namespace).UpdateStatus(
		context.Background(),
		&pod,
		metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatalf("mark test pod Running/Ready: %v", err)
	}
	return *updated
}


func newKindUnmanagedIntegrationEnv(t *testing.T, suffix string) kindIntegrationEnv {
	t.Helper()

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required for KinD integration tests")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}
	adapter, err := NewForConfigWithExperimentalMutations(config)
	if err != nil {
		t.Fatalf("build StateLatch adapter: %v", err)
	}

	namespace := "sl-it-" + suffix
	nodeName := "sl-it-node-" + suffix
	podName := "workload"
	ctx := context.Background()

	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := client.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create synthetic node: %v", err)
	}

	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: namespace},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create default service account: %v", err)
	}

	zero := int64(0)
	pod, err := client.CoreV1().Pods(namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels:    map[string]string{"app": "state-latch-real-it"},
		},
		Spec: corev1.PodSpec{
			NodeName:                      nodeName,
			ServiceAccountName:            "default",
			TerminationGracePeriodSeconds: &zero,
			Containers: []corev1.Container{
				{
					Name:  "hold",
					Image: "registry.k8s.io/pause:3.10",
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create unmanaged test pod: %v", err)
	}
	pod = ptrPod(markPodRunningAndReady(t, client, *pod))

	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
		_ = client.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
	})

	return kindIntegrationEnv{
		client:    client,
		adapter:   adapter,
		namespace: namespace,
		nodeName:  nodeName,
		podName:   pod.Name,
	}
}

func ptrPod(pod corev1.Pod) *corev1.Pod {
	return &pod
}

func integrationExecutionPolicy() NodeDrainPolicy {
	policy := integrationPolicy()
	policy.ForceUnmanagedPods = true
	policy.EvictionObservationTimeout = 10 * time.Second
	return policy
}

func integrationPolicy() NodeDrainPolicy {
	return NodeDrainPolicy{
		MaxEvidenceAge:      30 * time.Second,
		RequiredSourceCount: 1,
		MaxBlastRadius:      5,
		AuthorizationTTL:    30 * time.Second,
		IgnoreDaemonSets:    true,
	}
}

func waitForPDBStatus(
	t *testing.T,
	client kubernetes.Interface,
	namespace string,
	name string,
	ready func(*policyv1.PodDisruptionBudget) bool,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var last *policyv1.PodDisruptionBudget
	for {
		current, err := client.PolicyV1().PodDisruptionBudgets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			last = current
			if ready(current) {
				return
			}
		}

		select {
		case <-ctx.Done():
			if last == nil {
				t.Fatalf("PDB status did not become observable: %v", ctx.Err())
			}
			t.Fatalf(
				"PDB status did not converge: generation=%d observed=%d disruptionsAllowed=%d",
				last.Generation,
				last.Status.ObservedGeneration,
				last.Status.DisruptionsAllowed,
			)
		case <-ticker.C:
		}
	}
}



func TestKindD02CrashTakeoverAndClosureExercise(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "d02")
	ctx := context.Background()
	policy := integrationExecutionPolicy()
	policy.ExecutionLockNamespace = env.namespace
	policy.ExecutionLockDuration = 10 * time.Second

	zero := int64(0)
	secondPod, err := env.client.CoreV1().Pods(env.namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workload-d02-second",
			Namespace: env.namespace,
			Labels:    map[string]string{"app": "state-latch-real-it"},
		},
		Spec: corev1.PodSpec{
			NodeName:                      env.nodeName,
			ServiceAccountName:            "default",
			TerminationGracePeriodSeconds: &zero,
			Containers: []corev1.Container{
				{Name: "hold", Image: "registry.k8s.io/pause:3.10"},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create second D02 pod: %v", err)
	}
	_ = markPodRunningAndReady(t, env.client, *secondPod)

	store, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
	if err != nil {
		t.Fatalf("NewKubernetesDrainCheckpointStore returned error: %v", err)
	}

	firstReader := NewClientGoReader(env.client)
	failAfterAccepted := &failAfterAcceptedEvictionExecutor{
		delegate: firstReader,
		client:   env.client,
	}
	crashingWorker := NewWithExperimentalMutations(firstReader, failAfterAccepted)

	preparation, first := executeCheckpointedKindDrainPastPreMutationDrift(
		t,
		crashingWorker,
		"act-kind-d02",
		env.nodeName,
		policy,
		store,
	)
	if first.Decision != decision.Escalate {
		t.Fatalf("expected injected post-acceptance interruption, got %s reasons=%v", first.Decision, first.ReasonCodes)
	}
	if hasReason(first.ReasonCodes, decision.ResourceVersionChanged) {
		t.Fatalf("D02 did not reach the post-acceptance crash boundary: %v", first.ReasonCodes)
	}

	checkpoint, err := store.Load(ctx, "act-kind-d02")
	if err != nil {
		t.Fatalf("load shared checkpoint after crash: %v", err)
	}
	if checkpoint.Status != DrainExecutionPaused {
		t.Fatalf("checkpoint status after crash = %s, want PAUSED", checkpoint.Status)
	}
	if len(checkpoint.CompletedPodUIDs) != 0 {
		t.Fatalf("crash should occur before completion checkpoint, got %v", checkpoint.CompletedPodUIDs)
	}

	waitForPodNotFound(t, env.client, env.namespace, env.podName)

	// Simulate a new process taking recovery custody from the shared Kubernetes
	// checkpoint. This new adapter has no in-memory state from crashingWorker.
	recoveryReader := NewClientGoReader(env.client)
	recoveryWorker := NewWithExperimentalMutations(recoveryReader, recoveryReader)
	assessment, err := recoveryWorker.InspectDrainRecovery(
		ctx,
		"act-kind-d02",
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("InspectDrainRecovery returned error: %v", err)
	}
	if assessment.State != DrainRecoveryReauthorizationNeeded {
		t.Fatalf("recovery state = %s, want REAUTHORIZATION_REQUIRED reasons=%v", assessment.State, assessment.ReasonCodes)
	}
	if len(assessment.ReconciledPodUIDs) != 1 {
		t.Fatalf("accepted pre-crash eviction was not reconciled: %v", assessment.ReconciledPodUIDs)
	}
	if len(assessment.RemainingPods) != 1 ||
		assessment.RemainingPods[0].Name != "workload-d02-second" {
		t.Fatalf("unexpected D02 remainder: %+v", assessment.RemainingPods)
	}

	// Manual takeover owns the real Kubernetes Lease. A stale worker carrying
	// the old authorization cannot create another effect while that fence is held.
	takeoverLease, err := recoveryReader.AcquireExecutionLock(
		ctx,
		policy.ExecutionLockNamespace,
		"node/"+env.nodeName,
		"d02-manual-takeover-owner",
		policy.ExecutionLockDuration,
	)
	if err != nil {
		t.Fatalf("AcquireExecutionLock for takeover: %v", err)
	}

	staleWhileFenced, err := crashingWorker.ResumeAuthorizedNodeDrain(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("stale ResumeAuthorizedNodeDrain returned error: %v", err)
	}
	if staleWhileFenced.Decision != decision.Escalate ||
		!hasReason(staleWhileFenced.ReasonCodes, ReasonExecutionLockHeld) {
		t.Fatalf("stale worker was not fenced: decision=%s reasons=%v", staleWhileFenced.Decision, staleWhileFenced.ReasonCodes)
	}
	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		"workload-d02-second",
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("fenced stale worker changed remaining target: %v", err)
	}

	if err := recoveryReader.ReleaseExecutionLock(ctx, takeoverLease); err != nil {
		t.Fatalf("ReleaseExecutionLock after takeover: %v", err)
	}

	// Losing the takeover fence does not make stale authority current again.
	oldAuthorization, err := crashingWorker.ResumeAuthorizedNodeDrain(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("old authorization resume returned error: %v", err)
	}
	if oldAuthorization.Decision == decision.Allow {
		t.Fatal("old pre-crash authorization unexpectedly resumed the changed remainder")
	}
	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		"workload-d02-second",
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("old authorization changed remaining target: %v", err)
	}

	fresh := prepareKindDrainWithFreshAuthorization(
		t,
		recoveryWorker,
		"act-kind-d02",
		env.nodeName,
		policy,
	)
	resumed, err := recoveryWorker.ResumeAuthorizedNodeDrain(
		ctx,
		*fresh.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatalf("fresh takeover resume returned error: %v", err)
	}
	if resumed.Decision != decision.Allow {
		t.Fatalf("fresh takeover resume = %s reasons=%v", resumed.Decision, resumed.ReasonCodes)
	}
	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		"workload-d02-second",
		metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("remaining pod was not closed by fresh takeover: err=%v", err)
	}

	checkpoint, err = store.Load(ctx, "act-kind-d02")
	if err != nil {
		t.Fatalf("load completed shared checkpoint: %v", err)
	}
	if checkpoint.Status != DrainExecutionCompleted ||
		len(checkpoint.CompletedPodUIDs) != 2 {
		t.Fatalf("completed checkpoint = %+v", checkpoint)
	}

	// Prove the checkpoint store's claimed CAS boundary is the Kubernetes
	// resourceVersion, not a local observation.
	casBase, err := store.SaveVersioned(ctx, DrainExecutionCheckpoint{
		ActionID:     "act-kind-d02-cas",
		NodeName:     env.nodeName,
		NodeUID:      "d02-cas-node",
		NodeHealth:   "healthy",
		Status:       DrainExecutionPaused,
		LastDecision: decision.Escalate,
		UpdatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create CAS checkpoint: %v", err)
	}
	left := casBase
	right := casBase
	left.LastDecision = decision.Allow
	if _, err := store.SaveVersioned(ctx, left); err != nil {
		t.Fatalf("first CAS update failed: %v", err)
	}
	right.LastDecision = decision.Block
	if _, err := store.SaveVersioned(ctx, right); !IsDrainCheckpointConflict(err) {
		t.Fatalf("stale CAS update error = %v, want checkpoint conflict", err)
	}
}
