//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/outcome"
)

// Replay source: kubernetes/kubernetes#117843
// Pods with spec.nodeName can appear on a cordoned/drained node because direct
// node binding bypasses normal scheduler placement checks.
func TestKindIncidentReplay117843DirectNodeNamePodAfterDrain(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "v3-117843")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	preparation, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		env.adapter,
		"incident-117843",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Allow ||
		preparation.Authorization == nil ||
		preparation.Plan == nil {
		t.Fatalf(
			"expected successful guarded drain before incident replay, decision=%s reasons=%v",
			report.Decision,
			report.ReasonCodes,
		)
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get drained node: %v", err)
	}
	if !node.Spec.Unschedulable {
		t.Fatal("replay requires node to remain cordoned")
	}

	zero := int64(0)
	latePod, err := env.client.CoreV1().Pods(env.namespace).Create(
		ctx,
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "late-node-name-pod",
				Namespace: env.namespace,
				Labels:    map[string]string{"app": "incident-117843"},
			},
			Spec: corev1.PodSpec{
				NodeName:                      env.nodeName,
				ServiceAccountName:            "default",
				TerminationGracePeriodSeconds: &zero,
				Containers: []corev1.Container{{
					Name:  "hold",
					Image: "registry.k8s.io/pause:3.10",
				}},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("create direct-nodeName pod on cordoned node: %v", err)
	}
	if latePod.Spec.NodeName != env.nodeName {
		t.Fatalf("expected late pod bound to drained node, got %q", latePod.Spec.NodeName)
	}

	record, err := env.adapter.ObserveDrainOutcome(
		ctx,
		*preparation.Authorization,
		*preparation.Plan,
		[]outcome.Contributor{
			{Kind: outcome.ContributorSource, ID: "kubernetes-api"},
			{Kind: outcome.ContributorAssumption, ID: "A-DRAIN-SAFE"},
		},
	)
	if err != nil {
		t.Fatalf("ObserveDrainOutcome: %v", err)
	}
	if record.Verdict != outcome.Diverged {
		t.Fatalf(
			"incident #117843 replay: a new non-daemon workload exists on the drained node; expected DIVERGED, got %+v",
			record,
		)
	}
}

// Replay source class: kubernetes/kubernetes#59848.
// The historical issue is about stale reads and identity safety: a Pod with the
// same name but a new UID must not satisfy state captured for the old object.
func TestKindIncidentReplay59848SameNameNewUIDInvalidatesAuthorization(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "v3-59848")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	preparation := prepareKindDrainWithFreshAuthorization(
		t,
		env.adapter,
		"incident-59848",
		env.nodeName,
		policy,
	)
	if preparation.Authorization == nil {
		t.Fatal("expected initial authorization")
	}

	original, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		env.podName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get original pod: %v", err)
	}
	originalUID := original.UID

	if err := env.client.CoreV1().Pods(env.namespace).Delete(
		ctx,
		env.podName,
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatalf("delete original pod: %v", err)
	}
	waitForPodNotFound(t, env.client, env.namespace, env.podName)

	zero := int64(0)
	recreated, err := env.client.CoreV1().Pods(env.namespace).Create(
		ctx,
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      env.podName,
				Namespace: env.namespace,
				Labels:    map[string]string{"app": "state-latch-real-it"},
			},
			Spec: corev1.PodSpec{
				NodeName:                      env.nodeName,
				ServiceAccountName:            "default",
				TerminationGracePeriodSeconds: &zero,
				Containers: []corev1.Container{{
					Name:  "hold",
					Image: "registry.k8s.io/pause:3.10",
				}},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("recreate same-name pod: %v", err)
	}
	recreated = ptrPod(markPodRunningAndReady(t, env.client, *recreated))
	if recreated.UID == originalUID {
		t.Fatalf("replay requires a new UID; remained %s", recreated.UID)
	}

	revalidation, err := env.adapter.RevalidateNodeDrainAuthorization(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
	)
	if err != nil {
		t.Fatalf("RevalidateNodeDrainAuthorization: %v", err)
	}
	if revalidation.Decision != decision.Escalate ||
		!hasReason(revalidation.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf(
			"same-name new-UID object must invalidate prior authorization; got %s reasons=%v",
			revalidation.Decision,
			revalidation.ReasonCodes,
		)
	}
}

// Replay source: kubernetes/kubectl#1568.
// The reported drain flow continued to pod eviction after cordon was rejected.
// StateLatch must treat the cordon failure as a hard execution boundary.
func TestKindIncidentReplayKubectl1568CordonDenialStopsEvictions(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "v3-1568")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	reader := NewClientGoReader(env.client)
	executor := &cordonDeniedReplayExecutor{delegate: reader}
	adapter := NewWithExperimentalMutations(reader, executor)

	preparation := prepareKindDrainWithFreshAuthorization(
		t,
		adapter,
		"incident-1568",
		env.nodeName,
		policy,
	)
	if preparation.Authorization == nil {
		t.Fatal("expected preparation authorization before injected cordon denial")
	}

	report, err := adapter.ExecuteAuthorizedNodeDrain(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
	)
	if err != nil {
		t.Fatalf("ExecuteAuthorizedNodeDrain: %v", err)
	}
	if report.Decision != decision.Escalate ||
		!hasReason(report.ReasonCodes, ReasonExecutionCordonRejected) {
		t.Fatalf(
			"cordon denial must stop execution, got %s reasons=%v steps=%+v",
			report.Decision,
			report.ReasonCodes,
			report.Steps,
		)
	}
	if executor.evictions != 0 {
		t.Fatalf("incident replay: no pod eviction may occur after cordon denial; got %d", executor.evictions)
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after denied cordon: %v", err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("injected denial should leave node schedulable")
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		env.podName,
		metav1.GetOptions{},
	); err != nil {
		if apierrors.IsNotFound(err) {
			t.Fatal("pod was evicted despite cordon denial")
		}
		t.Fatalf("get workload after denied cordon: %v", err)
	}
}

type cordonDeniedReplayExecutor struct {
	delegate  *ClientGoReader
	evictions int
}

func (e *cordonDeniedReplayExecutor) DryRunCordonNode(
	ctx context.Context,
	nodeName string,
	resourceVersion string,
) error {
	return e.delegate.DryRunCordonNode(ctx, nodeName, resourceVersion)
}

func (e *cordonDeniedReplayExecutor) DryRunEvictPod(
	ctx context.Context,
	pod PodStateRef,
) error {
	return e.delegate.DryRunEvictPod(ctx, pod)
}

func (e *cordonDeniedReplayExecutor) CordonNode(
	context.Context,
	string,
	string,
) error {
	return fmt.Errorf("injected admission denial from incident replay")
}

func (e *cordonDeniedReplayExecutor) EvictPod(
	ctx context.Context,
	pod PodStateRef,
) error {
	e.evictions++
	return e.delegate.EvictPod(ctx, pod)
}
