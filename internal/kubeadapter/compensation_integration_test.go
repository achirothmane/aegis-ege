//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKindM11OwnedCordonCanBeSafelyCompensated(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m11-safe-comp")
	ctx := context.Background()
	policy := integrationExecutionPolicy()
	store := NewMemoryDrainCheckpointStore()

	reader := NewClientGoReader(env.client)
	executor := &failBeforeEvictionCompensationExecutor{delegate: reader}
	adapter := NewWithExperimentalMutations(reader, executor)

	preparation := prepareKindDrainWithFreshAuthorization(
		t,
		adapter,
		"m11-safe-comp",
		env.nodeName,
		policy,
	)
	report, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision != "ESCALATE" {
		t.Fatalf("expected injected eviction failure ESCALATE, got %+v", report)
	}

	checkpoint, err := store.Load(ctx, "m11-safe-comp")
	if err != nil {
		t.Fatal(err)
	}
	if !checkpoint.CordonOwned || !checkpoint.Cordoned || checkpoint.OriginallyUnschedulable {
		t.Fatalf("checkpoint did not prove owned cordon: %+v", checkpoint)
	}

	assessment, err := adapter.InspectDrainCompensation(
		ctx,
		"m11-safe-comp",
		env.nodeName,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.State != DrainCompensationReady {
		t.Fatalf("expected READY compensation, got %+v", assessment)
	}

	applied, err := adapter.CompensateNodeDrain(
		ctx,
		"m11-safe-comp",
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != DrainCompensationApplied {
		t.Fatalf("expected APPLIED compensation, got %+v", applied)
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("compensation did not uncordon the node")
	}

	checkpoint, err = store.Load(ctx, "m11-safe-comp")
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Status != DrainExecutionCompensated || checkpoint.Cordoned {
		t.Fatalf("checkpoint did not persist compensation: %+v", checkpoint)
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		env.podName,
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("workload should still exist because failed eviction was never retried: %v", err)
	}
}

func TestKindM11CompensationNeverRecreatesAcceptedEviction(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m11-no-recreate")
	ctx := context.Background()
	policy := integrationExecutionPolicy()
	store := NewMemoryDrainCheckpointStore()

	zero := int64(0)
	secondPod, err := env.client.CoreV1().Pods(env.namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "m11-remaining",
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
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = markPodRunningAndReady(t, env.client, *secondPod)

	reader := NewClientGoReader(env.client)
	executor := &failAfterAcceptedCompensationExecutor{
		failAfterAcceptedEvictionExecutor: failAfterAcceptedEvictionExecutor{
			delegate: reader,
			client:   env.client,
		},
	}
	adapter := NewWithExperimentalMutations(reader, executor)

	preparation, first := executeCheckpointedKindDrainPastPreMutationDrift(
		t,
		adapter,
		"m11-no-recreate",
		env.nodeName,
		policy,
		store,
	)
	if preparation.Authorization == nil || first.Decision != "ESCALATE" {
		t.Fatalf("expected accepted eviction interruption, prep=%+v report=%+v", preparation, first)
	}
	waitForPodNotFound(t, env.client, env.namespace, env.podName)

	applied, err := adapter.CompensateNodeDrain(
		ctx,
		"m11-no-recreate",
		env.nodeName,
		policy,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != DrainCompensationApplied {
		t.Fatalf("expected compensation after partial eviction, got %+v", applied)
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		env.podName,
		metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("StateLatch must never recreate an evicted Pod; got err=%v", err)
	}
	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		ctx,
		"m11-remaining",
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("remaining workload unexpectedly disappeared: %v", err)
	}
}

func TestKindM11UnexpectedWorkloadBlocksCompensation(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m11-drift-block")
	ctx := context.Background()
	policy := integrationExecutionPolicy()
	store := NewMemoryDrainCheckpointStore()

	reader := NewClientGoReader(env.client)
	executor := &failBeforeEvictionCompensationExecutor{delegate: reader}
	adapter := NewWithExperimentalMutations(reader, executor)

	preparation := prepareKindDrainWithFreshAuthorization(
		t,
		adapter,
		"m11-drift-block",
		env.nodeName,
		policy,
	)
	report, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		policy,
		store,
	)
	if err != nil || report.Decision != "ESCALATE" {
		t.Fatalf("failed to create paused owned-cordon state: report=%+v err=%v", report, err)
	}

	zero := int64(0)
	unexpected, err := env.client.CoreV1().Pods(env.namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "m11-unexpected",
			Namespace: env.namespace,
			Labels:    map[string]string{"app": "unexpected"},
		},
		Spec: corev1.PodSpec{
			NodeName:                      env.nodeName,
			TerminationGracePeriodSeconds: &zero,
			Containers: []corev1.Container{{
				Name:  "hold",
				Image: "registry.k8s.io/pause:3.10",
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = markPodRunningAndReady(t, env.client, *unexpected)

	assessment, err := adapter.InspectDrainCompensation(
		ctx,
		"m11-drift-block",
		env.nodeName,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.State != DrainCompensationBlocked ||
		!hasReason(assessment.ReasonCodes, ReasonCompensationUnexpectedWorkload) {
		t.Fatalf("unexpected workload must block compensation, got %+v", assessment)
	}

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Spec.Unschedulable {
		t.Fatal("blocked compensation unexpectedly uncordoned node")
	}
}

type failBeforeEvictionCompensationExecutor struct {
	delegate *ClientGoReader
}

func (e *failBeforeEvictionCompensationExecutor) DryRunCordonNode(
	ctx context.Context,
	nodeName string,
	resourceVersion string,
) error {
	return e.delegate.DryRunCordonNode(ctx, nodeName, resourceVersion)
}

func (e *failBeforeEvictionCompensationExecutor) DryRunEvictPod(
	ctx context.Context,
	pod PodStateRef,
) error {
	return e.delegate.DryRunEvictPod(ctx, pod)
}

func (e *failBeforeEvictionCompensationExecutor) CordonNode(
	ctx context.Context,
	nodeName string,
	resourceVersion string,
) error {
	return e.delegate.CordonNode(ctx, nodeName, resourceVersion)
}

func (e *failBeforeEvictionCompensationExecutor) EvictPod(
	context.Context,
	PodStateRef,
) error {
	return fmt.Errorf("injected pre-eviction failure")
}

func (e *failBeforeEvictionCompensationExecutor) UncordonNode(
	ctx context.Context,
	nodeName string,
	resourceVersion string,
) error {
	return e.delegate.UncordonNode(ctx, nodeName, resourceVersion)
}

type failAfterAcceptedCompensationExecutor struct {
	failAfterAcceptedEvictionExecutor
}

func (e *failAfterAcceptedCompensationExecutor) UncordonNode(
	ctx context.Context,
	nodeName string,
	resourceVersion string,
) error {
	return e.delegate.UncordonNode(ctx, nodeName, resourceVersion)
}
