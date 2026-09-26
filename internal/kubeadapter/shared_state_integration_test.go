//go:build integration

package kubeadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestKindM9SharedCheckpointStoreRejectsStaleReplicaWrite(t *testing.T) {
	env := newKindIntegrationEnv(t, "m9-cas")
	ctx := context.Background()

	storeA, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
	if err != nil {
		t.Fatal(err)
	}

	initial, err := storeA.SaveVersioned(ctx, DrainExecutionCheckpoint{
		ActionID:     "m9-cas-action",
		NodeName:     env.nodeName,
		NodeUID:      "node-uid",
		NodeHealth:   "healthy",
		Status:       DrainExecutionRunning,
		LastDecision: decision.Allow,
		UpdatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("initial shared save: %v", err)
	}
	if initial.StoreVersion == "" {
		t.Fatal("shared checkpoint did not return Kubernetes resourceVersion")
	}

	replicaA, err := storeA.Load(ctx, initial.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	replicaB, err := storeB.Load(ctx, initial.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if replicaA.StoreVersion != replicaB.StoreVersion {
		t.Fatalf("replicas did not observe same starting version: A=%q B=%q", replicaA.StoreVersion, replicaB.StoreVersion)
	}

	replicaB.Cordoned = true
	replicaB.UpdatedAt = time.Now().UTC()
	updatedB, err := storeB.SaveVersioned(ctx, replicaB)
	if err != nil {
		t.Fatalf("replica B update: %v", err)
	}
	if updatedB.StoreVersion == replicaA.StoreVersion {
		t.Fatal("Kubernetes resourceVersion did not advance")
	}

	replicaA.Status = DrainExecutionPaused
	replicaA.UpdatedAt = time.Now().UTC()
	if _, err := storeA.SaveVersioned(ctx, replicaA); !errors.Is(err, ErrDrainCheckpointConflict) {
		t.Fatalf("stale replica write must conflict, got %v", err)
	}

	final, err := storeA.Load(ctx, initial.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if !final.Cordoned || final.Status != DrainExecutionRunning {
		t.Fatalf("stale write overwrote newer shared state: %+v", final)
	}
}

func TestKindM9SecondReplicaRecoversPartialDrainFromSharedCheckpoint(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m9-recovery")
	ctx := context.Background()
	policy := integrationExecutionPolicy()

	zero := int64(0)
	secondPod, err := env.client.CoreV1().Pods(env.namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workload-m9-z",
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
		t.Fatalf("create second recovery pod: %v", err)
	}
	_ = markPodRunningAndReady(t, env.client, *secondPod)

	storeReplicaA, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
	if err != nil {
		t.Fatal(err)
	}
	storeReplicaB, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
	if err != nil {
		t.Fatal(err)
	}

	readerA := NewClientGoReader(env.client)
	failAfterAccepted := &failAfterAcceptedEvictionExecutor{
		delegate: readerA,
		client:   env.client,
	}
	replicaA := NewWithExperimentalMutations(readerA, failAfterAccepted)

	preparation, first := executeCheckpointedKindDrainPastPreMutationDrift(
		t,
		replicaA,
		"act-kind-m9-ha-recovery",
		env.nodeName,
		policy,
		storeReplicaA,
	)
	if first.Decision != decision.Escalate {
		t.Fatalf("expected injected partial execution ESCALATE, got %s reasons=%v", first.Decision, first.ReasonCodes)
	}
	if preparation.Authorization == nil {
		t.Fatal("expected initial authorization")
	}

	waitForPodNotFound(t, env.client, env.namespace, env.podName)

	// env.adapter is a distinct adapter instance. It reconstructs recovery from
	// the shared Kubernetes checkpoint rather than any process-local state.
	assessment, err := env.adapter.InspectDrainRecovery(
		ctx,
		"act-kind-m9-ha-recovery",
		env.nodeName,
		policy,
		storeReplicaB,
	)
	if err != nil {
		t.Fatalf("second replica InspectDrainRecovery: %v", err)
	}
	if assessment.State != DrainRecoveryReauthorizationNeeded {
		t.Fatalf("expected shared recovery to require reauthorization, got %s reasons=%v", assessment.State, assessment.ReasonCodes)
	}
	if len(assessment.RemainingPods) != 1 || assessment.RemainingPods[0].Name != "workload-m9-z" {
		t.Fatalf("unexpected shared recovery remainder: %+v", assessment.RemainingPods)
	}

	fresh := prepareKindDrainWithFreshAuthorization(
		t,
		env.adapter,
		"act-kind-m9-ha-recovery",
		env.nodeName,
		policy,
	)
	resumed, err := env.adapter.ResumeAuthorizedNodeDrain(
		ctx,
		*fresh.Authorization,
		env.nodeName,
		policy,
		storeReplicaB,
	)
	if err != nil {
		t.Fatalf("second replica ResumeAuthorizedNodeDrain: %v", err)
	}
	if resumed.Decision != decision.Allow {
		t.Fatalf("expected shared recovery ALLOW, got %s reasons=%v", resumed.Decision, resumed.ReasonCodes)
	}

	completed, err := storeReplicaA.Load(ctx, "act-kind-m9-ha-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != DrainExecutionCompleted || len(completed.CompletedPodUIDs) != 2 {
		t.Fatalf("shared checkpoint did not converge to completed state: %+v", completed)
	}
}
