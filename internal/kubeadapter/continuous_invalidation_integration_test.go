//go:build integration

package kubeadapter

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/achirothmane/state-latch/internal/epistemic"
)

func TestKindContinuousWatchInvalidatesDeploymentAssumption(t *testing.T) {
	env := newKindIntegrationEnv(t, "continuous-invalidation")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	zero := int32(0)
	deployment, err := env.client.AppsV1().Deployments(env.namespace).Create(
		ctx,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "epistemic-target",
				Namespace: env.namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &zero,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "epistemic-target"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "epistemic-target"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:  "pause",
							Image: "registry.k8s.io/pause:3.10",
						}},
					},
				},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("create deployment: %v", err)
	}

	events := make(chan epistemic.ResourceEvent, 16)
	synced := make(chan struct{})
	errCh := make(chan error, 1)
	watcher := &DeploymentInvalidationWatcher{
		Client:    env.client,
		Namespace: env.namespace,
		Name:      deployment.Name,
	}
	go func() {
		errCh <- watcher.Run(ctx, events, synced)
	}()

	select {
	case <-synced:
	case <-time.After(10 * time.Second):
		t.Fatal("deployment informer did not sync")
	}

	current, err := env.client.AppsV1().Deployments(env.namespace).Get(
		ctx,
		deployment.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get deployment after informer sync: %v", err)
	}

	tracker := epistemic.NewTracker()
	tracker.PutAssumption(epistemic.Assumption{
		ID:        "A-KIND-M0",
		Statement: "deployment state remains valid for a consequential action",
		Status:    epistemic.AssumptionSupported,
		Dependencies: []epistemic.ResourceRef{{
			APIVersion:      "apps/v1",
			Kind:            "Deployment",
			Namespace:       current.Namespace,
			Name:            current.Name,
			UID:             string(current.UID),
			ResourceVersion: current.ResourceVersion,
		}},
		EvaluatedAt: time.Now().UTC(),
	})

	patch := []byte(`{"metadata":{"annotations":{"state-latch.dev/m0":"changed"}}}`)
	after, err := env.client.AppsV1().Deployments(env.namespace).Patch(
		ctx,
		deployment.Name,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	if err != nil {
		t.Fatalf("patch deployment to create live state change: %v", err)
	}
	if after.ResourceVersion == current.ResourceVersion {
		t.Fatalf("expected resourceVersion to change, remained %q", after.ResourceVersion)
	}

	var observed epistemic.ResourceEvent
	deadline := time.After(10 * time.Second)
	for observed.Resource.ResourceVersion != after.ResourceVersion {
		select {
		case event := <-events:
			if event.Resource.ResourceVersion == after.ResourceVersion {
				observed = event
			}
		case <-deadline:
			t.Fatalf("watch did not observe patched resourceVersion %q", after.ResourceVersion)
		}
	}

	results := tracker.Handle(observed)
	if len(results) != 1 || !results[0].Changed {
		t.Fatalf("expected live watch event to invalidate assumption, got %+v", results)
	}

	assumption, ok := tracker.GetAssumption("A-KIND-M0")
	if !ok {
		t.Fatal("tracked assumption disappeared")
	}
	if assumption.Status != epistemic.AssumptionInvalidated {
		t.Fatalf("expected INVALIDATED, got %s", assumption.Status)
	}
	if assumption.Invalidation == nil {
		t.Fatal("expected causal invalidation record")
	}
	if assumption.Invalidation.Cause != epistemic.CauseResourceVersionChanged {
		t.Fatalf(
			"expected %s, got %+v",
			epistemic.CauseResourceVersionChanged,
			assumption.Invalidation,
		)
	}
	if assumption.Invalidation.OldResourceVersion != current.ResourceVersion ||
		assumption.Invalidation.NewResourceVersion != after.ResourceVersion {
		t.Fatalf(
			"expected causal resourceVersion transition %s -> %s, got %+v",
			current.ResourceVersion,
			after.ResourceVersion,
			assumption.Invalidation,
		)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("watcher returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop after cancellation")
	}
}
