//go:build integration

package kubeadapter

import (
	"context"
	"testing"
	"time"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/achirothmane/aegis-ege/internal/epistemic"
)

func TestKindPDBChangePropagatesToHigherLevelDrainAssumption(t *testing.T) {
	env := newKindIntegrationEnv(t, "m3-pdb-graph")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	one := intstr.FromInt(1)
	pdb, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Create(
		ctx,
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-budget",
				Namespace: env.namespace,
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &one,
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
		return current.Status.ObservedGeneration == current.Generation
	})

	events := make(chan epistemic.ResourceEvent, 16)
	synced := make(chan struct{})
	errCh := make(chan error, 1)
	watcher := &PDBInvalidationWatcher{
		Client:    env.client,
		Namespace: env.namespace,
		Name:      pdb.Name,
	}
	go func() {
		errCh <- watcher.Run(ctx, events, synced)
	}()

	select {
	case <-synced:
	case <-time.After(10 * time.Second):
		t.Fatal("PDB informer did not sync")
	}

	currentPDB, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Get(
		ctx,
		pdb.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get PDB after informer sync: %v", err)
	}
	nodeBefore, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node before indirect dependency change: %v", err)
	}

	tracker := epistemic.NewTracker()
	tracker.PutAssumption(epistemic.Assumption{
		ID:        "A-PDB-SAFE",
		Statement: "PDB state permits the planned disruption",
		Status:    epistemic.AssumptionSupported,
		Dependencies: []epistemic.ResourceRef{{
			APIVersion:      "policy/v1",
			Kind:            "PodDisruptionBudget",
			Namespace:       currentPDB.Namespace,
			Name:            currentPDB.Name,
			UID:             string(currentPDB.UID),
			ResourceVersion: currentPDB.ResourceVersion,
		}},
		EvaluatedAt: time.Now().UTC(),
	})
	tracker.PutAssumption(epistemic.Assumption{
		ID:                     "A-DRAIN-SAFE",
		Statement:              "node drain remains safe",
		Status:                 epistemic.AssumptionSupported,
		AssumptionDependencies: []string{"A-PDB-SAFE"},
		EvaluatedAt:            time.Now().UTC(),
	})

	patch := []byte(`{"metadata":{"annotations":{"state-latch.dev/m3":"changed"}}}`)
	after, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Patch(
		ctx,
		pdb.Name,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	if err != nil {
		t.Fatalf("patch PDB: %v", err)
	}
	if after.ResourceVersion == currentPDB.ResourceVersion {
		t.Fatalf("expected PDB resourceVersion to change, remained %q", after.ResourceVersion)
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
			t.Fatalf("watch did not observe patched PDB resourceVersion %q", after.ResourceVersion)
		}
	}

	results := tracker.Handle(observed)
	if len(results) != 2 {
		t.Fatalf("expected direct and propagated invalidation, got %+v", results)
	}

	pdbAssumption, ok := tracker.GetAssumption("A-PDB-SAFE")
	if !ok || pdbAssumption.Status != epistemic.AssumptionInvalidated {
		t.Fatalf("expected PDB assumption invalidated, got %+v ok=%v", pdbAssumption, ok)
	}
	if pdbAssumption.Invalidation == nil ||
		pdbAssumption.Invalidation.Cause != epistemic.CauseResourceVersionChanged {
		t.Fatalf("unexpected direct invalidation: %+v", pdbAssumption.Invalidation)
	}

	drainAssumption, ok := tracker.GetAssumption("A-DRAIN-SAFE")
	if !ok || drainAssumption.Status != epistemic.AssumptionInvalidated {
		t.Fatalf("expected higher-level drain assumption invalidated, got %+v ok=%v", drainAssumption, ok)
	}
	if drainAssumption.Invalidation == nil ||
		drainAssumption.Invalidation.Cause != epistemic.CauseUpstreamAssumptionInvalidated ||
		drainAssumption.Invalidation.UpstreamAssumptionID != "A-PDB-SAFE" {
		t.Fatalf("unexpected propagated invalidation: %+v", drainAssumption.Invalidation)
	}
	if drainAssumption.Invalidation.RootDependencyKey != pdbResourceRef(after).Key() {
		t.Fatalf(
			"expected root cause %q, got %+v",
			pdbResourceRef(after).Key(),
			drainAssumption.Invalidation,
		)
	}
	if drainAssumption.Invalidation.OldResourceVersion != currentPDB.ResourceVersion ||
		drainAssumption.Invalidation.NewResourceVersion != after.ResourceVersion {
		t.Fatalf(
			"expected root causal transition %s -> %s, got %+v",
			currentPDB.ResourceVersion,
			after.ResourceVersion,
			drainAssumption.Invalidation,
		)
	}

	nodeAfter, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after indirect dependency change: %v", err)
	}
	if nodeAfter.ResourceVersion != nodeBefore.ResourceVersion {
		t.Fatalf(
			"proof requires unchanged target node; resourceVersion changed %s -> %s",
			nodeBefore.ResourceVersion,
			nodeAfter.ResourceVersion,
		)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("PDB watcher returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PDB watcher did not stop after cancellation")
	}
}
