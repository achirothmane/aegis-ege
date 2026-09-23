package epistemic

import (
	"testing"
	"time"
)

func TestDependencyGraphPropagatesResourceInvalidation(t *testing.T) {
	tracker := NewTracker()
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)

	pdb := ResourceRef{
		APIVersion:      "policy/v1",
		Kind:            "PodDisruptionBudget",
		Namespace:       "production",
		Name:            "api-budget",
		UID:             "pdb-uid",
		ResourceVersion: "10",
	}
	tracker.PutAssumption(Assumption{
		ID:           "A-PDB",
		Statement:    "PDB permits the planned disruption",
		Status:       AssumptionSupported,
		Dependencies: []ResourceRef{pdb},
		EvaluatedAt:  now,
	})
	tracker.PutAssumption(Assumption{
		ID:                     "A-DRAIN",
		Statement:              "node drain is safe",
		Status:                 AssumptionSupported,
		AssumptionDependencies: []string{"A-PDB"},
		EvaluatedAt:            now,
	})

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion:      pdb.APIVersion,
			Kind:            pdb.Kind,
			Namespace:       pdb.Namespace,
			Name:            pdb.Name,
			UID:             pdb.UID,
			ResourceVersion: "11",
		},
		At: now.Add(time.Second),
	})

	if len(results) != 2 {
		t.Fatalf("expected direct + propagated invalidation, got %+v", results)
	}

	direct, _ := tracker.GetAssumption("A-PDB")
	if direct.Status != AssumptionInvalidated {
		t.Fatalf("expected A-PDB invalidated, got %+v", direct)
	}
	if direct.Invalidation == nil || direct.Invalidation.Cause != CauseResourceVersionChanged {
		t.Fatalf("expected direct resourceVersion invalidation, got %+v", direct.Invalidation)
	}

	downstream, _ := tracker.GetAssumption("A-DRAIN")
	if downstream.Status != AssumptionInvalidated {
		t.Fatalf("expected A-DRAIN invalidated through dependency graph, got %+v", downstream)
	}
	if downstream.Invalidation == nil ||
		downstream.Invalidation.Cause != CauseUpstreamAssumptionInvalidated ||
		downstream.Invalidation.UpstreamAssumptionID != "A-PDB" {
		t.Fatalf("unexpected propagated invalidation: %+v", downstream.Invalidation)
	}
	if downstream.Invalidation.RootDependencyKey != pdb.Key() {
		t.Fatalf("expected root dependency %q, got %+v", pdb.Key(), downstream.Invalidation)
	}
}

func TestDependencyGraphPropagatesAcrossMultipleLevels(t *testing.T) {
	tracker := NewTracker()
	now := time.Now().UTC()
	resource := ResourceRef{
		APIVersion: "v1", Kind: "Service", Namespace: "production", Name: "api",
		UID: "svc-1", ResourceVersion: "1",
	}

	tracker.PutAssumption(Assumption{
		ID: "A-SERVICE", Status: AssumptionSupported,
		Dependencies: []ResourceRef{resource},
	})
	tracker.PutAssumption(Assumption{
		ID: "A-ROUTING", Status: AssumptionSupported,
		AssumptionDependencies: []string{"A-SERVICE"},
	})
	tracker.PutAssumption(Assumption{
		ID: "A-MUTATION", Status: AssumptionSupported,
		AssumptionDependencies: []string{"A-ROUTING"},
	})

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: resource.APIVersion, Kind: resource.Kind,
			Namespace: resource.Namespace, Name: resource.Name,
			UID: resource.UID, ResourceVersion: "2",
		},
		At: now,
	})

	if len(results) != 3 {
		t.Fatalf("expected three invalidations across chain, got %+v", results)
	}
	for _, id := range []string{"A-SERVICE", "A-ROUTING", "A-MUTATION"} {
		a, ok := tracker.GetAssumption(id)
		if !ok || a.Status != AssumptionInvalidated {
			t.Fatalf("expected %s invalidated, got %+v ok=%v", id, a, ok)
		}
	}
}

func TestDependencyGraphDoesNotInvalidateSibling(t *testing.T) {
	tracker := NewTracker()
	resource := ResourceRef{
		APIVersion: "v1", Kind: "Service", Namespace: "production", Name: "api",
		UID: "svc-1", ResourceVersion: "1",
	}
	tracker.PutAssumption(Assumption{
		ID: "A-SERVICE", Status: AssumptionSupported,
		Dependencies: []ResourceRef{resource},
	})
	tracker.PutAssumption(Assumption{
		ID: "A-DEPENDENT", Status: AssumptionSupported,
		AssumptionDependencies: []string{"A-SERVICE"},
	})
	tracker.PutAssumption(Assumption{
		ID: "A-UNRELATED", Status: AssumptionSupported,
	})

	tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: resource.APIVersion, Kind: resource.Kind,
			Namespace: resource.Namespace, Name: resource.Name,
			UID: resource.UID, ResourceVersion: "2",
		},
		At: time.Now().UTC(),
	})

	unrelated, _ := tracker.GetAssumption("A-UNRELATED")
	if unrelated.Status != AssumptionSupported {
		t.Fatalf("unrelated assumption must remain supported, got %+v", unrelated)
	}
}

func TestDependencyGraphCycleDoesNotLoop(t *testing.T) {
	tracker := NewTracker()
	resource := ResourceRef{
		APIVersion: "v1", Kind: "ConfigMap", Namespace: "production", Name: "config",
		UID: "cm-1", ResourceVersion: "1",
	}
	tracker.PutAssumption(Assumption{
		ID: "A", Status: AssumptionSupported,
		Dependencies: []ResourceRef{resource},
		AssumptionDependencies: []string{"B"},
	})
	tracker.PutAssumption(Assumption{
		ID: "B", Status: AssumptionSupported,
		AssumptionDependencies: []string{"A"},
	})

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: resource.APIVersion, Kind: resource.Kind,
			Namespace: resource.Namespace, Name: resource.Name,
			UID: resource.UID, ResourceVersion: "2",
		},
		At: time.Now().UTC(),
	})

	if len(results) != 2 {
		t.Fatalf("expected each assumption invalidated once despite cycle, got %+v", results)
	}
}

func TestReplacingAssumptionUpdatesAssumptionReverseEdges(t *testing.T) {
	tracker := NewTracker()
	tracker.PutAssumption(Assumption{
		ID: "UPSTREAM-A", Status: AssumptionSupported,
		Dependencies: []ResourceRef{{
			APIVersion: "v1", Kind: "ConfigMap", Namespace: "prod", Name: "a",
			UID: "a", ResourceVersion: "1",
		}},
	})
	tracker.PutAssumption(Assumption{
		ID: "UPSTREAM-B", Status: AssumptionSupported,
		Dependencies: []ResourceRef{{
			APIVersion: "v1", Kind: "ConfigMap", Namespace: "prod", Name: "b",
			UID: "b", ResourceVersion: "1",
		}},
	})
	tracker.PutAssumption(Assumption{
		ID: "DOWNSTREAM", Status: AssumptionSupported,
		AssumptionDependencies: []string{"UPSTREAM-A"},
	})
	tracker.PutAssumption(Assumption{
		ID: "DOWNSTREAM", Status: AssumptionSupported,
		AssumptionDependencies: []string{"UPSTREAM-B"},
	})

	tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: "v1", Kind: "ConfigMap", Namespace: "prod", Name: "a",
			UID: "a", ResourceVersion: "2",
		},
		At: time.Now().UTC(),
	})

	downstream, _ := tracker.GetAssumption("DOWNSTREAM")
	if downstream.Status != AssumptionSupported {
		t.Fatalf("old reverse edge must be removed on replacement, got %+v", downstream)
	}
}
