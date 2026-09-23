package epistemic

import (
	"testing"
	"time"
)

func TestTrackerInvalidatesOnResourceVersionChange(t *testing.T) {
	tracker := NewTracker()
	dep := ResourceRef{
		APIVersion: "apps/v1",
		Kind: "Deployment",
		Namespace: "production",
		Name: "api",
		UID: "uid-1",
		ResourceVersion: "10",
	}
	tracker.PutAssumption(Assumption{
		ID: "A-001",
		Statement: "deployment production/api is safe to mutate",
		Status: AssumptionSupported,
		Dependencies: []ResourceRef{dep},
		EvaluatedAt: time.Now().UTC(),
	})

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "api",
			UID: "uid-1",
			ResourceVersion: "11",
		},
		At: time.Now().UTC(),
	})

	if len(results) != 1 || !results[0].Changed {
		t.Fatalf("expected one changed result, got %+v", results)
	}
	if got := results[0].Assumption.Invalidation; got == nil || got.Cause != CauseResourceVersionChanged {
		t.Fatalf("expected %s, got %+v", CauseResourceVersionChanged, got)
	}
}

func TestTrackerInvalidatesOnUIDChange(t *testing.T) {
	tracker := NewTracker()
	tracker.PutAssumption(testAssumption("uid-old", "10"))

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "api",
			UID: "uid-new",
			ResourceVersion: "10",
		},
		At: time.Now().UTC(),
	})

	if len(results) != 1 || !results[0].Changed {
		t.Fatalf("expected UID change to invalidate, got %+v", results)
	}
	if results[0].Assumption.Invalidation.Cause != CauseResourceUIDChanged {
		t.Fatalf("expected %s, got %+v", CauseResourceUIDChanged, results[0].Assumption.Invalidation)
	}
}

func TestTrackerInvalidatesOnDelete(t *testing.T) {
	tracker := NewTracker()
	tracker.PutAssumption(testAssumption("uid-1", "10"))

	results := tracker.Handle(ResourceEvent{
		Type: "DELETED",
		Resource: ResourceRef{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "api",
			UID: "uid-1",
			ResourceVersion: "10",
		},
		At: time.Now().UTC(),
	})

	if len(results) != 1 || !results[0].Changed {
		t.Fatalf("expected deletion to invalidate, got %+v", results)
	}
	if results[0].Assumption.Invalidation.Cause != CauseResourceDeleted {
		t.Fatalf("expected %s, got %+v", CauseResourceDeleted, results[0].Assumption.Invalidation)
	}
}

func TestTrackerIgnoresUnrelatedResource(t *testing.T) {
	tracker := NewTracker()
	tracker.PutAssumption(testAssumption("uid-1", "10"))

	results := tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "worker",
			UID: "uid-2",
			ResourceVersion: "11",
		},
		At: time.Now().UTC(),
	})

	if len(results) != 0 {
		t.Fatalf("expected unrelated resource to be ignored, got %+v", results)
	}
	a, ok := tracker.GetAssumption("A-001")
	if !ok || a.Status != AssumptionSupported {
		t.Fatalf("expected assumption to remain supported, got %+v ok=%v", a, ok)
	}
}

func TestTrackerInvalidationIsIdempotent(t *testing.T) {
	tracker := NewTracker()
	tracker.PutAssumption(testAssumption("uid-1", "10"))

	event := ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "api",
			UID: "uid-1",
			ResourceVersion: "11",
		},
		At: time.Now().UTC(),
	}

	first := tracker.Handle(event)
	second := tracker.Handle(event)
	if len(first) != 1 || !first[0].Changed {
		t.Fatalf("expected first event to invalidate, got %+v", first)
	}
	if len(second) != 1 || second[0].Changed {
		t.Fatalf("expected repeated event to be idempotent, got %+v", second)
	}
}

func testAssumption(uid, rv string) Assumption {
	return Assumption{
		ID: "A-001",
		Statement: "deployment production/api is safe to mutate",
		Status: AssumptionSupported,
		Dependencies: []ResourceRef{{
			APIVersion: "apps/v1",
			Kind: "Deployment",
			Namespace: "production",
			Name: "api",
			UID: uid,
			ResourceVersion: rv,
		}},
		EvaluatedAt: time.Now().UTC(),
	}
}
