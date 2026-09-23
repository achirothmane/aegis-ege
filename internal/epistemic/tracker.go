package epistemic

import (
	"sort"
	"sync"
	"time"
)

type AssumptionStatus string

const (
	AssumptionSupported   AssumptionStatus = "SUPPORTED"
	AssumptionInvalidated AssumptionStatus = "INVALIDATED"
)

const (
	CauseResourceVersionChanged       = "RESOURCE_VERSION_CHANGED"
	CauseResourceDeleted              = "RESOURCE_DELETED"
	CauseResourceUIDChanged           = "RESOURCE_UID_CHANGED"
	CauseUpstreamAssumptionInvalidated = "UPSTREAM_ASSUMPTION_INVALIDATED"
)

type ResourceRef struct {
	APIVersion      string
	Kind            string
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
}

func (r ResourceRef) Key() string {
	return r.APIVersion + "/" + r.Kind + "/" + r.Namespace + "/" + r.Name
}

type Assumption struct {
	ID                     string
	Statement              string
	Status                 AssumptionStatus
	Dependencies           []ResourceRef
	AssumptionDependencies []string
	EvaluatedAt            time.Time
	InvalidatedAt          *time.Time
	Invalidation           *Invalidation
}

type ResourceEvent struct {
	Type     string
	Resource ResourceRef
	At       time.Time
}

type Invalidation struct {
	Cause                  string
	DependencyKey          string
	RootDependencyKey      string
	UpstreamAssumptionID   string
	OldResourceVersion     string
	NewResourceVersion     string
	EventType              string
}

type Result struct {
	Assumption Assumption
	Changed    bool
}

type Tracker struct {
	mu                 sync.RWMutex
	assumptions        map[string]Assumption
	reverseResources   map[string]map[string]struct{}
	reverseAssumptions map[string]map[string]struct{}
}

func NewTracker() *Tracker {
	return &Tracker{
		assumptions:        make(map[string]Assumption),
		reverseResources:   make(map[string]map[string]struct{}),
		reverseAssumptions: make(map[string]map[string]struct{}),
	}
}

func (t *Tracker) PutAssumption(a Assumption) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if previous, ok := t.assumptions[a.ID]; ok {
		for _, dep := range previous.Dependencies {
			removeReverseEdge(t.reverseResources, dep.Key(), a.ID)
		}
		for _, upstream := range previous.AssumptionDependencies {
			removeReverseEdge(t.reverseAssumptions, upstream, a.ID)
		}
	}

	a.Dependencies = append([]ResourceRef(nil), a.Dependencies...)
	a.AssumptionDependencies = append([]string(nil), a.AssumptionDependencies...)
	t.assumptions[a.ID] = a

	for _, dep := range a.Dependencies {
		addReverseEdge(t.reverseResources, dep.Key(), a.ID)
	}
	for _, upstream := range a.AssumptionDependencies {
		addReverseEdge(t.reverseAssumptions, upstream, a.ID)
	}
}

func (t *Tracker) GetAssumption(id string) (Assumption, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	a, ok := t.assumptions[id]
	if !ok {
		return Assumption{}, false
	}
	a.Dependencies = append([]ResourceRef(nil), a.Dependencies...)
	a.AssumptionDependencies = append([]string(nil), a.AssumptionDependencies...)
	return a, true
}

func (t *Tracker) Handle(event ResourceEvent) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()

	rootKey := event.Resource.Key()
	directIDs := sortedIDs(t.reverseResources[rootKey])
	results := make([]Result, 0, len(directIDs))
	queue := make([]string, 0, len(directIDs))

	for _, id := range directIDs {
		a := t.assumptions[id]
		if a.Status == AssumptionInvalidated {
			results = append(results, Result{Assumption: a, Changed: false})
			continue
		}

		dep, ok := matchingDependency(a.Dependencies, rootKey)
		if !ok {
			continue
		}

		cause := resourceInvalidationCause(dep, event)
		if cause == "" {
			results = append(results, Result{Assumption: a, Changed: false})
			continue
		}

		a = invalidateAssumption(a, event.At, Invalidation{
			Cause:              cause,
			DependencyKey:      dep.Key(),
			RootDependencyKey:  rootKey,
			OldResourceVersion: dep.ResourceVersion,
			NewResourceVersion: event.Resource.ResourceVersion,
			EventType:          event.Type,
		})
		t.assumptions[id] = a
		results = append(results, Result{Assumption: a, Changed: true})
		queue = append(queue, id)
	}

	for len(queue) > 0 {
		upstream := queue[0]
		queue = queue[1:]

		for _, id := range sortedIDs(t.reverseAssumptions[upstream]) {
			a := t.assumptions[id]
			if a.Status == AssumptionInvalidated {
				continue
			}

			rootInvalidation := t.assumptions[upstream].Invalidation
			oldResourceVersion := ""
			newResourceVersion := ""
			rootDependencyKey := rootKey
			eventType := event.Type
			if rootInvalidation != nil {
				oldResourceVersion = rootInvalidation.OldResourceVersion
				newResourceVersion = rootInvalidation.NewResourceVersion
				if rootInvalidation.RootDependencyKey != "" {
					rootDependencyKey = rootInvalidation.RootDependencyKey
				}
				if rootInvalidation.EventType != "" {
					eventType = rootInvalidation.EventType
				}
			}

			a = invalidateAssumption(a, event.At, Invalidation{
				Cause:                CauseUpstreamAssumptionInvalidated,
				DependencyKey:        "assumption/" + upstream,
				RootDependencyKey:    rootDependencyKey,
				UpstreamAssumptionID: upstream,
				OldResourceVersion:   oldResourceVersion,
				NewResourceVersion:   newResourceVersion,
				EventType:            eventType,
			})
			t.assumptions[id] = a
			results = append(results, Result{Assumption: a, Changed: true})
			queue = append(queue, id)
		}
	}

	return results
}

func invalidateAssumption(a Assumption, at time.Time, invalidation Invalidation) Assumption {
	when := at.UTC()
	a.Status = AssumptionInvalidated
	a.InvalidatedAt = &when
	a.Invalidation = &invalidation
	return a
}

func matchingDependency(dependencies []ResourceRef, key string) (ResourceRef, bool) {
	for _, dep := range dependencies {
		if dep.Key() == key {
			return dep, true
		}
	}
	return ResourceRef{}, false
}

func resourceInvalidationCause(dep ResourceRef, event ResourceEvent) string {
	switch {
	case event.Type == "DELETED":
		return CauseResourceDeleted
	case dep.UID != "" && event.Resource.UID != "" && dep.UID != event.Resource.UID:
		return CauseResourceUIDChanged
	case dep.ResourceVersion != event.Resource.ResourceVersion:
		return CauseResourceVersionChanged
	default:
		return ""
	}
}

func addReverseEdge(index map[string]map[string]struct{}, key, assumptionID string) {
	ids := index[key]
	if ids == nil {
		ids = make(map[string]struct{})
		index[key] = ids
	}
	ids[assumptionID] = struct{}{}
}

func removeReverseEdge(index map[string]map[string]struct{}, key, assumptionID string) {
	ids := index[key]
	delete(ids, assumptionID)
	if len(ids) == 0 {
		delete(index, key)
	}
}

func sortedIDs(idsMap map[string]struct{}) []string {
	ids := make([]string, 0, len(idsMap))
	for id := range idsMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
