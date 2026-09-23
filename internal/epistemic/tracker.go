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
	CauseResourceVersionChanged = "RESOURCE_VERSION_CHANGED"
	CauseResourceDeleted        = "RESOURCE_DELETED"
	CauseResourceUIDChanged     = "RESOURCE_UID_CHANGED"
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
	ID            string
	Statement     string
	Status        AssumptionStatus
	Dependencies  []ResourceRef
	EvaluatedAt   time.Time
	InvalidatedAt *time.Time
	Invalidation  *Invalidation
}

type ResourceEvent struct {
	Type     string
	Resource ResourceRef
	At       time.Time
}

type Invalidation struct {
	Cause              string
	DependencyKey      string
	OldResourceVersion string
	NewResourceVersion string
	EventType          string
}

type Result struct {
	Assumption Assumption
	Changed    bool
}

type Tracker struct {
	mu          sync.RWMutex
	assumptions map[string]Assumption
	reverse     map[string]map[string]struct{}
}

func NewTracker() *Tracker {
	return &Tracker{
		assumptions: make(map[string]Assumption),
		reverse:     make(map[string]map[string]struct{}),
	}
}

func (t *Tracker) PutAssumption(a Assumption) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if previous, ok := t.assumptions[a.ID]; ok {
		for _, dep := range previous.Dependencies {
			ids := t.reverse[dep.Key()]
			delete(ids, a.ID)
			if len(ids) == 0 {
				delete(t.reverse, dep.Key())
			}
		}
	}

	a.Dependencies = append([]ResourceRef(nil), a.Dependencies...)
	t.assumptions[a.ID] = a

	for _, dep := range a.Dependencies {
		ids := t.reverse[dep.Key()]
		if ids == nil {
			ids = make(map[string]struct{})
			t.reverse[dep.Key()] = ids
		}
		ids[a.ID] = struct{}{}
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
	return a, true
}

func (t *Tracker) Handle(event ResourceEvent) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()

	idsMap := t.reverse[event.Resource.Key()]
	ids := make([]string, 0, len(idsMap))
	for id := range idsMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	results := make([]Result, 0, len(ids))
	for _, id := range ids {
		a := t.assumptions[id]
		if a.Status == AssumptionInvalidated {
			results = append(results, Result{Assumption: a, Changed: false})
			continue
		}

		for _, dep := range a.Dependencies {
			if dep.Key() != event.Resource.Key() {
				continue
			}

			cause := ""
			switch {
			case event.Type == "DELETED":
				cause = CauseResourceDeleted
			case dep.UID != "" && event.Resource.UID != "" && dep.UID != event.Resource.UID:
				cause = CauseResourceUIDChanged
			case dep.ResourceVersion != event.Resource.ResourceVersion:
				cause = CauseResourceVersionChanged
			default:
				results = append(results, Result{Assumption: a, Changed: false})
				continue
			}

			at := event.At.UTC()
			a.Status = AssumptionInvalidated
			a.InvalidatedAt = &at
			a.Invalidation = &Invalidation{
				Cause:              cause,
				DependencyKey:      dep.Key(),
				OldResourceVersion: dep.ResourceVersion,
				NewResourceVersion: event.Resource.ResourceVersion,
				EventType:          event.Type,
			}
			t.assumptions[id] = a
			results = append(results, Result{Assumption: a, Changed: true})
			break
		}
	}

	return results
}
