package runtime_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

var (
	takeoverIssuer = gaRuntime.Identity{ID: "takeover:controller", Kind: "controller"}
	errFencedDuplicate = errors.New("fenced custody already exists")
	errFencedCAS       = errors.New("fenced custody compare-and-swap failed")
	errStaleFence      = errors.New("stale fenced custody rejected at effect boundary")
)

type fencedFakeAdapter struct {
	*fakeAdapter

	mu     sync.Mutex
	fenced map[string]gaRuntime.FencedCustody
}

func newFencedAdapter(current, after gaRuntime.State) *fencedFakeAdapter {
	base := newAdapter(current, after)
	base.trusted[takeoverIssuer.ID] = true
	return &fencedFakeAdapter{
		fakeAdapter: base,
		fenced:      make(map[string]gaRuntime.FencedCustody),
	}
}

func fencedKey(effectID, attemptID string) string {
	return effectID + "\x00" + attemptID
}

func (a *fencedFakeAdapter) ReserveFencedCustody(_ context.Context, custody gaRuntime.FencedCustody) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fencedKey(custody.EffectID, custody.AttemptID)
	if _, exists := a.fenced[key]; exists {
		return errFencedDuplicate
	}
	a.fenced[key] = custody
	return nil
}

func (a *fencedFakeAdapter) LoadFencedCustody(_ context.Context, effectID, attemptID string) (gaRuntime.FencedCustody, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	custody, ok := a.fenced[fencedKey(effectID, attemptID)]
	if !ok {
		return gaRuntime.FencedCustody{}, gaRuntime.ErrIncompleteFencedCustody
	}
	return custody, nil
}

func (a *fencedFakeAdapter) TransitionFencedCustodyCAS(_ context.Context, expected, next gaRuntime.FencedCustody) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := fencedKey(expected.EffectID, expected.AttemptID)
	current, ok := a.fenced[key]
	if !ok || !current.Equal(expected) {
		return errFencedCAS
	}
	a.fenced[key] = next
	return nil
}

func (a *fencedFakeAdapter) ExecuteFenced(_ context.Context, _ gaRuntime.Transition, custody gaRuntime.FencedCustody) (gaRuntime.Acceptance, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	current, ok := a.fenced[fencedKey(custody.EffectID, custody.AttemptID)]
	if !ok || !current.Equal(custody) || current.Phase != gaRuntime.CustodyCrossing {
		return gaRuntime.Acceptance{}, errStaleFence
	}
	a.effectCalls++
	return a.acceptance, a.effectErr
}

func (a *fencedFakeAdapter) ObserveFenced(ctx context.Context, transition gaRuntime.Transition, custody gaRuntime.FencedCustody) (gaRuntime.Observation, error) {
	return a.fakeAdapter.Observe(ctx, transition, gaRuntime.Custody{
		EffectID:  custody.EffectID,
		AttemptID: custody.AttemptID,
		Target:    custody.Target,
		Owner:     custody.Owner,
	})
}

func takeoverRequestFor(t *testing.T, original gaRuntime.Request, current gaRuntime.FencedCustody, newOwner gaRuntime.Identity) gaRuntime.TakeoverRequest {
	t.Helper()
	return gaRuntime.TakeoverRequest{
		Original: original,
		NewOwner: newOwner,
		Authorization: gaRuntime.Attestation{
			ID:            "takeover-auth:" + newOwner.ID,
			Issuer:        takeoverIssuer,
			BindingDigest: gaRuntime.TakeoverBindingDigest(current, newOwner),
		},
	}
}

func TestFencedRunClosesWithDurablePhaseProgression(t *testing.T) {
	req := defaultRequest(t)
	adapter := newFencedAdapter(req.Current, req.Transition.To)

	result := gaRuntime.RunFenced(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("fenced run did not close: %+v", result)
	}
	if !result.CustodyRecorded || !result.BoundaryEntered {
		t.Fatalf("fenced run boundary facts missing: %+v", result)
	}
	if result.Custody.Phase != gaRuntime.CustodyClosed || result.Custody.Generation != 1 {
		t.Fatalf("unexpected final custody: %+v", result.Custody)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("expected exactly one effect, got %d", adapter.effectCalls)
	}
}

func TestReservedTakeoverFencesLateOldOwnerAndAllowsNewOwner(t *testing.T) {
	req := defaultRequest(t)
	adapter := newFencedAdapter(req.Current, req.Transition.To)

	prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
	if err != nil {
		t.Fatalf("reserve fenced: %v", err)
	}
	if prep.Custody.Phase != gaRuntime.CustodyReserved {
		t.Fatalf("expected RESERVED, got %+v", prep.Custody)
	}

	newOwner := gaRuntime.Identity{ID: "process:executor-2", Kind: "process"}
	takeoverReq := takeoverRequestFor(t, req, prep.Custody, newOwner)
	taken, err := gaRuntime.TakeoverReserved(context.Background(), takeoverReq, adapter)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if taken.Current.Generation != prep.Custody.Generation+1 ||
		!taken.Current.Owner.Equal(newOwner) ||
		taken.Current.Phase != gaRuntime.CustodyReserved {
		t.Fatalf("unexpected takeover result: %+v", taken)
	}

	// Worker A returns late with its stale generation. Native fencing must deny
	// it even though A still holds the old in-memory custody record.
	stale := prep.Custody
	stale.Phase = gaRuntime.CustodyCrossing
	if _, err := adapter.ExecuteFenced(context.Background(), req.Transition, stale); !errors.Is(err, errStaleFence) {
		t.Fatalf("late old owner was not fenced: %v", err)
	}
	if adapter.effectCalls != 0 {
		t.Fatalf("stale owner produced an effect: %d", adapter.effectCalls)
	}

	reqB := req
	reqB.Executor = newOwner
	result := gaRuntime.ExecuteReservedFenced(context.Background(), reqB, taken.Current, adapter)
	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("new owner could not execute exact retained effect: %+v", result)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("expected exactly one effect after takeover, got %d", adapter.effectCalls)
	}
}

func TestTakeoverDeniedOnceCustodyMayHaveCrossedEffectBoundary(t *testing.T) {
	req := defaultRequest(t)

	for _, phase := range []gaRuntime.CustodyPhase{
		gaRuntime.CustodyCrossing,
		gaRuntime.CustodyUnknown,
		gaRuntime.CustodyClosed,
	} {
		t.Run(string(phase), func(t *testing.T) {
			adapter := newFencedAdapter(req.Current, req.Transition.To)
			prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
			if err != nil {
				t.Fatal(err)
			}

			current := prep.Custody
			next := current
			next.Phase = gaRuntime.CustodyCrossing
			if err := adapter.TransitionFencedCustodyCAS(context.Background(), current, next); err != nil {
				t.Fatal(err)
			}
			current = next

			if phase == gaRuntime.CustodyUnknown || phase == gaRuntime.CustodyClosed {
				next = current
				next.Phase = gaRuntime.CustodyUnknown
				if err := adapter.TransitionFencedCustodyCAS(context.Background(), current, next); err != nil {
					t.Fatal(err)
				}
				current = next
			}
			if phase == gaRuntime.CustodyClosed {
				next = current
				next.Phase = gaRuntime.CustodyClosed
				if err := adapter.TransitionFencedCustodyCAS(context.Background(), current, next); err != nil {
					t.Fatal(err)
				}
				current = next
			}

			newOwner := gaRuntime.Identity{ID: "process:executor-2", Kind: "process"}
			takeoverReq := takeoverRequestFor(t, req, current, newOwner)
			_, err = gaRuntime.TakeoverReserved(context.Background(), takeoverReq, adapter)
			if !errors.Is(err, gaRuntime.ErrCustodyNotReserved) {
				t.Fatalf("phase %s was reopened for execution: %v", phase, err)
			}
			if adapter.effectCalls != 0 {
				t.Fatalf("phase %s produced an effect during denied takeover", phase)
			}
		})
	}
}

func TestConcurrentReservedTakeoverHasSingleWinner(t *testing.T) {
	req := defaultRequest(t)
	adapter := newFencedAdapter(req.Current, req.Transition.To)
	prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	owners := []gaRuntime.Identity{
		{ID: "process:executor-b", Kind: "process"},
		{ID: "process:executor-c", Kind: "process"},
	}
	requests := []gaRuntime.TakeoverRequest{
		takeoverRequestFor(t, req, prep.Custody, owners[0]),
		takeoverRequestFor(t, req, prep.Custody, owners[1]),
	}

	type outcome struct {
		result gaRuntime.TakeoverResult
		err    error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, takeoverReq := range requests {
		wg.Add(1)
		go func(r gaRuntime.TakeoverRequest) {
			defer wg.Done()
			got, err := gaRuntime.TakeoverReserved(context.Background(), r, adapter)
			results <- outcome{result: got, err: err}
		}(takeoverReq)
	}
	wg.Wait()
	close(results)

	successes := 0
	var winner gaRuntime.FencedCustody
	for got := range results {
		if got.err == nil {
			successes++
			winner = got.result.Current
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one takeover winner, got %d", successes)
	}
	if winner.Generation != prep.Custody.Generation+1 {
		t.Fatalf("winner did not advance generation: %+v", winner)
	}

	current, err := adapter.LoadFencedCustody(context.Background(), prep.Custody.EffectID, prep.Custody.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Equal(winner) {
		t.Fatalf("durable winner differs from successful CAS: current=%+v winner=%+v", current, winner)
	}
}

func TestSecondTakeoverFencesIntermediateOwner(t *testing.T) {
	reqA := defaultRequest(t)
	adapter := newFencedAdapter(reqA.Current, reqA.Transition.To)
	prep, err := gaRuntime.ReserveFenced(context.Background(), reqA, adapter)
	if err != nil {
		t.Fatal(err)
	}

	ownerB := gaRuntime.Identity{ID: "process:executor-b", Kind: "process"}
	first, err := gaRuntime.TakeoverReserved(
		context.Background(),
		takeoverRequestFor(t, reqA, prep.Custody, ownerB),
		adapter,
	)
	if err != nil {
		t.Fatal(err)
	}

	reqB := reqA
	reqB.Executor = ownerB
	ownerC := gaRuntime.Identity{ID: "process:executor-c", Kind: "process"}
	second, err := gaRuntime.TakeoverReserved(
		context.Background(),
		takeoverRequestFor(t, reqB, first.Current, ownerC),
		adapter,
	)
	if err != nil {
		t.Fatal(err)
	}

	staleB := first.Current
	staleB.Phase = gaRuntime.CustodyCrossing
	if _, err := adapter.ExecuteFenced(context.Background(), reqA.Transition, staleB); !errors.Is(err, errStaleFence) {
		t.Fatalf("intermediate owner was not fenced: %v", err)
	}

	reqC := reqA
	reqC.Executor = ownerC
	result := gaRuntime.ExecuteReservedFenced(context.Background(), reqC, second.Current, adapter)
	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("latest owner failed: %+v", result)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("multiple generations produced effects: %d", adapter.effectCalls)
	}
	if second.Current.Generation != 3 {
		t.Fatalf("expected third generation, got %d", second.Current.Generation)
	}
}

func TestTakeoverAuthorizationBindsExactNewOwner(t *testing.T) {
	req := defaultRequest(t)
	adapter := newFencedAdapter(req.Current, req.Transition.To)
	prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	ownerB := gaRuntime.Identity{ID: "process:executor-b", Kind: "process"}
	takeoverReq := takeoverRequestFor(t, req, prep.Custody, ownerB)
	takeoverReq.NewOwner = gaRuntime.Identity{ID: "process:executor-c", Kind: "process"}

	_, err = gaRuntime.TakeoverReserved(context.Background(), takeoverReq, adapter)
	if !errors.Is(err, gaRuntime.ErrTakeoverBinding) {
		t.Fatalf("new-owner substitution retained takeover authority: %v", err)
	}
}

func TestTakeoverDoesNotBypassFreshStateRevalidation(t *testing.T) {
	req := defaultRequest(t)
	adapter := newFencedAdapter(req.Current, req.Transition.To)
	prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	newOwner := gaRuntime.Identity{ID: "process:executor-2", Kind: "process"}
	taken, err := gaRuntime.TakeoverReserved(
		context.Background(),
		takeoverRequestFor(t, req, prep.Custody, newOwner),
		adapter,
	)
	if err != nil {
		t.Fatal(err)
	}

	advanced := req.Current
	advanced.Revision = "head:advanced"
	advanced.Digest = "sha256:advanced"
	adapter.states = []gaRuntime.State{advanced}

	reqB := req
	reqB.Executor = newOwner
	result := gaRuntime.ExecuteReservedFenced(context.Background(), reqB, taken.Current, adapter)
	if result.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(result.Cause, gaRuntime.ErrStateChanged) {
		t.Fatalf("takeover bypassed fresh state check: %+v", result)
	}
	if adapter.effectCalls != 0 {
		t.Fatalf("stale state after takeover produced effect: %d", adapter.effectCalls)
	}
}
