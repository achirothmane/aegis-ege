package runtime_test

import (
	"context"
	"errors"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// Hooks run after successful storage operations, before returning to runtime.
// The fixture models delayed storage; it does not claim native provider fencing.
type delayedFencedAdapter struct {
	*fencedFakeAdapter
	afterLoad func()
	afterCrossing func()
}

func (a *delayedFencedAdapter) LoadFencedCustody(ctx context.Context, effectID, attemptID string) (gaRuntime.FencedCustody, error) {
	custody, err := a.fencedFakeAdapter.LoadFencedCustody(ctx, effectID, attemptID)
	if err == nil && a.afterLoad != nil {
		a.afterLoad()
	}
	return custody, err
}

func (a *delayedFencedAdapter) TransitionFencedCustodyCAS(ctx context.Context, expected, next gaRuntime.FencedCustody) error {
	if err := a.fencedFakeAdapter.TransitionFencedCustodyCAS(ctx, expected, next); err != nil {
		return err
	}
	if next.Phase == gaRuntime.CustodyCrossing && a.afterCrossing != nil {
		a.afterCrossing()
	}
	return nil
}

func TestFencedRevalidatesAfterCustodyStorage(t *testing.T) {
	for _, scenario := range []string{"state-during-load", "state-during-CAS", "authority-during-CAS", "cancel-during-CAS", "unchanged"} {
		t.Run(scenario, func(t *testing.T) {
			req := defaultRequest(t)
			base := newFencedAdapter(req.Current, req.Transition.To)
			prep, err := gaRuntime.ReserveFenced(context.Background(), req, base)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter := &delayedFencedAdapter{fencedFakeAdapter: base}
			changeState := func() {
				changed := req.Current
				changed.Revision += ":advanced"
				base.states = []gaRuntime.State{changed}
			}
			var expected error
			switch scenario {
			case "state-during-load":
				adapter.afterLoad = changeState
				expected = gaRuntime.ErrStateChanged
			case "state-during-CAS":
				adapter.afterCrossing = changeState
				expected = gaRuntime.ErrStateChanged
			case "authority-during-CAS":
				adapter.afterCrossing = func() { delete(base.trusted, policyIssuer.ID) }
				expected = errUntrusted
			case "cancel-during-CAS":
				adapter.afterCrossing = cancel
				expected = context.Canceled
			}
			result := gaRuntime.ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
			if expected == nil {
				if result.Disposition != gaRuntime.DispositionClosed || base.effectCalls != 1 || base.observeCalls != 1 {
					t.Fatalf("unchanged request did not close exactly once: %+v", result)
				}
				return
			}
			if result.Disposition != gaRuntime.DispositionRejected || !errors.Is(result.Cause, expected) {
				t.Fatalf("storage invalidation was not rejected: %+v", result)
			}
			if !result.CustodyRecorded || result.BoundaryEntered || base.effectCalls != 0 || base.observeCalls != 0 {
				t.Fatalf("denied request entered effect or observation: %+v", result)
			}
			durable, err := base.LoadFencedCustody(context.Background(), prep.Custody.EffectID, req.AttemptID)
			if err != nil || durable.Phase != gaRuntime.CustodyCrossing || !durable.Equal(result.Custody) {
				t.Fatalf("CROSSING custody was not preserved: %+v err=%v", durable, err)
			}
			replay := gaRuntime.ExecuteReservedFenced(context.Background(), req, durable, base)
			if !errors.Is(replay.Cause, gaRuntime.ErrCustodyNotReserved) || replay.BoundaryEntered || base.effectCalls != 0 {
				t.Fatalf("denied CROSSING record was reopened: %+v", replay)
			}
		})
	}
}
