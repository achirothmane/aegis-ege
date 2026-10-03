package runtime_test

import (
	"context"
	"errors"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// temporalClosureAdapter adds exact durable custody lookup to the existing
// reference adapter so the conformance proof can continue from UNKNOWN to
// observation-only recovery without dispatching a second effect.
type temporalClosureAdapter struct {
	*fakeAdapter
}

func (a *temporalClosureAdapter) LoadCustody(_ context.Context, effectID, attemptID string) (gaRuntime.Custody, error) {
	custody, ok := a.retained[effectID+"\x00"+attemptID]
	if !ok {
		return gaRuntime.Custody{}, gaRuntime.ErrMissingRecoveryCustody
	}
	return custody, nil
}

func TestTemporalStandingConformance(t *testing.T) {
	t.Run("standing-defeating state delta is fenced before effect", func(t *testing.T) {
		req := defaultRequest(t)
		base := newFencedAdapter(req.Current, req.Transition.To)
		prep, err := gaRuntime.ReserveFenced(context.Background(), req, base)
		if err != nil {
			t.Fatal(err)
		}

		adapter := &delayedFencedAdapter{fencedFakeAdapter: base}
		adapter.afterCrossing = func() {
			changed := req.Current
			changed.Revision = "head:advanced-after-admission"
			changed.Digest = "sha256:advanced-after-admission"
			base.states = []gaRuntime.State{changed}
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionRejected ||
			!errors.Is(result.Cause, gaRuntime.ErrStateChanged) {
			t.Fatalf("standing-defeating state delta was not rejected: %+v", result)
		}
		if result.BoundaryEntered || base.effectCalls != 0 || base.observeCalls != 0 {
			t.Fatalf("standing-defeating state delta crossed effect boundary: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyCrossing {
			t.Fatalf("failed revalidation must preserve non-replayable CROSSING custody: %+v", result.Custody)
		}
	})

	t.Run("standing-defeating authority delta is fenced before effect", func(t *testing.T) {
		req := defaultRequest(t)
		base := newFencedAdapter(req.Current, req.Transition.To)
		prep, err := gaRuntime.ReserveFenced(context.Background(), req, base)
		if err != nil {
			t.Fatal(err)
		}

		adapter := &delayedFencedAdapter{fencedFakeAdapter: base}
		adapter.afterCrossing = func() {
			delete(base.trusted, policyIssuer.ID)
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionRejected ||
			!errors.Is(result.Cause, errUntrusted) {
			t.Fatalf("standing-defeating authority delta was not rejected: %+v", result)
		}
		if result.BoundaryEntered || base.effectCalls != 0 || base.observeCalls != 0 {
			t.Fatalf("revoked authority crossed effect boundary: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyCrossing {
			t.Fatalf("failed authority revalidation must preserve CROSSING custody: %+v", result.Custody)
		}
	})

	t.Run("standing-preserving evidence-path rotation does not overblock", func(t *testing.T) {
		req := defaultRequest(t)
		base := newFencedAdapter(req.Current, req.Transition.To)
		prep, err := gaRuntime.ReserveFenced(context.Background(), req, base)
		if err != nil {
			t.Fatal(err)
		}

		rotatedObserver := gaRuntime.Identity{ID: "observer:rotated", Kind: "observer"}
		base.trusted[rotatedObserver.ID] = true

		adapter := &delayedFencedAdapter{fencedFakeAdapter: base}
		adapter.afterCrossing = func() {
			// This changes the post-effect evidence path, not the admitted
			// subject, exact target state, transition, or current authority.
			base.observationIssuer = rotatedObserver
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionClosed {
			t.Fatalf("standing-preserving delta was overblocked: %+v", result)
		}
		if !result.BoundaryEntered || base.effectCalls != 1 || base.observeCalls != 1 {
			t.Fatalf("standing-preserving path did not execute and close exactly once: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyClosed {
			t.Fatalf("standing-preserving path did not reach CLOSED custody: %+v", result.Custody)
		}
	})
}

func TestEffectClosureExtensionUnknownThenObservationOnlyRecovery(t *testing.T) {
	req := defaultRequest(t)
	adapter := &temporalClosureAdapter{fakeAdapter: newAdapter(req.Current, req.Transition.To)}
	adapter.observationErr = errObserve

	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("missing effect evidence must remain UNKNOWN: %+v", first)
	}
	if !first.BoundaryEntered || first.Acceptance.Reference == "" || adapter.effectCalls != 1 {
		t.Fatalf("test requires one entered/accepted provider call: %+v", first)
	}

	custody, err := adapter.LoadCustody(context.Background(), first.EffectID, req.AttemptID)
	if err != nil {
		t.Fatalf("load retained custody: %v", err)
	}

	recoveryIssuer := gaRuntime.Identity{ID: "recovery:observer-controller", Kind: "controller"}
	recoverer := gaRuntime.Identity{ID: "process:reconciler-1", Kind: "process"}
	adapter.trusted[recoveryIssuer.ID] = true
	adapter.observationErr = nil

	recovery := gaRuntime.RecoveryRequest{
		Original:  req,
		Recoverer: recoverer,
		RecoveryAuthorization: gaRuntime.Attestation{
			ID:            "recovery-auth:001",
			Issuer:        recoveryIssuer,
			BindingDigest: gaRuntime.RecoveryBindingDigest(custody, recoverer),
		},
	}

	closed := gaRuntime.Recover(context.Background(), recovery, adapter)
	if closed.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("fresh exact observation did not close retained UNKNOWN effect: %+v", closed)
	}
	if closed.BoundaryEntered {
		t.Fatalf("observation-only recovery incorrectly entered a new effect boundary: %+v", closed)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("recovery dispatched a second effect: %d", adapter.effectCalls)
	}
	if adapter.observeCalls != 2 {
		t.Fatalf("expected initial failed observation plus one recovery observation, got %d", adapter.observeCalls)
	}
}
