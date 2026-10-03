package temporalconformance_test

import (
	"context"
	"errors"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

var (
	policyIssuer   = gaRuntime.Identity{ID: "policy:temporal-conformance", Kind: "policy"}
	observerIssuer = gaRuntime.Identity{ID: "observer:temporal-conformance", Kind: "observer"}
	subject        = gaRuntime.Identity{ID: "agent:temporal-conformance", Kind: "agent"}
	executor       = gaRuntime.Identity{ID: "process:temporal-conformance", Kind: "process"}

	errUntrusted   = errors.New("attestation issuer is not trusted")
	errObservation = errors.New("trusted observation unavailable")
	errDuplicate   = errors.New("custody already retained")
	errCAS         = errors.New("fenced custody compare-and-swap failed")
	errStaleFence  = errors.New("stale fenced custody rejected")
)

func requestFor(t *testing.T) gaRuntime.Request {
	t.Helper()

	current := gaRuntime.State{
		Target:   "github:achirothmane/aegis-ege#temporal-conformance",
		Revision: "head:t0",
		Digest:   "sha256:t0",
	}
	after := gaRuntime.State{
		Target:   current.Target,
		Revision: "merged:tn",
		Digest:   "sha256:tn",
	}

	req := gaRuntime.Request{
		Subject:   subject,
		Executor:  executor,
		Current:   current,
		Transition: gaRuntime.Transition{
			Operation: "github.pull_request.merge",
			From:      current,
			To:        after,
		},
		AttemptID: "attempt:temporal-001",
	}

	binding, err := gaRuntime.AdmissionBindingDigest(req)
	if err != nil {
		t.Fatalf("admission binding: %v", err)
	}
	req.Admission = gaRuntime.Attestation{
		ID:            "admission:temporal-001",
		Issuer:        policyIssuer,
		BindingDigest: binding,
	}
	return req
}

type temporalFencedAdapter struct {
	states []gaRuntime.State
	reads  int

	trusted map[string]bool
	fenced  map[string]gaRuntime.FencedCustody

	afterCrossing func()

	effectCalls  int
	observeCalls int

	acceptance        gaRuntime.Acceptance
	observationState  gaRuntime.State
	observationIssuer gaRuntime.Identity
}

func newTemporalFencedAdapter(current, after gaRuntime.State) *temporalFencedAdapter {
	return &temporalFencedAdapter{
		states: []gaRuntime.State{current},
		trusted: map[string]bool{
			policyIssuer.ID:   true,
			observerIssuer.ID: true,
		},
		fenced:            make(map[string]gaRuntime.FencedCustody),
		acceptance:        gaRuntime.Acceptance{Reference: "provider:accepted"},
		observationState:  after,
		observationIssuer: observerIssuer,
	}
}

func (a *temporalFencedAdapter) CurrentState(context.Context, string) (gaRuntime.State, error) {
	if len(a.states) == 0 {
		return gaRuntime.State{}, errors.New("no current state")
	}
	index := a.reads
	if index >= len(a.states) {
		index = len(a.states) - 1
	}
	a.reads++
	return a.states[index], nil
}

func (a *temporalFencedAdapter) VerifyAttestation(_ context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return errors.New("binding digest mismatch")
	}
	if !a.trusted[att.Issuer.ID] {
		return errUntrusted
	}
	return nil
}

func fencedKey(effectID, attemptID string) string {
	return effectID + "\x00" + attemptID
}

func (a *temporalFencedAdapter) ReserveFencedCustody(_ context.Context, custody gaRuntime.FencedCustody) error {
	key := fencedKey(custody.EffectID, custody.AttemptID)
	if _, exists := a.fenced[key]; exists {
		return errDuplicate
	}
	a.fenced[key] = custody
	return nil
}

func (a *temporalFencedAdapter) LoadFencedCustody(_ context.Context, effectID, attemptID string) (gaRuntime.FencedCustody, error) {
	custody, ok := a.fenced[fencedKey(effectID, attemptID)]
	if !ok {
		return gaRuntime.FencedCustody{}, gaRuntime.ErrIncompleteFencedCustody
	}
	return custody, nil
}

func (a *temporalFencedAdapter) TransitionFencedCustodyCAS(_ context.Context, expected, next gaRuntime.FencedCustody) error {
	key := fencedKey(expected.EffectID, expected.AttemptID)
	current, ok := a.fenced[key]
	if !ok || !current.Equal(expected) {
		return errCAS
	}
	a.fenced[key] = next
	if next.Phase == gaRuntime.CustodyCrossing && a.afterCrossing != nil {
		a.afterCrossing()
	}
	return nil
}

func (a *temporalFencedAdapter) ExecuteFenced(_ context.Context, _ gaRuntime.Transition, custody gaRuntime.FencedCustody) (gaRuntime.Acceptance, error) {
	current, ok := a.fenced[fencedKey(custody.EffectID, custody.AttemptID)]
	if !ok || !current.Equal(custody) || current.Phase != gaRuntime.CustodyCrossing {
		return gaRuntime.Acceptance{}, errStaleFence
	}
	a.effectCalls++
	return a.acceptance, nil
}

func (a *temporalFencedAdapter) ObserveFenced(_ context.Context, _ gaRuntime.Transition, custody gaRuntime.FencedCustody) (gaRuntime.Observation, error) {
	a.observeCalls++
	return gaRuntime.Observation{
		State: a.observationState,
		Attestation: gaRuntime.Attestation{
			ID:            "observation:temporal",
			Issuer:        a.observationIssuer,
			BindingDigest: gaRuntime.ObservationBindingDigest(custody.EffectID, a.observationState),
		},
	}, nil
}

func TestTemporalStandingConformanceHeldOut(t *testing.T) {
	t.Run("standing-defeating state delta is fenced before effect", func(t *testing.T) {
		req := requestFor(t)
		adapter := newTemporalFencedAdapter(req.Current, req.Transition.To)

		prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
		if err != nil {
			t.Fatal(err)
		}

		adapter.afterCrossing = func() {
			changed := req.Current
			changed.Revision = "head:advanced-after-admission"
			changed.Digest = "sha256:advanced-after-admission"
			adapter.states = []gaRuntime.State{changed}
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionRejected ||
			!errors.Is(result.Cause, gaRuntime.ErrStateChanged) {
			t.Fatalf("standing-defeating state delta was not rejected: %+v", result)
		}
		if result.BoundaryEntered || adapter.effectCalls != 0 || adapter.observeCalls != 0 {
			t.Fatalf("standing-defeating state delta crossed effect boundary: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyCrossing {
			t.Fatalf("failed revalidation must preserve CROSSING custody: %+v", result.Custody)
		}
	})

	t.Run("standing-defeating authority delta is fenced before effect", func(t *testing.T) {
		req := requestFor(t)
		adapter := newTemporalFencedAdapter(req.Current, req.Transition.To)

		prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
		if err != nil {
			t.Fatal(err)
		}

		adapter.afterCrossing = func() {
			delete(adapter.trusted, policyIssuer.ID)
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionRejected ||
			!errors.Is(result.Cause, errUntrusted) {
			t.Fatalf("standing-defeating authority delta was not rejected: %+v", result)
		}
		if result.BoundaryEntered || adapter.effectCalls != 0 || adapter.observeCalls != 0 {
			t.Fatalf("revoked authority crossed effect boundary: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyCrossing {
			t.Fatalf("failed authority revalidation must preserve CROSSING custody: %+v", result.Custody)
		}
	})

	t.Run("standing-preserving evidence-path rotation does not overblock", func(t *testing.T) {
		req := requestFor(t)
		adapter := newTemporalFencedAdapter(req.Current, req.Transition.To)

		prep, err := gaRuntime.ReserveFenced(context.Background(), req, adapter)
		if err != nil {
			t.Fatal(err)
		}

		rotatedObserver := gaRuntime.Identity{ID: "observer:rotated", Kind: "observer"}
		adapter.trusted[rotatedObserver.ID] = true
		adapter.afterCrossing = func() {
			// This rotates the trusted post-effect evidence path while leaving
			// the admitted subject, exact target state, transition and current
			// admission authority unchanged.
			adapter.observationIssuer = rotatedObserver
		}

		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, adapter)
		if result.Disposition != gaRuntime.DispositionClosed {
			t.Fatalf("standing-preserving delta was overblocked: %+v", result)
		}
		if !result.BoundaryEntered || adapter.effectCalls != 1 || adapter.observeCalls != 1 {
			t.Fatalf("standing-preserving path did not execute and close exactly once: %+v", result)
		}
		if result.Custody.Phase != gaRuntime.CustodyClosed {
			t.Fatalf("standing-preserving path did not reach CLOSED custody: %+v", result.Custody)
		}
	})
}

type closureAdapter struct {
	current gaRuntime.State
	after   gaRuntime.State

	trusted map[string]bool
	retained map[string]gaRuntime.Custody

	effectCalls  int
	observeCalls int

	observationErr error
}

func newClosureAdapter(current, after gaRuntime.State) *closureAdapter {
	return &closureAdapter{
		current: current,
		after:   after,
		trusted: map[string]bool{
			policyIssuer.ID:   true,
			observerIssuer.ID: true,
		},
		retained: make(map[string]gaRuntime.Custody),
	}
}

func (a *closureAdapter) CurrentState(context.Context, string) (gaRuntime.State, error) {
	return a.current, nil
}

func (a *closureAdapter) VerifyAttestation(_ context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return errors.New("binding digest mismatch")
	}
	if !a.trusted[att.Issuer.ID] {
		return errUntrusted
	}
	return nil
}

func (a *closureAdapter) RetainCustody(_ context.Context, custody gaRuntime.Custody) error {
	key := fencedKey(custody.EffectID, custody.AttemptID)
	if _, exists := a.retained[key]; exists {
		return errDuplicate
	}
	a.retained[key] = custody
	return nil
}

func (a *closureAdapter) LoadCustody(_ context.Context, effectID, attemptID string) (gaRuntime.Custody, error) {
	custody, ok := a.retained[fencedKey(effectID, attemptID)]
	if !ok {
		return gaRuntime.Custody{}, gaRuntime.ErrMissingRecoveryCustody
	}
	return custody, nil
}

func (a *closureAdapter) Execute(context.Context, gaRuntime.Transition, gaRuntime.Custody) (gaRuntime.Acceptance, error) {
	a.effectCalls++
	return gaRuntime.Acceptance{Reference: "provider:accepted"}, nil
}

func (a *closureAdapter) Observe(_ context.Context, _ gaRuntime.Transition, custody gaRuntime.Custody) (gaRuntime.Observation, error) {
	a.observeCalls++
	if a.observationErr != nil {
		return gaRuntime.Observation{}, a.observationErr
	}
	return gaRuntime.Observation{
		State: a.after,
		Attestation: gaRuntime.Attestation{
			ID:            "observation:closure",
			Issuer:        observerIssuer,
			BindingDigest: gaRuntime.ObservationBindingDigest(custody.EffectID, a.after),
		},
	}, nil
}

func TestEffectClosureExtensionHeldOut(t *testing.T) {
	req := requestFor(t)
	adapter := newClosureAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObservation

	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("provider acceptance without effect evidence must remain UNKNOWN: %+v", first)
	}
	if !first.BoundaryEntered || first.Acceptance.Reference == "" || adapter.effectCalls != 1 {
		t.Fatalf("test requires one entered provider call: %+v", first)
	}

	custody, err := adapter.LoadCustody(context.Background(), first.EffectID, req.AttemptID)
	if err != nil {
		t.Fatalf("load retained custody: %v", err)
	}

	recoveryIssuer := gaRuntime.Identity{ID: "recovery:temporal-conformance", Kind: "controller"}
	recoverer := gaRuntime.Identity{ID: "process:reconciler", Kind: "process"}
	adapter.trusted[recoveryIssuer.ID] = true
	adapter.observationErr = nil

	recovery := gaRuntime.RecoveryRequest{
		Original:  req,
		Recoverer: recoverer,
		RecoveryAuthorization: gaRuntime.Attestation{
			ID:            "recovery-auth:temporal-001",
			Issuer:        recoveryIssuer,
			BindingDigest: gaRuntime.RecoveryBindingDigest(custody, recoverer),
		},
	}

	closed := gaRuntime.Recover(context.Background(), recovery, adapter)
	if closed.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("fresh exact observation did not close retained UNKNOWN effect: %+v", closed)
	}
	if closed.BoundaryEntered {
		t.Fatalf("observation-only recovery entered a new effect boundary: %+v", closed)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("recovery dispatched a second effect: %d", adapter.effectCalls)
	}
	if adapter.observeCalls != 2 {
		t.Fatalf("expected failed initial observation plus one recovery observation, got %d", adapter.observeCalls)
	}
}
