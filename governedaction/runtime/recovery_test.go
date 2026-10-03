package runtime_test

import (
	"context"
	"errors"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

var recoveryIssuer = gaRuntime.Identity{ID: "recovery:controller", Kind: "controller"}

func (a *fakeAdapter) LoadCustody(_ context.Context, effectID, attemptID string) (gaRuntime.Custody, error) {
	key := effectID + "\x00" + attemptID
	custody, ok := a.retained[key]
	if !ok {
		return gaRuntime.Custody{}, gaRuntime.ErrMissingRecoveryCustody
	}
	return custody, nil
}

func recoveryRequestFor(t *testing.T, original gaRuntime.Request, adapter *fakeAdapter, recoverer gaRuntime.Identity) gaRuntime.RecoveryRequest {
	t.Helper()

	effectID, err := gaRuntime.EffectIdentity(original)
	if err != nil {
		t.Fatalf("effect identity: %v", err)
	}
	custody, err := adapter.LoadCustody(context.Background(), effectID, original.AttemptID)
	if err != nil {
		t.Fatalf("load custody: %v", err)
	}
	adapter.trusted[recoveryIssuer.ID] = true

	return gaRuntime.RecoveryRequest{
		Original:  original,
		Recoverer: recoverer,
		RecoveryAuthorization: gaRuntime.Attestation{
			ID:            "recovery-auth:001",
			Issuer:        recoveryIssuer,
			BindingDigest: gaRuntime.RecoveryBindingDigest(custody, recoverer),
		},
	}
}

func TestCrashAfterEffectThenRecoveryClosesWithoutReplay(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve

	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("first invocation should be UNKNOWN after observation loss: %+v", first)
	}
	if !first.CustodyRecorded || !first.BoundaryEntered || adapter.effectCalls != 1 {
		t.Fatalf("first invocation did not cross the intended crash window: %+v calls=%d", first, adapter.effectCalls)
	}

	// Simulate process restart: the external effect may already exist, but
	// observation becomes available again. Recovery must not call Execute.
	adapter.observationErr = nil
	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)

	recovered := gaRuntime.Recover(context.Background(), recovery, adapter)
	if recovered.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("exact post-restart observation did not close: %+v", recovered)
	}
	if !recovered.CustodyRecorded {
		t.Fatalf("recovery did not reconstruct exact durable custody: %+v", recovered)
	}
	if recovered.BoundaryEntered {
		t.Fatalf("observation-only recovery entered a new effect boundary: %+v", recovered)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("recovery replayed the effect: effect calls=%d", adapter.effectCalls)
	}
}

func TestRecoveryObservationFailureRemainsUnknownAndNeverRetries(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve

	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("first invocation should be UNKNOWN: %+v", first)
	}

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)
	recovered := gaRuntime.Recover(context.Background(), recovery, adapter)

	if recovered.Disposition != gaRuntime.DispositionUnknown || !errors.Is(recovered.Cause, errObserve) {
		t.Fatalf("unobservable recovery did not remain UNKNOWN: %+v", recovered)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("UNKNOWN recovery retried the effect: %d", adapter.effectCalls)
	}
}

func TestRecoveryRequiresFreshBoundAuthorization(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", first)
	}
	adapter.observationErr = nil

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)

	// A restart/wakeup alone is not continuation authority.
	recovery.RecoveryAuthorization = gaRuntime.Attestation{}
	got := gaRuntime.Recover(context.Background(), recovery, adapter)
	if got.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(got.Cause, gaRuntime.ErrIncompleteRecoveryRequest) {
		t.Fatalf("missing recovery authorization did not fail closed: %+v", got)
	}
	if adapter.effectCalls != 1 {
		t.Fatal("missing recovery authorization caused replay")
	}
}

func TestRecovererSubstitutionInvalidatesRecoveryAuthorization(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	if got := gaRuntime.Run(context.Background(), req, adapter); got.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", got)
	}
	adapter.observationErr = nil

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)
	recovery.Recoverer = gaRuntime.Identity{ID: "process:other", Kind: "process"}

	got := gaRuntime.Recover(context.Background(), recovery, adapter)
	if got.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(got.Cause, gaRuntime.ErrRecoveryBinding) {
		t.Fatalf("recoverer substitution retained recovery authority: %+v", got)
	}
	if adapter.effectCalls != 1 {
		t.Fatal("recoverer substitution caused replay")
	}
}

func TestRecoveryRejectsTamperedDurableCustody(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", first)
	}

	key := first.EffectID + "\x00" + req.AttemptID
	custody := adapter.retained[key]
	custody.Target = "github:other/repo#145"
	adapter.retained[key] = custody

	recovery := gaRuntime.RecoveryRequest{
		Original:  req,
		Recoverer: gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"},
		RecoveryAuthorization: gaRuntime.Attestation{
			ID:            "recovery-auth:tampered",
			Issuer:        recoveryIssuer,
			BindingDigest: gaRuntime.RecoveryBindingDigest(custody, gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}),
		},
	}
	adapter.trusted[recoveryIssuer.ID] = true

	got := gaRuntime.Recover(context.Background(), recovery, adapter)
	if got.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(got.Cause, gaRuntime.ErrRecoveryCustodyMismatch) {
		t.Fatalf("tampered custody was accepted: %+v", got)
	}
	if adapter.effectCalls != 1 {
		t.Fatal("tampered custody caused replay")
	}
}

func TestRecoveryCannotSwapAttemptIdentity(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", first)
	}

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)
	recovery.Original.AttemptID = "attempt:other"

	got := gaRuntime.Recover(context.Background(), recovery, adapter)
	if got.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(got.Cause, gaRuntime.ErrMissingRecoveryCustody) {
		t.Fatalf("attempt substitution recovered another custody record: %+v", got)
	}
	if adapter.effectCalls != 1 {
		t.Fatal("attempt substitution caused replay")
	}
}

func TestRecoveryProviderHistoryMismatchRemainsUnknown(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	if got := gaRuntime.Run(context.Background(), req, adapter); got.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", got)
	}

	wrong := req.Transition.To
	wrong.Revision = "merged:other"
	wrong.Digest = "sha256:other"
	adapter.observationErr = nil
	adapter.observationState = wrong

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)
	got := gaRuntime.Recover(context.Background(), recovery, adapter)

	if got.Disposition != gaRuntime.DispositionUnknown ||
		!errors.Is(got.Cause, gaRuntime.ErrObservedStateMismatch) {
		t.Fatalf("mismatched recovery observation manufactured closure: %+v", got)
	}
	if adapter.effectCalls != 1 {
		t.Fatal("mismatched observation caused replay")
	}
}

func TestRecoveryAuthorizationIsNotNewEffectAuthority(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = errObserve
	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("setup failed: %+v", first)
	}
	adapter.observationErr = nil

	recoverer := gaRuntime.Identity{ID: "process:recovery-2", Kind: "process"}
	recovery := recoveryRequestFor(t, req, adapter, recoverer)
	got := gaRuntime.Recover(context.Background(), recovery, adapter)
	if got.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("recovery did not close exact effect: %+v", got)
	}

	// Even repeated valid recovery may re-observe but can never dispatch.
	second := gaRuntime.Recover(context.Background(), recovery, adapter)
	if second.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("repeat observation-only recovery changed truth: %+v", second)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("recovery authorization became effect authority: %d calls", adapter.effectCalls)
	}
}
