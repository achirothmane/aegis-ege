package runtime

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrMissingRecoveryAdapter    = errors.New("reference runtime recovery adapter is required")
	ErrMissingRecoveryCustody    = errors.New("recovery custody is unavailable")
	ErrRecoveryCustodyMismatch   = errors.New("recovery custody does not match the exact effect attempt")
	ErrRecoveryBinding           = errors.New("recovery attestation binding does not match the exact custody")
	ErrIncompleteRecoveryRequest = errors.New("recovery request is incomplete")
)

// RecoveryRequest is an observation-only continuation for one previously
// retained effect attempt.
//
// RecoveryAuthorization is deliberately distinct from the original Admission.
// A wakeup/restart does not inherit permission merely because the original
// request was once admissible.
//
// Recoverer may equal the original executor identity or may be a distinct
// recovery principal. Either way, the recovery authorization must bind the exact
// retained custody and recoverer.
type RecoveryRequest struct {
	Original              Request
	Recoverer             Identity
	RecoveryAuthorization Attestation
}

// RecoveryAdapter extends the execution adapter with exact durable custody
// lookup. LoadCustody must return the retained record for the exact
// effectID/attemptID pair or fail closed.
//
// Recovery does not dispatch, retry, compensate, mutate custody ownership or
// create a replacement attempt. Those require separate governed transitions.
type RecoveryAdapter interface {
	Adapter
	LoadCustody(context.Context, string, string) (Custody, error)
}

// Recover resumes only the epistemic/closure side of a previously retained
// attempt. It never calls Execute.
//
// The allowed path is:
//
//	exact original request
//	  -> derive exact EffectID
//	  -> load exact durable custody
//	  -> verify fresh recovery authorization
//	  -> observe
//	  -> CLOSED | UNKNOWN
//
// Missing/mismatched custody or recovery authorization is REJECTED. Once exact
// custody is recovered, inability to prove the intended after-state remains
// UNKNOWN rather than becoming safe retry permission.
func Recover(ctx context.Context, req RecoveryRequest, adapter RecoveryAdapter) Result {
	result := Result{
		Disposition: DispositionRejected,
		AttemptID:   req.Original.AttemptID,
	}
	if adapter == nil {
		result.Cause = ErrMissingRecoveryAdapter
		return result
	}
	if err := validateRecoveryRequest(req); err != nil {
		result.Cause = err
		return result
	}

	effectID, err := EffectIdentity(req.Original)
	if err != nil {
		result.Cause = err
		return result
	}
	result.EffectID = effectID

	custody, err := adapter.LoadCustody(ctx, effectID, req.Original.AttemptID)
	if err != nil {
		result.Cause = err
		return result
	}
	if err := validateRecoveredCustody(req.Original, effectID, custody); err != nil {
		result.Cause = err
		return result
	}
	result.CustodyRecorded = true

	expectedRecovery := RecoveryBindingDigest(custody, req.Recoverer)
	if req.RecoveryAuthorization.BindingDigest != expectedRecovery {
		result.Cause = ErrRecoveryBinding
		return result
	}
	if err := adapter.VerifyAttestation(ctx, req.RecoveryAuthorization, expectedRecovery); err != nil {
		result.Cause = err
		return result
	}

	// Recovery is observation-only. BoundaryEntered describes this invocation,
	// therefore it remains false. The retained custody proves only that the
	// pre-effect ownership record existed; it does not by itself prove the
	// original effect callback was entered.
	result.Disposition = DispositionUnknown

	observation, observeErr := adapter.Observe(ctx, req.Original.Transition, custody)
	result.Observation = observation
	result.ObservationError = observeErr
	if observeErr != nil {
		result.Cause = observeErr
		return result
	}
	if err := verifyObservation(ctx, effectID, req.Original.Transition.To, observation, adapter.VerifyAttestation); err != nil {
		result.Cause = err
		return result
	}

	result.Disposition = DispositionClosed
	result.Cause = nil
	return result
}

func validateRecoveryRequest(req RecoveryRequest) error {
	if err := validateRequest(req.Original); err != nil {
		return err
	}
	if !req.Recoverer.Complete() || !req.RecoveryAuthorization.Complete() {
		return ErrIncompleteRecoveryRequest
	}
	return nil
}

func validateRecoveredCustody(original Request, effectID string, custody Custody) error {
	if strings.TrimSpace(custody.EffectID) == "" ||
		strings.TrimSpace(custody.AttemptID) == "" ||
		strings.TrimSpace(custody.Target) == "" ||
		!custody.Owner.Complete() {
		return ErrMissingRecoveryCustody
	}
	if custody.EffectID != effectID ||
		custody.AttemptID != original.AttemptID ||
		custody.Target != original.Current.Target ||
		!custody.Owner.Equal(original.Executor) {
		return ErrRecoveryCustodyMismatch
	}
	return nil
}

// RecoveryBindingDigest binds fresh continuation authority to one exact durable
// custody record and one exact recovery principal.
//
// It intentionally does not authorize another effect. It authorizes only the
// observation-only Recover path for this retained effect attempt.
func RecoveryBindingDigest(custody Custody, recoverer Identity) string {
	return digest(
		"recovery-v1",
		custody.EffectID,
		custody.AttemptID,
		custody.Target,
		custody.Owner.ID,
		custody.Owner.Kind,
		recoverer.ID,
		recoverer.Kind,
	)
}

// Equal compares opaque identity values exactly.
func (i Identity) Equal(other Identity) bool {
	return i.ID == other.ID && i.Kind == other.Kind
}
