package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CustodyPhase is runtime state, not a new semantic primitive. It records the
// durable relationship between one exact effect attempt and the effect boundary.
type CustodyPhase string

const (
	CustodyReserved CustodyPhase = "RESERVED"
	CustodyCrossing CustodyPhase = "CROSSING"
	CustodyUnknown  CustodyPhase = "UNKNOWN"
	CustodyClosed   CustodyPhase = "CLOSED"
)

var (
	ErrMissingFencedAdapter      = errors.New("fenced runtime adapter is required")
	ErrIncompleteFencedCustody   = errors.New("fenced custody is incomplete")
	ErrFencedCustodyMismatch     = errors.New("fenced custody does not match the exact effect attempt")
	ErrCustodyNotReserved        = errors.New("custody is not in RESERVED phase")
	ErrTakeoverBinding           = errors.New("takeover attestation binding does not match the exact custody transfer")
	ErrIncompleteTakeoverRequest = errors.New("takeover request is incomplete")
	ErrFenceGenerationExhausted  = errors.New("custody fence generation is exhausted")
)

// FencedCustody is the durable ownership state for one exact effect attempt.
// Generation is a monotonic fencing token. Phase makes the crash boundary
// explicit:
//
//   RESERVED -> no effect has been allowed to enter through this runtime path.
//   CROSSING -> effect boundary entry may be in progress or may have happened.
//   UNKNOWN  -> effect may have happened; exact closure is not yet established.
//   CLOSED   -> exact trusted observation established the intended after-state.
//
// Only RESERVED may transfer execution ownership. CROSSING and UNKNOWN may be
// observed/reconciled, but they may not be reopened as executable custody.
type FencedCustody struct {
	EffectID   string
	AttemptID  string
	Target     string
	Owner      Identity
	Generation uint64
	Phase      CustodyPhase
}

func (c FencedCustody) Complete() bool {
	return strings.TrimSpace(c.EffectID) != "" &&
		strings.TrimSpace(c.AttemptID) != "" &&
		strings.TrimSpace(c.Target) != "" &&
		c.Owner.Complete() &&
		c.Generation > 0 &&
		validCustodyPhase(c.Phase)
}

func (c FencedCustody) Equal(other FencedCustody) bool {
	return c.EffectID == other.EffectID &&
		c.AttemptID == other.AttemptID &&
		c.Target == other.Target &&
		c.Owner.Equal(other.Owner) &&
		c.Generation == other.Generation &&
		c.Phase == other.Phase
}

func validCustodyPhase(phase CustodyPhase) bool {
	switch phase {
	case CustodyReserved, CustodyCrossing, CustodyUnknown, CustodyClosed:
		return true
	default:
		return false
	}
}

// FencedAdapter supplies a native linearization/fencing substrate for the
// reference runtime.
//
// ReserveFencedCustody must atomically create one exact durable record.
//
// TransitionFencedCustodyCAS must compare the complete expected record and
// atomically replace it with next. A stale owner/generation/phase must fail.
//
// ExecuteFenced must enforce the exact Owner + Generation at the native effect
// boundary. Merely checking the token in userspace before a provider call is
// insufficient; a transfer can race between check and use.
//
// ObserveFenced returns typed post-state evidence for the exact effect attempt.
type FencedAdapter interface {
	CurrentState(context.Context, string) (State, error)
	VerifyAttestation(context.Context, Attestation, string) error
	ReserveFencedCustody(context.Context, FencedCustody) error
	LoadFencedCustody(context.Context, string, string) (FencedCustody, error)
	TransitionFencedCustodyCAS(context.Context, FencedCustody, FencedCustody) error
	ExecuteFenced(context.Context, Transition, FencedCustody) (Acceptance, error)
	ObserveFenced(context.Context, Transition, FencedCustody) (Observation, error)
}

type FencedPreparation struct {
	Custody         FencedCustody
	CustodyRecorded bool
}

type FencedResult struct {
	Result
	Custody FencedCustody
}

// ReserveFenced creates initial RESERVED custody with generation 1.
//
// The request is checked before and after the durable reservation. If the
// second check fails, the RESERVED record remains durable, but no effect has
// entered. A later takeover still has to revalidate the request before use.
func ReserveFenced(ctx context.Context, req Request, adapter FencedAdapter) (FencedPreparation, error) {
	prep := FencedPreparation{}
	if adapter == nil {
		return prep, ErrMissingFencedAdapter
	}
	if err := validateRequest(req); err != nil {
		return prep, err
	}
	if err := checkRequestAtBoundary(ctx, req, adapter); err != nil {
		return prep, fmt.Errorf("before fenced custody: %w", err)
	}

	effectID, err := EffectIdentity(req)
	if err != nil {
		return prep, err
	}
	custody := FencedCustody{
		EffectID:   effectID,
		AttemptID:  req.AttemptID,
		Target:     req.Current.Target,
		Owner:      req.Executor,
		Generation: 1,
		Phase:      CustodyReserved,
	}
	if err := adapter.ReserveFencedCustody(ctx, custody); err != nil {
		return prep, fmt.Errorf("reserve fenced custody: %w", err)
	}
	prep.Custody = custody
	prep.CustodyRecorded = true

	if err := checkRequestAtBoundary(ctx, req, adapter); err != nil {
		return prep, fmt.Errorf("after fenced custody: %w", err)
	}
	return prep, nil
}

// ExecuteReservedFenced consumes one exact RESERVED ownership record.
//
// The durable transition to CROSSING happens before the effect callback. If the
// process disappears after that transition, later code cannot treat the record
// as safe-to-replay RESERVED custody.
//
// ExecuteFenced receives the exact crossing generation and must enforce it at
// the native effect boundary. A late former owner therefore cannot execute
// after an atomic takeover has advanced the generation.
func ExecuteReservedFenced(ctx context.Context, req Request, custody FencedCustody, adapter FencedAdapter) FencedResult {
	result := FencedResult{
		Result: Result{
			Disposition:     DispositionRejected,
			AttemptID:       req.AttemptID,
			CustodyRecorded: custody.Complete(),
		},
		Custody: custody,
	}
	if adapter == nil {
		result.Cause = ErrMissingFencedAdapter
		return result
	}
	if err := validateRequest(req); err != nil {
		result.Cause = err
		return result
	}

	effectID, err := EffectIdentity(req)
	if err != nil {
		result.Cause = err
		return result
	}
	result.EffectID = effectID

	if err := validateFencedCustody(req, effectID, custody); err != nil {
		result.Cause = err
		return result
	}
	if custody.Phase != CustodyReserved {
		result.Cause = ErrCustodyNotReserved
		return result
	}
	if err := checkRequestAtBoundary(ctx, req, adapter); err != nil {
		result.Cause = err
		return result
	}

	current, err := adapter.LoadFencedCustody(ctx, effectID, req.AttemptID)
	if err != nil {
		result.Cause = err
		return result
	}
	if !current.Equal(custody) {
		result.Cause = ErrFencedCustodyMismatch
		return result
	}

	crossing := custody
	crossing.Phase = CustodyCrossing
	if err := adapter.TransitionFencedCustodyCAS(ctx, custody, crossing); err != nil {
		result.Cause = err
		return result
	}
	result.Custody = crossing

	// Loading and committing custody may block. Revalidate after those calls,
	// before entering the effect callback. A denial keeps CROSSING durable:
	// never reopen this record for replay merely because this process knows
	// it did not call the provider.
	if err := checkRequestAtBoundary(ctx, req, adapter); err != nil {
		result.Cause = fmt.Errorf("after crossing custody: %w", err)
		return result
	}
	if err := ctx.Err(); err != nil {
		result.Cause = err
		return result
	}

	result.BoundaryEntered = true
	acceptance, effectErr := adapter.ExecuteFenced(ctx, req.Transition, crossing)
	result.Acceptance = acceptance
	result.EffectError = effectErr
	result.Disposition = DispositionUnknown

	unknown := crossing
	unknown.Phase = CustodyUnknown
	if err := adapter.TransitionFencedCustodyCAS(ctx, crossing, unknown); err != nil {
		result.Cause = fmt.Errorf("mark custody unknown: %w", err)
		return result
	}
	result.Custody = unknown

	observation, observeErr := adapter.ObserveFenced(ctx, req.Transition, unknown)
	result.Observation = observation
	result.ObservationError = observeErr
	if observeErr != nil {
		result.Cause = observeErr
		return result
	}
	if !observation.State.Complete() || !observation.Attestation.Complete() {
		result.Cause = ErrIncompleteObservation
		return result
	}

	expectedObservation := ObservationBindingDigest(effectID, observation.State)
	if observation.Attestation.BindingDigest != expectedObservation {
		result.Cause = ErrObservationBinding
		return result
	}
	if err := adapter.VerifyAttestation(ctx, observation.Attestation, expectedObservation); err != nil {
		result.Cause = err
		return result
	}
	if !observation.State.Equal(req.Transition.To) {
		result.Cause = ErrObservedStateMismatch
		return result
	}

	closed := unknown
	closed.Phase = CustodyClosed
	if err := adapter.TransitionFencedCustodyCAS(ctx, unknown, closed); err != nil {
		result.Cause = fmt.Errorf("close fenced custody: %w", err)
		return result
	}
	result.Custody = closed
	result.Disposition = DispositionClosed
	result.Cause = nil
	return result
}

// RunFenced is a convenience composition of ReserveFenced and
// ExecuteReservedFenced. The split API exists so crash-window tests and durable
// schedulers can stop after reservation without pretending an effect entered.
func RunFenced(ctx context.Context, req Request, adapter FencedAdapter) FencedResult {
	prep, err := ReserveFenced(ctx, req, adapter)
	if err != nil {
		return FencedResult{
			Result: Result{
				Disposition:     DispositionRejected,
				AttemptID:       req.AttemptID,
				CustodyRecorded: prep.CustodyRecorded,
				Cause:           err,
			},
			Custody: prep.Custody,
		}
	}
	return ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
}

// TakeoverRequest transfers only still-RESERVED custody.
//
// Authorization is fresh and exact. Possession of an old request, an old
// admission attestation, or a process restart is not takeover authority.
type TakeoverRequest struct {
	Original      Request
	NewOwner      Identity
	Authorization Attestation
}

type TakeoverResult struct {
	Previous FencedCustody
	Current  FencedCustody
}

// TakeoverReserved atomically transfers one exact RESERVED record and advances
// its monotonic fencing generation.
//
// CROSSING, UNKNOWN and CLOSED are deliberately non-transferable for execution.
// They may be observed/reconciled, but cannot be converted back into executable
// RESERVED custody by this operation.
func TakeoverReserved(ctx context.Context, req TakeoverRequest, adapter FencedAdapter) (TakeoverResult, error) {
	result := TakeoverResult{}
	if adapter == nil {
		return result, ErrMissingFencedAdapter
	}
	if err := validateRequest(req.Original); err != nil {
		return result, err
	}
	if !req.NewOwner.Complete() || !req.Authorization.Complete() {
		return result, ErrIncompleteTakeoverRequest
	}

	effectID, err := EffectIdentity(req.Original)
	if err != nil {
		return result, err
	}
	current, err := adapter.LoadFencedCustody(ctx, effectID, req.Original.AttemptID)
	if err != nil {
		return result, err
	}
	result.Previous = current

	if err := validateFencedCustody(req.Original, effectID, current); err != nil {
		return result, err
	}
	if current.Phase != CustodyReserved {
		return result, ErrCustodyNotReserved
	}
	if current.Generation == ^uint64(0) {
		return result, ErrFenceGenerationExhausted
	}

	expected := TakeoverBindingDigest(current, req.NewOwner)
	if req.Authorization.BindingDigest != expected {
		return result, ErrTakeoverBinding
	}
	if err := adapter.VerifyAttestation(ctx, req.Authorization, expected); err != nil {
		return result, err
	}

	next := current
	next.Owner = req.NewOwner
	next.Generation++
	if err := adapter.TransitionFencedCustodyCAS(ctx, current, next); err != nil {
		return result, err
	}
	result.Current = next
	return result, nil
}

// TakeoverBindingDigest binds transfer authority to the complete currently
// retained record and the exact next owner/generation.
func TakeoverBindingDigest(current FencedCustody, newOwner Identity) string {
	nextGeneration := current.Generation + 1
	return digest(
		"takeover-v1",
		current.EffectID,
		current.AttemptID,
		current.Target,
		current.Owner.ID,
		current.Owner.Kind,
		fmt.Sprintf("%d", current.Generation),
		string(current.Phase),
		newOwner.ID,
		newOwner.Kind,
		fmt.Sprintf("%d", nextGeneration),
	)
}

func checkRequestAtBoundary(ctx context.Context, req Request, adapter interface {
	CurrentState(context.Context, string) (State, error)
	VerifyAttestation(context.Context, Attestation, string) error
}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := adapter.CurrentState(ctx, req.Current.Target)
	if err != nil {
		return err
	}
	if !current.Equal(req.Current) {
		return ErrStateChanged
	}
	expected, err := AdmissionBindingDigest(req)
	if err != nil {
		return err
	}
	if req.Admission.BindingDigest != expected {
		return ErrAdmissionBinding
	}
	return adapter.VerifyAttestation(ctx, req.Admission, expected)
}

func validateFencedCustody(req Request, effectID string, custody FencedCustody) error {
	if !custody.Complete() {
		return ErrIncompleteFencedCustody
	}
	if custody.EffectID != effectID ||
		custody.AttemptID != req.AttemptID ||
		custody.Target != req.Current.Target ||
		!custody.Owner.Equal(req.Executor) {
		return ErrFencedCustodyMismatch
	}
	return nil
}
