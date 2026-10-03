// Package runtime is an experimental reference executable runtime built from
// the four semantic primitive types that survived the primitive-reduction
// corpus: Identity, State, Attestation and Transition.
//
// It is deliberately non-normative. The frozen governed-action v1 contract
// remains authoritative. This package composes the existing governedaction
// effect-boundary ordering with a minimal semantic surface; it does not create
// a policy engine, identity service, durable store, observer or trust root.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

var (
	ErrMissingAdapter        = errors.New("reference runtime adapter is required")
	ErrIncompleteRequest     = errors.New("reference runtime request is incomplete")
	ErrTransitionBinding     = errors.New("transition is not bound to the exact current state")
	ErrAdmissionBinding      = errors.New("admission attestation binding does not match the request")
	ErrStateChanged          = errors.New("current state changed at the effect boundary")
	ErrObservationBinding    = errors.New("observation attestation binding does not match the observed state")
	ErrObservedStateMismatch = errors.New("trusted observation does not match the intended after-state")
	ErrIncompleteObservation = errors.New("observation is incomplete")
)

// Identity is an opaque principal identity. Subject and executor are separate
// instances of the same primitive type.
type Identity struct {
	ID   string
	Kind string
}

func (i Identity) Complete() bool {
	return strings.TrimSpace(i.ID) != "" && strings.TrimSpace(i.Kind) != ""
}

// State identifies one exact revision of one target.
type State struct {
	Target   string
	Revision string
	Digest   string
}

func (s State) Complete() bool {
	return strings.TrimSpace(s.Target) != "" &&
		strings.TrimSpace(s.Revision) != "" &&
		strings.TrimSpace(s.Digest) != ""
}

func (s State) Equal(other State) bool {
	return s.Target == other.Target &&
		s.Revision == other.Revision &&
		s.Digest == other.Digest
}

// Attestation is a provenance-bearing reference to a trusted statement.
// Signature formats, key discovery, revocation and trust roots remain adapter
// responsibilities. BindingDigest prevents the runtime from treating a valid
// attestation for another relation as authority for this one.
type Attestation struct {
	ID            string
	Issuer        Identity
	BindingDigest string
}

func (a Attestation) Complete() bool {
	return strings.TrimSpace(a.ID) != "" &&
		a.Issuer.Complete() &&
		strings.TrimSpace(a.BindingDigest) != ""
}

// Transition identifies the exact requested effect relation.
type Transition struct {
	Operation string
	From      State
	To        State
}

func (t Transition) Complete() bool {
	return strings.TrimSpace(t.Operation) != "" &&
		t.From.Complete() &&
		t.To.Complete()
}

// Request is a composite relation built only from the four primitive types.
// AttemptID is runtime bookkeeping, not a fifth semantic primitive.
type Request struct {
	Subject    Identity
	Executor   Identity
	Current    State
	Admission  Attestation
	Transition Transition
	AttemptID  string
}

// Custody is a composite runtime record. Durable cardinality, atomic reservation
// and fencing are supplied by the adapter's native substrate.
type Custody struct {
	EffectID  string
	AttemptID string
	Target    string
	Owner     Identity
}

// Acceptance is only a provider/adapter call fact. It never proves the intended
// postcondition.
type Acceptance struct {
	Reference string
}

// Observation is a State plus an Attestation over that exact observation.
type Observation struct {
	State       State
	Attestation Attestation
}

// Adapter supplies domain-owned trust and native enforcement. RetainCustody
// must durably and atomically retain the same effect/attempt/owner before an
// effect may escape. It must reject unsafe duplicate reservations.
//
// CurrentState and VerifyAttestation are called at the actual boundary through
// the existing governedaction PrepareEffect/Dispatch ordering.
//
// Observe must not claim success merely because Execute returned nil. It returns
// a typed state observation; the runtime closes only on an exact intended
// after-state with a valid observation attestation.
type Adapter interface {
	CurrentState(context.Context, string) (State, error)
	VerifyAttestation(context.Context, Attestation, string) error
	RetainCustody(context.Context, Custody) error
	Execute(context.Context, Transition, Custody) (Acceptance, error)
	Observe(context.Context, Transition, Custody) (Observation, error)
}

// Disposition is the reference runtime's conservative current knowledge.
type Disposition string

const (
	DispositionRejected Disposition = "REJECTED"
	DispositionUnknown  Disposition = "UNKNOWN"
	DispositionClosed   Disposition = "CLOSED"
)

// Result keeps execution facts distinct from epistemic disposition.
type Result struct {
	Disposition     Disposition
	EffectID        string
	AttemptID       string
	CustodyRecorded bool
	BoundaryEntered bool
	Acceptance      Acceptance
	Observation     Observation

	// Cause is a pre-boundary rejection or closure-verification failure.
	Cause error
	// EffectError is preserved even when a later exact trusted observation
	// closes the intended-state obligation.
	EffectError error
	// ObservationError records failure to obtain a trusted observation.
	ObservationError error
}

// Run executes one bounded attempt. It never retries.
//
// REJECTED means the effect callback was not entered.
// UNKNOWN means an effect may have happened but exact trusted closure evidence
// is unavailable.
// CLOSED means an exact trusted observation matches Transition.To.
//
// A provider success return cannot produce CLOSED by itself. Conversely, a
// provider error may still end CLOSED when an exact trusted observation proves
// the intended after-state.
func Run(ctx context.Context, req Request, adapter Adapter) Result {
	result := Result{
		Disposition: DispositionRejected,
		AttemptID:   req.AttemptID,
	}
	if adapter == nil {
		result.Cause = ErrMissingAdapter
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

	custody := Custody{
		EffectID:  effectID,
		AttemptID: req.AttemptID,
		Target:    req.Current.Target,
		Owner:     req.Executor,
	}

	check := func(checkCtx context.Context) error {
		current, err := adapter.CurrentState(checkCtx, req.Current.Target)
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
		return adapter.VerifyAttestation(checkCtx, req.Admission, expected)
	}

	retain := func(retainCtx context.Context) error {
		return adapter.RetainCustody(retainCtx, custody)
	}

	dispatch, dispatchErr := ga.Dispatch(
		ctx,
		check,
		retain,
		func(effectCtx context.Context) (Acceptance, error) {
			return adapter.Execute(effectCtx, req.Transition, custody)
		},
	)
	result.CustodyRecorded = dispatch.CustodyRecorded
	result.BoundaryEntered = dispatch.BoundaryEntered
	result.Acceptance = dispatch.Value
	result.EffectError = dispatchErr

	if !dispatch.BoundaryEntered {
		result.Disposition = DispositionRejected
		result.Cause = dispatchErr
		return result
	}

	result.Disposition = DispositionUnknown

	observation, observeErr := adapter.Observe(ctx, req.Transition, custody)
	result.Observation = observation
	result.ObservationError = observeErr
	if observeErr != nil {
		result.Cause = observeErr
		return result
	}
	if err := verifyObservation(ctx, effectID, req.Transition.To, observation, adapter.VerifyAttestation); err != nil {
		result.Cause = err
		return result
	}

	result.Disposition = DispositionClosed
	result.Cause = nil
	return result
}

func validateRequest(req Request) error {
	if !req.Subject.Complete() ||
		!req.Executor.Complete() ||
		!req.Current.Complete() ||
		!req.Admission.Complete() ||
		!req.Transition.Complete() ||
		strings.TrimSpace(req.AttemptID) == "" {
		return ErrIncompleteRequest
	}
	if !req.Transition.From.Equal(req.Current) ||
		req.Transition.To.Target != req.Current.Target {
		return ErrTransitionBinding
	}
	expected, err := AdmissionBindingDigest(req)
	if err != nil {
		return err
	}
	if req.Admission.BindingDigest != expected {
		return ErrAdmissionBinding
	}
	return nil
}

// EffectIdentity binds subject + exact current state + exact transition while
// deliberately excluding the authorization path. Two trusted attestations for
// the same logical effect therefore do not manufacture two effect identities.
func EffectIdentity(req Request) (string, error) {
	return requestBinding(req, "effect-v0")
}

// AdmissionBindingDigest is the statement a trusted admission producer signs or
// otherwise attests. Executor identity is intentionally not implied by subject
// authority; adapters may require an additional executor binding in their
// attestation verifier when their profile demands it.
func AdmissionBindingDigest(req Request) (string, error) {
	return requestBinding(req, "admission-v0")
}

// The two bindings share an exact request projection, but retain distinct
// domains: an effect identity cannot serve as an admission statement.
func requestBinding(req Request, domain string) (string, error) {
	if !req.Subject.Complete() ||
		!req.Current.Complete() ||
		!req.Transition.Complete() ||
		!req.Transition.From.Equal(req.Current) ||
		req.Transition.To.Target != req.Current.Target {
		return "", ErrTransitionBinding
	}
	return digest(
		domain,
		req.Subject.ID,
		req.Subject.Kind,
		req.Current.Target,
		req.Current.Revision,
		req.Current.Digest,
		req.Transition.Operation,
		req.Transition.To.Revision,
		req.Transition.To.Digest,
	), nil
}

// This verifies the existing adapter observation contract. Its epistemic
// strength still depends on that contract; matching state alone is not an
// independent proof of effect causality. Run, Recover and RunFenced use the
// same checks, in the same order, before their respective closure transitions.
func verifyObservation(ctx context.Context, effectID string, expected State, observation Observation, verify func(context.Context, Attestation, string) error) error {
	if !observation.State.Complete() || !observation.Attestation.Complete() {
		return ErrIncompleteObservation
	}
	binding := ObservationBindingDigest(effectID, observation.State)
	if observation.Attestation.BindingDigest != binding {
		return ErrObservationBinding
	}
	if err := verify(ctx, observation.Attestation, binding); err != nil {
		return err
	}
	if !observation.State.Equal(expected) {
		return ErrObservedStateMismatch
	}
	return nil
}

// ObservationBindingDigest binds one trusted observation to the exact logical
// effect and exact observed state.
func ObservationBindingDigest(effectID string, observed State) string {
	return digest(
		"observation-v0",
		effectID,
		observed.Target,
		observed.Revision,
		observed.Digest,
	)
}

func digest(parts ...string) string {
	h := sha256.New()
	// Length-prefix exact bytes: separators can occur inside opaque fields.
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
