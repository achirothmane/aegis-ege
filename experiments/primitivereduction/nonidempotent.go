package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Effect-custody phases are generic governance state, not domain state.
// They model whether a non-idempotent effect may already have escaped even
// when the business target itself has not changed observably.
const (
	CustodyReserved = "RESERVED"
	CustodyCrossing = "CROSSING"
	CustodyUnknown  = "UNKNOWN"
	CustodyClosed   = "CLOSED"
)

const (
	custodyNamespace = "governance.effect_custody"
	factEffectID      = "effect.id"
	factCustodyPhase  = "effect.phase"
	factCustodyOwner  = "effect.owner"
	factTargetDigest  = "effect.target_digest"
	factOperation     = "effect.operation"
)

// PrepareEffectCustody derives a durable pre-effect state from the same six
// candidate primitives. It intentionally creates another State instance
// rather than introducing EffectAttempt or EffectCustody as a seventh
// primitive.
func PrepareEffectCustody(p Proposal, executor Identity, sequence string) (StateRef, error) {
	if !executor.Complete() {
		return StateRef{}, errors.New("executor identity is incomplete")
	}
	effectID, err := EffectIdentity(p)
	if err != nil {
		return StateRef{}, err
	}
	if sequence == "" {
		return StateRef{}, errors.New("custody sequence is required")
	}

	state := StateRef{
		Namespace: custodyNamespace,
		ObjectID:  effectID,
		Version:   "reserved:" + sequence,
		Facts: map[string]string{
			factEffectID:     effectID,
			factCustodyPhase: CustodyReserved,
			factCustodyOwner: executor.ID,
			factTargetDigest: p.Current.Digest,
			factOperation:    p.Transition.Operation,
		},
	}
	state.Digest = custodyDigest(state)
	return state, nil
}

// EvaluateNonIdempotentBoundary requires both the ordinary proposal admission
// and a unique RESERVED custody state for the same logical effect. This is the
// critical case where the external effect may not mutate the proposal's target
// state at all, so target-state revalidation alone is insufficient.
func EvaluateNonIdempotentBoundary(p Proposal, executor Identity, custody StateRef) AdmissionResult {
	if result := EvaluateAdmission(p); result.Decision != DecisionAllow {
		return result
	}
	if !executor.Complete() {
		return deny(ReasonMissingIdentity, "executor identity is incomplete")
	}
	if !custody.Complete() || custody.Namespace != custodyNamespace {
		return deny(ReasonMissingState, "effect custody state is incomplete")
	}

	effectID, err := EffectIdentity(p)
	if err != nil {
		return deny(ReasonMissingTransition, err.Error())
	}
	if custody.ObjectID != effectID ||
		custody.Facts[factEffectID] != effectID ||
		custody.Facts[factCustodyPhase] != CustodyReserved ||
		custody.Facts[factCustodyOwner] != executor.ID ||
		custody.Facts[factTargetDigest] != p.Current.Digest ||
		custody.Facts[factOperation] != p.Transition.Operation ||
		custody.Digest != custodyDigest(custody) {
		return deny(ReasonBindingMismatch, "effect custody is not the unique reserved state for this exact effect boundary")
	}
	return allow()
}

// AdvanceEffectCustody returns a Transition over governance State. The allowed
// graph is deliberately one-way around the ambiguous region:
//
// RESERVED -> CROSSING -> UNKNOWN -> CLOSED
//                    \-> CLOSED
//
// There is no UNKNOWN -> RESERVED edge: uncertainty never becomes replay
// permission merely because the caller retries.
func AdvanceEffectCustody(custody StateRef, next string) (Transition, error) {
	if !custody.Complete() || custody.Namespace != custodyNamespace || custody.Digest != custodyDigest(custody) {
		return Transition{}, errors.New("invalid custody state")
	}
	current := custody.Facts[factCustodyPhase]
	if !validCustodyAdvance(current, next) {
		return Transition{}, errors.New("invalid custody phase transition")
	}

	after := copyState(custody)
	after.Version = strings.ToLower(next) + ":" + custody.Version
	after.Facts[factCustodyPhase] = next
	after.Digest = custodyDigest(after)

	return Transition{
		Operation: "effect_custody:" + strings.ToLower(current) + "->" + strings.ToLower(next),
		From:      custody,
		To:        after,
	}, nil
}

func validCustodyAdvance(current, next string) bool {
	switch current {
	case CustodyReserved:
		return next == CustodyCrossing
	case CustodyCrossing:
		return next == CustodyUnknown || next == CustodyClosed
	case CustodyUnknown:
		return next == CustodyClosed
	default:
		return false
	}
}

// ReconcileExternalEffect remains UNKNOWN when the external world exposes no
// reliable evidence. A valid exact provider observation can close the custody
// obligation without pretending that the business target had to change.
func ReconcileExternalEffect(custody StateRef, providerObservation Evidence) ClosureStatus {
	if !custody.Complete() ||
		custody.Namespace != custodyNamespace ||
		custody.Digest != custodyDigest(custody) ||
		custody.Facts[factCustodyPhase] != CustodyUnknown {
		return ClosureUnknown
	}
	if !providerObservation.Complete() ||
		!providerObservation.Valid ||
		providerObservation.StateDigest != custody.Digest ||
		providerObservation.ID != custody.Facts[factEffectID] {
		return ClosureUnknown
	}
	return ClosureClosed
}

func copyState(in StateRef) StateRef {
	out := in
	if in.Facts != nil {
		out.Facts = make(map[string]string, len(in.Facts))
		for k, v := range in.Facts {
			out.Facts[k] = v
		}
	}
	return out
}

func custodyDigest(state StateRef) string {
	keys := []string{
		factEffectID,
		factCustodyPhase,
		factCustodyOwner,
		factTargetDigest,
		factOperation,
	}
	parts := []string{state.Namespace, state.ObjectID, state.Version}
	for _, key := range keys {
		parts = append(parts, key, state.Facts[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
