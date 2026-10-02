package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const factEffectSlot = "effect.slot"

var errIncompleteEffectSlotIdentity = errors.New("effect-slot identity requires a complete target transition and trusted effect.slot state")

// ReducedEffectSlotIdentity derives one external-effect cardinality slot from
// already-existing reduced primitives. The subject is intentionally excluded:
//
//   authority answers who may act;
//   effect slot answers which one external effect may exist.
//
// Domain adapters own the slot value. The kernel experiment only binds and
// compares the opaque slot through State + Transition.
func ReducedEffectSlotIdentity(p ReducedProposal) (string, error) {
	if !p.Current.Complete() || !p.Transition.Complete() {
		return "", errIncompleteEffectSlotIdentity
	}
	target := p.Current.TargetKey()
	if target == "" ||
		p.Transition.From.TargetKey() != target ||
		p.Transition.To.TargetKey() != target ||
		p.Transition.From.Version != p.Current.Version ||
		p.Transition.From.Digest != p.Current.Digest {
		return "", errIncompleteEffectSlotIdentity
	}
	slot := p.Current.Facts[factEffectSlot]
	if slot == "" {
		return "", errIncompleteEffectSlotIdentity
	}

	parts := []string{
		slot,
		target,
		p.Transition.Operation,
		p.Transition.From.Version,
		p.Transition.From.Digest,
		p.Transition.To.Version,
		p.Transition.To.Digest,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}

// PrepareReducedEffectSlotCustody creates one durable RESERVED state for an
// admitted reduced proposal. Multiple independently authorized agents that map
// to the same trusted effect slot therefore contend on the same custody object.
func PrepareReducedEffectSlotCustody(p ReducedProposal, executor Identity, sequence string) (StateRef, error) {
	if result := EvaluateReducedAdmission(p); result.Decision != DecisionAllow {
		return StateRef{}, fmt.Errorf("reduced proposal is not admitted: %s", result.Reason)
	}
	if !executor.Complete() {
		return StateRef{}, errors.New("executor identity is incomplete")
	}
	if sequence == "" {
		return StateRef{}, errors.New("custody sequence is required")
	}

	effectID, err := ReducedEffectSlotIdentity(p)
	if err != nil {
		return StateRef{}, err
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

// EvaluateReducedEffectSlotBoundary revalidates both semantic admission and
// shared effect-slot custody immediately before the external effect boundary.
func EvaluateReducedEffectSlotBoundary(p ReducedProposal, executor Identity, custody StateRef) AdmissionResult {
	if result := EvaluateReducedAdmission(p); result.Decision != DecisionAllow {
		return result
	}
	if !executor.Complete() {
		return deny(ReasonMissingIdentity, "executor identity is incomplete")
	}
	if !custody.Complete() || custody.Namespace != custodyNamespace {
		return deny(ReasonMissingState, "effect custody state is incomplete")
	}

	effectID, err := ReducedEffectSlotIdentity(p)
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
		return deny(ReasonBindingMismatch, "custody is not the unique RESERVED state for this shared effect slot")
	}
	return allow()
}

// ClaimReducedEffectSlotBoundary derives RESERVED -> CROSSING. Competing agents
// may both derive the same transition from one stale snapshot, but exact CAS
// permits only one transition to commit.
func ClaimReducedEffectSlotBoundary(p ReducedProposal, executor Identity, custody StateRef) (Transition, AdmissionResult) {
	if result := EvaluateReducedEffectSlotBoundary(p, executor, custody); result.Decision != DecisionAllow {
		return Transition{}, result
	}
	transition, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		return Transition{}, deny(ReasonBindingMismatch, err.Error())
	}
	return transition, allow()
}
