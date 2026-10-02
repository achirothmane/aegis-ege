package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// FourPrimitiveBasis is the surviving semantic candidate after the direct
// elimination tests in v12-v15.
func FourPrimitiveBasis() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
}

// FourPrimitiveEffectIdentity derives logical effect identity without the
// eliminated Capability, Constraint, or Evidence primitives.
//
// Attestation is intentionally not part of logical effect identity: two trusted
// authorization paths for the exact same subject/state/transition still refer
// to the same logical effect.
func FourPrimitiveEffectIdentity(p ConstraintFreeProposal) (string, error) {
	if !p.Subject.Complete() || !p.Current.Complete() || !p.Transition.Complete() {
		return "", errors.New("four-primitive effect identity requires complete identity, state, and transition")
	}

	target := p.Current.TargetKey()
	if p.Transition.From.TargetKey() != target ||
		p.Transition.To.TargetKey() != target ||
		p.Transition.From.Version != p.Current.Version ||
		p.Transition.From.Digest != p.Current.Digest {
		return "", errors.New("state and transition are not bound to the same logical effect")
	}

	parts := []string{
		p.Subject.ID,
		p.Subject.Kind,
		target,
		p.Current.Version,
		p.Current.Digest,
		p.Transition.Operation,
		p.Transition.To.Version,
		p.Transition.To.Digest,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}

// PrepareFourPrimitiveCustody represents possible-effect ownership as another
// State instance. It does not introduce a fifth primitive.
func PrepareFourPrimitiveCustody(
	p ConstraintFreeProposal,
	executor Identity,
	sequence string,
) (StateRef, error) {
	if result := ValidateFourPrimitiveProposalShape(p); result.Decision != DecisionAllow {
		return StateRef{}, errors.New("four-primitive proposal is structurally invalid")
	}
	if !executor.Complete() {
		return StateRef{}, errors.New("executor identity is incomplete")
	}
	if sequence == "" {
		return StateRef{}, errors.New("custody sequence is required")
	}

	effectID, err := FourPrimitiveEffectIdentity(p)
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

// ValidateFourPrimitiveProposalShape checks only the relations expressible by
// Identity + State + Transition. Authorization provenance is verified
// separately by EvaluateConstraintFreeAdmission.
func ValidateFourPrimitiveProposalShape(p ConstraintFreeProposal) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case !p.Transition.Complete():
		return deny(ReasonMissingTransition, "transition is incomplete")
	}

	target := p.Current.TargetKey()
	if p.Transition.From.TargetKey() != target ||
		p.Transition.To.TargetKey() != target ||
		p.Transition.From.Version != p.Current.Version ||
		p.Transition.From.Digest != p.Current.Digest {
		return deny(ReasonBindingMismatch, "state and transition are not bound to the same proposal")
	}
	return allow()
}

// EvaluateFourPrimitiveEffectBoundary composes the surviving four-primitives at
// the real effect boundary:
//
//   Identity: subject + executor/owner
//   State: current target state + custody state + provenance trust state
//   Attestation: trusted admission decision
//   Transition: exact requested effect
//
// Multiple instances of one primitive are not additional primitives.
func EvaluateFourPrimitiveEffectBoundary(
	p ConstraintFreeProposal,
	trust StateRef,
	executor Identity,
	custody StateRef,
) AdmissionResult {
	if result := EvaluateConstraintFreeAdmission(p, trust); result.Decision != DecisionAllow {
		return result
	}
	if !executor.Complete() {
		return deny(ReasonMissingIdentity, "executor identity is incomplete")
	}
	if !custody.Complete() || custody.Namespace != custodyNamespace {
		return deny(ReasonMissingState, "effect custody state is incomplete")
	}

	effectID, err := FourPrimitiveEffectIdentity(p)
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
		return deny(ReasonBindingMismatch, "custody is not RESERVED for this exact four-primitive effect")
	}

	return allow()
}
