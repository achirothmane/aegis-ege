package primitivereduction

import "errors"

// AttestationFreeProposal is the three-primitive candidate:
//
//   Identity + State + Transition
//
// It deliberately removes Attestation / Provenance Binding entirely. The
// runtime can still identify the actor, current revision, and requested effect,
// but it has no semantic object that says the effect was actually authorized by
// a trusted decision producer.
type AttestationFreeProposal struct {
	Subject    Identity
	Current    StateRef
	Transition Transition
}

func AttestationFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveTransition,
	}
}

// BuildAttestationFreeAdmission begins with an already-admitted v11 relation and
// strips the attestation only after the richer source has been verified.
//
// This helper exists solely to construct the reduction experiment. Runtime v15
// receives no evidence of the authorization decision.
func BuildAttestationFreeAdmission(
	source ConstraintFreeProposal,
	trust StateRef,
) (AttestationFreeProposal, error) {
	if result := EvaluateConstraintFreeAdmission(source, trust); result.Decision != DecisionAllow {
		return AttestationFreeProposal{}, errors.New("source relation is not admitted")
	}

	return AttestationFreeProposal{
		Subject:    source.Subject,
		Current:    source.Current,
		Transition: source.Transition,
	}, nil
}

// EvaluateAttestationFreeAdmission can verify structural binding only.
//
// It intentionally demonstrates the unsound branch of the indistinguishability
// boundary: if structurally valid proposals are allowed, the evaluator cannot
// tell an authorized proposal from the same proposal copied into a world where
// no trusted authorization decision exists.
//
// A fail-closed implementation could deny both worlds instead, but then it
// would reject the previously admitted world as well. Either way, the original
// authorized/unauthorized distinction is lost.
func EvaluateAttestationFreeAdmission(p AttestationFreeProposal) AdmissionResult {
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
