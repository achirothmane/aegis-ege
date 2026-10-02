package primitivereduction

import "errors"

// LinearizationWitness is derived evidence that a particular effect-boundary
// claim is expected to commit through a named shared serialization domain.
//
// The witness is not a primitive and it is not the serialization mechanism.
// It only binds the proposal/custody to an enforcement assumption that must be
// discharged by the substrate.
type LinearizationWitness struct {
	DomainID  string
	Epoch     string
	Authority Identity
	Evidence  Evidence
}

// EvaluateDistributedPrecondition fails closed unless the boundary has evidence
// for the exact expected shared commit domain. This makes the hidden
// linearizability assumption explicit instead of pretending local CAS is
// globally exclusive.
func EvaluateDistributedPrecondition(
	custody StateRef,
	expectedDomain string,
	witness LinearizationWitness,
) AdmissionResult {
	if !custody.Complete() {
		return deny(ReasonMissingState, "custody state is incomplete")
	}
	if expectedDomain == "" {
		return deny(ReasonConstraintUnknown, "shared linearization domain is not declared")
	}
	if witness.DomainID == "" ||
		witness.Epoch == "" ||
		!witness.Authority.Complete() ||
		!witness.Evidence.Complete() ||
		!witness.Evidence.Valid {
		return deny(ReasonEvidenceInvalid, "linearization witness is incomplete or invalid")
	}
	if witness.DomainID != expectedDomain ||
		witness.Evidence.StateDigest != custody.Digest {
		return deny(ReasonBindingMismatch, "linearization witness is not bound to the expected domain and custody state")
	}
	return allow()
}

// LinearizationAuthority is a tiny executable model of the substrate
// assumption required by concurrent claim safety. In production this role
// could be discharged by a linearizable datastore, consensus system, or
// another single commit authority. The experiment deliberately does not claim
// that this in-memory model implements distributed consensus.
type LinearizationAuthority struct {
	DomainID string
	Current  StateRef
}

func (a *LinearizationAuthority) Commit(
	witness LinearizationWitness,
	transition Transition,
) (StateRef, error) {
	if a == nil || a.DomainID == "" {
		return StateRef{}, errors.New("linearization authority is not configured")
	}
	if witness.DomainID != a.DomainID {
		return StateRef{}, errors.New("linearization witness targets another commit domain")
	}
	next, err := ApplyStateTransitionCAS(a.Current, transition)
	if err != nil {
		return StateRef{}, err
	}
	a.Current = next
	return next, nil
}
