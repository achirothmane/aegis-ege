package primitivereduction

import (
	"fmt"
	"strconv"
)

// ReducedProposal intentionally removes Capability as a candidate semantic
// primitive. Authority is represented as evidence-backed constraints over the
// subject, target state, and requested transition.
//
// This is a falsification experiment against the claim that Capability must be
// a fundamental semantic primitive. It does not remove capability tokens from
// implementation: those can still be derived after admission.
type ReducedProposal struct {
	Subject     Identity
	Current     StateRef
	Constraints []Constraint
	Evidence    []Evidence
	Transition  Transition
}

func ReducedCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveConstraint,
		PrimitiveEvidence,
		PrimitiveTransition,
	}
}

const authorityEvidenceType = "authority-binding-attestation"

// EvaluateReducedAdmission uses the same generic state/evidence/predicate
// machinery as v0 but has no Capability field.
//
// The authorization relationship must be carried by at least one valid
// authority-binding Evidence item and a Constraint that cites that evidence.
// This keeps "who may perform which transition against which state" explicit
// without requiring Capability to be a standalone semantic atom.
func EvaluateReducedAdmission(p ReducedProposal) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case len(p.Constraints) == 0:
		return deny(ReasonMissingConstraint, "at least one constraint is required")
	case len(p.Evidence) == 0:
		return deny(ReasonMissingEvidence, "at least one state-bound evidence item is required")
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

	evidenceByID := make(map[string]Evidence, len(p.Evidence))
	authorityEvidenceIDs := make(map[string]struct{})
	for _, e := range p.Evidence {
		if !e.Complete() || !e.Valid || e.StateDigest != p.Current.Digest {
			return deny(ReasonEvidenceInvalid, "evidence is incomplete, invalid, or bound to a different state")
		}
		evidenceByID[e.ID] = e
		if e.Type == authorityEvidenceType {
			authorityEvidenceIDs[e.ID] = struct{}{}
		}
	}
	if len(authorityEvidenceIDs) == 0 {
		return deny(ReasonEvidenceInvalid, "no authority-binding evidence is present")
	}

	authorityConstraintSatisfied := false
	for _, c := range p.Constraints {
		if !c.Complete() {
			return deny(ReasonConstraintUnknown, "constraint is incomplete")
		}

		referencesAuthority := false
		for _, evidenceID := range c.EvidenceIDs {
			if _, ok := evidenceByID[evidenceID]; !ok {
				return deny(ReasonEvidenceInvalid, "constraint references missing or invalid evidence")
			}
			if _, ok := authorityEvidenceIDs[evidenceID]; ok {
				referencesAuthority = true
			}
		}

		for _, predicate := range c.Predicates {
			ok, known := evaluateReducedPredicate(p, predicate)
			if !known {
				return deny(ReasonConstraintUnknown, fmt.Sprintf("cannot evaluate constraint %q", c.ID))
			}
			if !ok {
				return deny(ReasonConstraintViolated, fmt.Sprintf("constraint %q is violated", c.ID))
			}
		}
		if referencesAuthority {
			authorityConstraintSatisfied = true
		}
	}
	if !authorityConstraintSatisfied {
		return deny(ReasonEvidenceInvalid, "authority evidence is not consumed by any constraint")
	}

	return allow()
}

// evaluateReducedPredicate extends ordinary state-fact predicates with three
// synthetic proposal facts. They are not stored authority objects; they are
// values already present in the proposal relation.
func evaluateReducedPredicate(p ReducedProposal, predicate Predicate) (bool, bool) {
	actual := ""
	switch predicate.Fact {
	case "$subject.id":
		actual = p.Subject.ID
	case "$transition.operation":
		actual = p.Transition.Operation
	case "$target.key":
		actual = p.Current.TargetKey()
	default:
		value, ok := p.Current.Facts[predicate.Fact]
		if !ok || predicate.Fact == "" {
			return false, false
		}
		actual = value
	}

	switch predicate.Op {
	case OpEqual:
		return actual == predicate.Value, true
	case OpNotEqual:
		return actual != predicate.Value, true
	}

	left, err := strconv.ParseInt(actual, 10, 64)
	if err != nil {
		return false, false
	}
	right, err := strconv.ParseInt(predicate.Value, 10, 64)
	if err != nil {
		return false, false
	}

	switch predicate.Op {
	case OpLessThanInt:
		return left < right, true
	case OpLessOrEqualInt:
		return left <= right, true
	case OpGreaterThanInt:
		return left > right, true
	case OpGreaterOrEqualInt:
		return left >= right, true
	default:
		return false, false
	}
}

// ReduceCapability translates an existing six-primitive fixture into the
// five-primitive candidate by replacing the Capability record with an
// evidence-backed authority constraint over subject + operation + target.
//
// The Capability value is used only by this migration helper to preserve the
// meaning of the original fixture. EvaluateReducedAdmission never consumes it.
func ReduceCapability(p Proposal) ReducedProposal {
	const authorityEvidenceID = "derived-authority-binding"

	constraints := make([]Constraint, 0, len(p.Constraints)+1)
	constraints = append(constraints, Constraint{
		ID: "derived-authority-binding",
		Predicates: []Predicate{
			{Fact: "$subject.id", Op: OpEqual, Value: p.Capability.SubjectID},
			{Fact: "$transition.operation", Op: OpEqual, Value: p.Capability.Name},
			{Fact: "$target.key", Op: OpEqual, Value: p.Capability.TargetKey},
		},
		EvidenceIDs: []string{authorityEvidenceID},
	})
	constraints = append(constraints, p.Constraints...)

	evidence := append([]Evidence(nil), p.Evidence...)
	evidence = append(evidence, Evidence{
		ID:          authorityEvidenceID,
		Type:        authorityEvidenceType,
		StateDigest: p.Current.Digest,
		Valid:       true,
	})

	return ReducedProposal{
		Subject:     p.Subject,
		Current:     p.Current,
		Constraints: constraints,
		Evidence:    evidence,
		Transition:  p.Transition,
	}
}

// MintDerivedCapability demonstrates the implementation/security role that can
// remain after semantic reduction. The token is minted from an already-admitted
// relation; it is not required as an input primitive to decide admission.
func MintDerivedCapability(p ReducedProposal) (Capability, error) {
	if result := EvaluateReducedAdmission(p); result.Decision != DecisionAllow {
		return Capability{}, fmt.Errorf("reduced proposal is not admitted: %s", result.Reason)
	}
	return Capability{
		Name:      p.Transition.Operation,
		SubjectID: p.Subject.ID,
		TargetKey: p.Current.TargetKey(),
	}, nil
}
