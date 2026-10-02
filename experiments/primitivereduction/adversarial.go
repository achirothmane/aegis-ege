package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// EvaluateAtBoundary revalidates a previously composed proposal against the
// state observed at the actual effect boundary. A stale proposal cannot carry
// its old authority across a state change.
func EvaluateAtBoundary(p Proposal, boundary StateRef) AdmissionResult {
	if !boundary.Complete() {
		return deny(ReasonMissingState, "effect-boundary state is incomplete")
	}
	if boundary.TargetKey() != p.Current.TargetKey() ||
		boundary.Version != p.Current.Version ||
		boundary.Digest != p.Current.Digest {
		return deny(ReasonBindingMismatch, "proposal state does not match the actual effect-boundary state")
	}
	return EvaluateAdmission(p)
}

// ReconcileAll is conservative across multiple observations. CLOSED requires
// every supplied observation to be valid, bound to its observed state, and to
// agree with the exact expected after-state. Contradiction remains UNKNOWN.
func ReconcileAll(expected Transition, observations []Observation) ClosureStatus {
	if len(observations) == 0 {
		return ClosureUnknown
	}
	for _, observation := range observations {
		if Reconcile(expected, observation) != ClosureClosed {
			return ClosureUnknown
		}
	}
	return ClosureClosed
}

// StateRelation is a generic cross-state constraint. It lets the experiment
// express monotonicity and anti-rollback using State + Constraint rather than
// promoting Time to a primitive prematurely.
//
// Semantics: current[Fact] Op previous[Fact].
// When ScopeFact is set (for example a boot identity), the relation is known
// only when both states carry the same non-empty scope value.
type StateRelation struct {
	Fact      string
	Op        Operator
	ScopeFact string
}

func EvaluateStateRelation(previous, current StateRef, relation StateRelation) (bool, bool) {
	if !previous.Complete() || !current.Complete() ||
		previous.TargetKey() != current.TargetKey() ||
		relation.Fact == "" {
		return false, false
	}

	if relation.ScopeFact != "" {
		beforeScope, beforeOK := previous.Facts[relation.ScopeFact]
		afterScope, afterOK := current.Facts[relation.ScopeFact]
		if !beforeOK || !afterOK || beforeScope == "" || afterScope == "" || beforeScope != afterScope {
			return false, false
		}
	}

	before, beforeOK := previous.Facts[relation.Fact]
	after, afterOK := current.Facts[relation.Fact]
	if !beforeOK || !afterOK {
		return false, false
	}

	switch relation.Op {
	case OpEqual:
		return after == before, true
	case OpNotEqual:
		return after != before, true
	}

	left, err := strconv.ParseInt(after, 10, 64)
	if err != nil {
		return false, false
	}
	right, err := strconv.ParseInt(before, 10, 64)
	if err != nil {
		return false, false
	}

	switch relation.Op {
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

// EffectIdentity is derived from the six primitives. It remains stable across
// executor takeover for the same logical effect, while any material change to
// subject, capability, target, or state transition yields a different identity.
func EffectIdentity(p Proposal) (string, error) {
	if !p.Subject.Complete() || !p.Capability.Complete() || !p.Transition.Complete() {
		return "", ErrIncompleteEffectIdentity
	}
	parts := []string{
		p.Subject.ID,
		p.Subject.Kind,
		p.Capability.Name,
		p.Capability.SubjectID,
		p.Capability.TargetKey,
		p.Transition.From.TargetKey(),
		p.Transition.From.Version,
		p.Transition.From.Digest,
		p.Transition.To.TargetKey(),
		p.Transition.To.Version,
		p.Transition.To.Digest,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}

var ErrIncompleteEffectIdentity = effectIdentityError("effect identity requires complete identity, capability, and transition")

type effectIdentityError string

func (e effectIdentityError) Error() string { return string(e) }
