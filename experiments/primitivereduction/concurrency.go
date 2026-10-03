package primitivereduction

import "errors"

// ApplyStateTransitionCAS models the one property the effect boundary must
// provide for concurrent claim safety: the Transition's From state must still
// be the exact current state when the transition commits.
//
// This is deliberately generic. It does not know about locks, databases,
// Kubernetes resourceVersion, Git refs, or provider semantics.
func ApplyStateTransitionCAS(current StateRef, transition Transition) (StateRef, error) {
	if !current.Complete() || !transition.Complete() {
		return StateRef{}, errors.New("current state and transition must be complete")
	}
	if current.TargetKey() != transition.From.TargetKey() ||
		current.Version != transition.From.Version ||
		current.Digest != transition.From.Digest {
		return StateRef{}, errors.New("compare-and-swap precondition failed")
	}
	return transition.To, nil
}

// ClaimEffectBoundary converts RESERVED custody into CROSSING through an
// ordinary Transition. Two workers may both derive this Transition from the
// same snapshot; only one can commit if the State transition is applied with
// exact compare-and-swap semantics.
func ClaimEffectBoundary(p Proposal, executor Identity, custody StateRef) (Transition, AdmissionResult) {
	if result := EvaluateNonIdempotentBoundary(p, executor, custody); result.Decision != DecisionAllow {
		return Transition{}, result
	}
	transition, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		return Transition{}, deny(ReasonBindingMismatch, err.Error())
	}
	return transition, allow()
}

// ConcurrentJoinStatus is derived from child custody State values. A join can
// proceed only when every required predecessor is truthfully CLOSED.
type ConcurrentJoinStatus string

const (
	JoinBlocked ConcurrentJoinStatus = "BLOCKED"
	JoinReady   ConcurrentJoinStatus = "READY"
	JoinUnknown ConcurrentJoinStatus = "UNKNOWN"
)

func EvaluateConcurrentJoin(required []StateRef) ConcurrentJoinStatus {
	if len(required) == 0 {
		return JoinUnknown
	}
	for _, custody := range required {
		if !custody.Complete() ||
			custody.Namespace != custodyNamespace ||
			custody.Digest != custodyDigest(custody) {
			return JoinUnknown
		}
		switch custody.Facts[factCustodyPhase] {
		case CustodyClosed:
			// continue
		case CustodyReserved:
			return JoinBlocked
		case CustodyCrossing, CustodyUnknown:
			return JoinUnknown
		default:
			return JoinUnknown
		}
	}
	return JoinReady
}

// OrderingObservation describes evidence about causal order between two
// logical effects. Order itself is not promoted to a primitive; it is evidence
// about State/Transition relationships.
type OrderingObservation struct {
	BeforeEffectID string
	AfterEffectID  string
	Evidence       Evidence
}

// ReconcileOrdering is conservative. Conflicting valid observations do not
// manufacture a total order; they remain UNKNOWN.
func ReconcileOrdering(observations []OrderingObservation) ClosureStatus {
	if len(observations) == 0 {
		return ClosureUnknown
	}
	var before, after string
	for i, observation := range observations {
		if observation.BeforeEffectID == "" ||
			observation.AfterEffectID == "" ||
			observation.BeforeEffectID == observation.AfterEffectID ||
			!observation.Evidence.Complete() ||
			!observation.Evidence.Valid {
			return ClosureUnknown
		}
		if i == 0 {
			before = observation.BeforeEffectID
			after = observation.AfterEffectID
			continue
		}
		if observation.BeforeEffectID != before || observation.AfterEffectID != after {
			return ClosureUnknown
		}
	}
	return ClosureClosed
}
