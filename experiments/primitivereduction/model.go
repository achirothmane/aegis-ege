// Package primitivereduction is a non-normative executable experiment.
//
// It tests whether a small, domain-agnostic candidate basis can represent
// governed actions across unrelated domains without embedding those domains'
// business semantics in the evaluator. It does not modify the frozen
// governed-action kernel v1 contract.
package primitivereduction

import (
	"errors"
	"fmt"
	"strconv"
)

type Primitive string

const (
	PrimitiveIdentity   Primitive = "identity"
	PrimitiveState      Primitive = "state"
	PrimitiveCapability Primitive = "capability"
	PrimitiveConstraint Primitive = "constraint"
	PrimitiveEvidence   Primitive = "evidence"
	PrimitiveTransition Primitive = "transition"
)

func CandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveCapability,
		PrimitiveConstraint,
		PrimitiveEvidence,
		PrimitiveTransition,
	}
}

type Identity struct {
	ID   string
	Kind string
}

func (i Identity) Complete() bool {
	return i.ID != "" && i.Kind != ""
}

type StateRef struct {
	Namespace string
	ObjectID  string
	Version   string
	Digest    string
	Facts     map[string]string
}

func (s StateRef) TargetKey() string {
	if s.Namespace == "" || s.ObjectID == "" {
		return ""
	}
	return s.Namespace + ":" + s.ObjectID
}

func (s StateRef) Complete() bool {
	return s.TargetKey() != "" && s.Version != "" && s.Digest != ""
}

type Capability struct {
	Name      string
	SubjectID string
	TargetKey string
}

func (c Capability) Complete() bool {
	return c.Name != "" && c.SubjectID != "" && c.TargetKey != ""
}

type Operator string

const (
	OpEqual            Operator = "EQ"
	OpNotEqual         Operator = "NEQ"
	OpLessThanInt      Operator = "LT_INT"
	OpLessOrEqualInt   Operator = "LTE_INT"
	OpGreaterThanInt   Operator = "GT_INT"
	OpGreaterOrEqualInt Operator = "GTE_INT"
)

type Predicate struct {
	Fact  string
	Op    Operator
	Value string
}

type Constraint struct {
	ID          string
	Predicates  []Predicate
	EvidenceIDs []string
}

func (c Constraint) Complete() bool {
	return c.ID != "" && len(c.Predicates) > 0 && len(c.EvidenceIDs) > 0
}

type Evidence struct {
	ID          string
	Type        string
	StateDigest string
	Valid       bool
}

func (e Evidence) Complete() bool {
	return e.ID != "" && e.Type != "" && e.StateDigest != ""
}

type Transition struct {
	Operation string
	From      StateRef
	To        StateRef
}

func (t Transition) Complete() bool {
	return t.Operation != "" && t.From.Complete() && t.To.Complete()
}

type Proposal struct {
	Subject     Identity
	Current     StateRef
	Capability  Capability
	Constraints []Constraint
	Evidence    []Evidence
	Transition  Transition
}

type AdmissionDecision string

const (
	DecisionAllow AdmissionDecision = "ALLOW"
	DecisionDeny  AdmissionDecision = "DENY"
)

type Reason string

const (
	ReasonMissingIdentity      Reason = "MISSING_IDENTITY"
	ReasonMissingState         Reason = "MISSING_STATE"
	ReasonMissingCapability    Reason = "MISSING_CAPABILITY"
	ReasonMissingConstraint    Reason = "MISSING_CONSTRAINT"
	ReasonMissingEvidence      Reason = "MISSING_EVIDENCE"
	ReasonMissingTransition    Reason = "MISSING_TRANSITION"
	ReasonBindingMismatch      Reason = "BINDING_MISMATCH"
	ReasonEvidenceInvalid      Reason = "EVIDENCE_INVALID"
	ReasonConstraintUnknown    Reason = "CONSTRAINT_UNKNOWN"
	ReasonConstraintViolated   Reason = "CONSTRAINT_VIOLATED"
)

type AdmissionResult struct {
	Decision AdmissionDecision
	Reason   Reason
	Detail   string
}

func allow() AdmissionResult {
	return AdmissionResult{Decision: DecisionAllow}
}

func deny(reason Reason, detail string) AdmissionResult {
	return AdmissionResult{Decision: DecisionDeny, Reason: reason, Detail: detail}
}

// EvaluateAdmission is intentionally domain-agnostic. Domain adapters are
// responsible for translating their world into these candidate primitives.
// The evaluator only checks completeness, binding integrity, evidence binding,
// and generic predicates over state facts.
func EvaluateAdmission(p Proposal) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case !p.Capability.Complete():
		return deny(ReasonMissingCapability, "capability is incomplete")
	case len(p.Constraints) == 0:
		return deny(ReasonMissingConstraint, "at least one constraint is required")
	case len(p.Evidence) == 0:
		return deny(ReasonMissingEvidence, "at least one state-bound evidence item is required")
	case !p.Transition.Complete():
		return deny(ReasonMissingTransition, "transition is incomplete")
	}

	target := p.Current.TargetKey()
	if p.Capability.SubjectID != p.Subject.ID ||
		p.Capability.TargetKey != target ||
		p.Transition.Operation != p.Capability.Name ||
		p.Transition.From.TargetKey() != target ||
		p.Transition.To.TargetKey() != target ||
		p.Transition.From.Version != p.Current.Version ||
		p.Transition.From.Digest != p.Current.Digest {
		return deny(ReasonBindingMismatch, "identity, capability, state, and transition are not bound to the same proposal")
	}

	evidenceByID := make(map[string]Evidence, len(p.Evidence))
	for _, e := range p.Evidence {
		if !e.Complete() || !e.Valid || e.StateDigest != p.Current.Digest {
			return deny(ReasonEvidenceInvalid, "evidence is incomplete, invalid, or bound to a different state")
		}
		evidenceByID[e.ID] = e
	}

	for _, c := range p.Constraints {
		if !c.Complete() {
			return deny(ReasonConstraintUnknown, "constraint is incomplete")
		}
		for _, evidenceID := range c.EvidenceIDs {
			if _, ok := evidenceByID[evidenceID]; !ok {
				return deny(ReasonEvidenceInvalid, "constraint references missing or invalid evidence")
			}
		}
		for _, predicate := range c.Predicates {
			ok, known := evaluatePredicate(p.Current.Facts, predicate)
			if !known {
				return deny(ReasonConstraintUnknown, fmt.Sprintf("cannot evaluate constraint %q", c.ID))
			}
			if !ok {
				return deny(ReasonConstraintViolated, fmt.Sprintf("constraint %q is violated", c.ID))
			}
		}
	}

	return allow()
}

func evaluatePredicate(facts map[string]string, predicate Predicate) (bool, bool) {
	actual, ok := facts[predicate.Fact]
	if !ok || predicate.Fact == "" {
		return false, false
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

// Intent and Authority are derived relations. They are deliberately not
// candidate primitives in this experiment.
type Intent struct {
	SubjectID   string
	Operation   string
	TargetKey   string
	FromVersion string
	ToVersion   string
}

func DeriveIntent(p Proposal) Intent {
	return Intent{
		SubjectID:   p.Subject.ID,
		Operation:   p.Transition.Operation,
		TargetKey:   p.Current.TargetKey(),
		FromVersion: p.Transition.From.Version,
		ToVersion:   p.Transition.To.Version,
	}
}

type Authority struct {
	SubjectID     string
	Capability    string
	TargetKey     string
	StateDigest   string
	ConstraintIDs []string
}

func DeriveAuthority(p Proposal) Authority {
	ids := make([]string, 0, len(p.Constraints))
	for _, c := range p.Constraints {
		ids = append(ids, c.ID)
	}
	return Authority{
		SubjectID:     p.Subject.ID,
		Capability:    p.Capability.Name,
		TargetKey:     p.Current.TargetKey(),
		StateDigest:   p.Current.Digest,
		ConstraintIDs: ids,
	}
}

type ExecutionLease struct {
	Authority              Authority
	StateDigest            string
	ValidityConstraintID   string
	RevocationConstraintID string
}

func DeriveExecutionLease(p Proposal, validityConstraintID, revocationConstraintID string) ExecutionLease {
	return ExecutionLease{
		Authority:              DeriveAuthority(p),
		StateDigest:            p.Current.Digest,
		ValidityConstraintID:   validityConstraintID,
		RevocationConstraintID: revocationConstraintID,
	}
}

type Receipt struct {
	Executor   Identity
	Transition Transition
	Before     StateRef
	After      StateRef
	Evidence   Evidence
}

func BuildReceipt(executor Identity, p Proposal, after StateRef, evidence Evidence) (Receipt, error) {
	if !executor.Complete() {
		return Receipt{}, errors.New("executor identity is incomplete")
	}
	if !after.Complete() || after.TargetKey() != p.Current.TargetKey() {
		return Receipt{}, errors.New("after-state is incomplete or bound to a different target")
	}
	if !evidence.Complete() || !evidence.Valid || evidence.StateDigest != after.Digest {
		return Receipt{}, errors.New("effect evidence is invalid or not bound to the observed after-state")
	}
	return Receipt{
		Executor:   executor,
		Transition: p.Transition,
		Before:     p.Current,
		After:      after,
		Evidence:   evidence,
	}, nil
}

type Observation struct {
	State    StateRef
	Evidence Evidence
}

type ClosureStatus string

const (
	ClosureClosed  ClosureStatus = "CLOSED"
	ClosureUnknown ClosureStatus = "UNKNOWN"
)

// Reconcile closes only when a valid observation is bound to the exact
// expected after-state. It never turns ambiguity into success.
func Reconcile(expected Transition, observation Observation) ClosureStatus {
	if !expected.Complete() ||
		!observation.State.Complete() ||
		!observation.Evidence.Complete() ||
		!observation.Evidence.Valid ||
		observation.Evidence.StateDigest != observation.State.Digest {
		return ClosureUnknown
	}

	if observation.State.TargetKey() == expected.To.TargetKey() &&
		observation.State.Version == expected.To.Version &&
		observation.State.Digest == expected.To.Digest {
		return ClosureClosed
	}
	return ClosureUnknown
}
