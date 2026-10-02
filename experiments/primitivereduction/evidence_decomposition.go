package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const PrimitiveAttestation Primitive = "attestation"

// SemanticConstraint keeps the claim/predicate content of Constraint but drops
// EvidenceIDs. In v9, provenance is represented explicitly by Attestation
// rather than by an opaque Evidence record referenced through string IDs.
type SemanticConstraint struct {
	ID         string
	Predicates []Predicate
}

func (c SemanticConstraint) Complete() bool {
	return c.ID != "" && len(c.Predicates) > 0
}

// Attestation is the provenance/binding component that was previously hidden
// inside the broad Evidence concept. The claim content itself lives in the
// referenced SemanticConstraint.
//
// Valid means the attestation has already passed the implementation-specific
// verifier (signature/TPM/provider/etc.). This experiment is semantic, not a
// cryptographic implementation.
type Attestation struct {
	ID            string
	Issuer        Identity
	ConstraintID  string
	BindingDigest string
	Valid         bool
}

func (a Attestation) Complete() bool {
	return a.ID != "" &&
		a.Issuer.Complete() &&
		a.ConstraintID != "" &&
		a.BindingDigest != ""
}

// EvidenceDecomposedProposal has no Capability and no Evidence field.
type EvidenceDecomposedProposal struct {
	Subject      Identity
	Current      StateRef
	Constraints  []SemanticConstraint
	Attestations []Attestation
	Transition   Transition
}

func EvidenceDecomposedCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveConstraint,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
}

func attestationBindingDigest(p EvidenceDecomposedProposal, c SemanticConstraint, issuer Identity) string {
	parts := []string{
		issuer.ID,
		issuer.Kind,
		p.Subject.ID,
		p.Subject.Kind,
		p.Current.TargetKey(),
		p.Current.Version,
		p.Current.Digest,
		p.Transition.Operation,
		p.Transition.From.TargetKey(),
		p.Transition.From.Version,
		p.Transition.From.Digest,
		p.Transition.To.TargetKey(),
		p.Transition.To.Version,
		p.Transition.To.Digest,
		c.ID,
	}

	predicates := append([]Predicate(nil), c.Predicates...)
	sort.Slice(predicates, func(i, j int) bool {
		if predicates[i].Fact != predicates[j].Fact {
			return predicates[i].Fact < predicates[j].Fact
		}
		if predicates[i].Op != predicates[j].Op {
			return predicates[i].Op < predicates[j].Op
		}
		return predicates[i].Value < predicates[j].Value
	})
	for _, predicate := range predicates {
		parts = append(parts, predicate.Fact, string(predicate.Op), predicate.Value)
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EvaluateEvidenceDecomposedAdmission tests whether opaque Evidence can be
// replaced by explicit claim + provenance semantics.
//
// Every semantic constraint must have at least one valid attestation bound to
// the exact proposal relation and exact constraint content.
func EvaluateEvidenceDecomposedAdmission(p EvidenceDecomposedProposal) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case len(p.Constraints) == 0:
		return deny(ReasonMissingConstraint, "at least one semantic constraint is required")
	case len(p.Attestations) == 0:
		return deny(ReasonMissingEvidence, "at least one attestation is required")
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

	constraintsByID := make(map[string]SemanticConstraint, len(p.Constraints))
	for _, c := range p.Constraints {
		if !c.Complete() {
			return deny(ReasonConstraintUnknown, "semantic constraint is incomplete")
		}
		if _, exists := constraintsByID[c.ID]; exists {
			return deny(ReasonConstraintUnknown, "duplicate semantic constraint id")
		}
		constraintsByID[c.ID] = c
	}

	attested := make(map[string]bool, len(p.Constraints))
	for _, a := range p.Attestations {
		if !a.Complete() || !a.Valid {
			return deny(ReasonEvidenceInvalid, "attestation is incomplete or invalid")
		}
		constraint, ok := constraintsByID[a.ConstraintID]
		if !ok {
			return deny(ReasonEvidenceInvalid, "attestation references an unknown constraint")
		}
		if a.BindingDigest != attestationBindingDigest(p, constraint, a.Issuer) {
			return deny(ReasonEvidenceInvalid, "attestation is stale or bound to different proposal/claim content")
		}
		attested[a.ConstraintID] = true
	}

	for _, c := range p.Constraints {
		if !attested[c.ID] {
			return deny(ReasonEvidenceInvalid, fmt.Sprintf("constraint %q has no valid attestation", c.ID))
		}
		for _, predicate := range c.Predicates {
			ok, known := evaluateEvidenceDecomposedPredicate(p, predicate)
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

func evaluateEvidenceDecomposedPredicate(p EvidenceDecomposedProposal, predicate Predicate) (bool, bool) {
	var actual string
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

// DecomposeEvidence migrates the v8 representation into explicit semantic
// constraints plus attestations. Existing Evidence objects are intentionally
// not copied into the returned proposal.
func DecomposeEvidence(p ReducedProposal) EvidenceDecomposedProposal {
	out := EvidenceDecomposedProposal{
		Subject:    p.Subject,
		Current:    p.Current,
		Transition: p.Transition,
	}

	for _, c := range p.Constraints {
		out.Constraints = append(out.Constraints, SemanticConstraint{
			ID:         c.ID,
			Predicates: append([]Predicate(nil), c.Predicates...),
		})
	}

	// Migration helper only: use the v8 evidence references to choose a stable
	// provenance identity for each claim. Runtime v9 evaluation does not accept
	// or inspect Evidence records.
	evidenceTypeByID := make(map[string]string, len(p.Evidence))
	for _, e := range p.Evidence {
		evidenceTypeByID[e.ID] = e.Type
	}

	for index, c := range p.Constraints {
		issuerName := "attestor:constraint"
		for _, evidenceID := range c.EvidenceIDs {
			if evidenceType, ok := evidenceTypeByID[evidenceID]; ok {
				issuerName = "attestor:" + evidenceType
				break
			}
		}

		semantic := out.Constraints[index]
		issuer := Identity{ID: issuerName, Kind: "attestor"}
		out.Attestations = append(out.Attestations, Attestation{
			ID:            "attestation:" + c.ID,
			Issuer:        issuer,
			ConstraintID:  c.ID,
			BindingDigest: attestationBindingDigest(out, semantic, issuer),
			Valid:         true,
		})
	}

	return out
}

// MaterializeEvidence demonstrates compatibility with code that still consumes
// Evidence. It is an adapter output derived from an attestation and current
// state, not a required semantic input to v9 admission.
func MaterializeEvidence(p EvidenceDecomposedProposal, a Attestation) (Evidence, error) {
	if !a.Complete() || !a.Valid {
		return Evidence{}, fmt.Errorf("attestation is incomplete or invalid")
	}
	var constraint SemanticConstraint
	found := false
	for _, candidate := range p.Constraints {
		if candidate.ID == a.ConstraintID {
			constraint = candidate
			found = true
			break
		}
	}
	if !found || a.BindingDigest != attestationBindingDigest(p, constraint, a.Issuer) {
		return Evidence{}, fmt.Errorf("attestation binding is invalid")
	}
	return Evidence{
		ID:          a.ID,
		Type:        "derived-attestation",
		StateDigest: p.Current.Digest,
		Valid:       true,
	}, nil
}
