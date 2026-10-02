package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const provenanceTrustNamespace = "governance.provenance_trust"

// ProvenanceFreeProposal is the strongest naive four-primitive reduction of v9.
// It deliberately removes Attestation entirely.
//
// The experiment uses this representation to demonstrate an indistinguishability
// boundary: trusted and copied/untrusted claims collapse to identical semantic
// input when provenance is removed.
type ProvenanceFreeProposal struct {
	Subject     Identity
	Current     StateRef
	Constraints []SemanticConstraint
	Transition  Transition
}

func ProvenanceFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveConstraint,
		PrimitiveTransition,
	}
}

func StripProvenance(p EvidenceDecomposedProposal) ProvenanceFreeProposal {
	return ProvenanceFreeProposal{
		Subject:     p.Subject,
		Current:     p.Current,
		Constraints: append([]SemanticConstraint(nil), p.Constraints...),
		Transition:  p.Transition,
	}
}

// EvaluateProvenanceFreeAdmission is intentionally complete enough to show the
// reduction failure. It can evaluate state, subject, target, transition, and
// constraint content, but it has no information about who asserted those
// claims or whether that origin is trusted.
func EvaluateProvenanceFreeAdmission(p ProvenanceFreeProposal) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case len(p.Constraints) == 0:
		return deny(ReasonMissingConstraint, "at least one semantic constraint is required")
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

	bridge := EvidenceDecomposedProposal{
		Subject:     p.Subject,
		Current:     p.Current,
		Constraints: p.Constraints,
		Transition:  p.Transition,
	}
	for _, c := range p.Constraints {
		if !c.Complete() {
			return deny(ReasonConstraintUnknown, "semantic constraint is incomplete")
		}
		for _, predicate := range c.Predicates {
			ok, known := evaluateEvidenceDecomposedPredicate(bridge, predicate)
			if !known {
				return deny(ReasonConstraintUnknown, "cannot evaluate semantic constraint")
			}
			if !ok {
				return deny(ReasonConstraintViolated, "semantic constraint is violated")
			}
		}
	}

	return allow()
}

func provenanceTrustFact(issuer Identity) string {
	return "issuer:" + issuer.Kind + ":" + issuer.ID
}

// BuildProvenanceTrustState reuses the existing State primitive to model the
// current set of trusted attestation issuers. This is not a sixth primitive.
//
// In production, the authenticity/currentness of this State must terminate in
// an external root of trust (for example, GenesisManifest / cryptographic root)
// rather than a self-asserted boolean inside the proposal.
func BuildProvenanceTrustState(version string, trusted []Identity) StateRef {
	facts := make(map[string]string, len(trusted))
	keys := make([]string, 0, len(trusted))
	for _, issuer := range trusted {
		if !issuer.Complete() {
			continue
		}
		key := provenanceTrustFact(issuer)
		facts[key] = "trusted"
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := []string{provenanceTrustNamespace, "issuers", version}
	for _, key := range keys {
		parts = append(parts, key, facts[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))

	return StateRef{
		Namespace: provenanceTrustNamespace,
		ObjectID:  "issuers",
		Version:   version,
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Facts:     facts,
	}
}

// EvaluateTrustBoundAdmission makes explicit a hidden assumption exposed by
// v10: cryptographic/binding validity is not the same thing as issuer trust.
//
// v9's Attestation.Valid is treated here only as "the attestation passed its
// integrity verifier". Authorization of the issuer is checked independently
// against current trusted-issuer State.
func EvaluateTrustBoundAdmission(
	p EvidenceDecomposedProposal,
	trust StateRef,
) AdmissionResult {
	if !trust.Complete() ||
		trust.Namespace != provenanceTrustNamespace ||
		trust.ObjectID != "issuers" {
		return deny(ReasonMissingState, "provenance trust state is incomplete or invalid")
	}

	if result := EvaluateEvidenceDecomposedAdmission(p); result.Decision != DecisionAllow {
		return result
	}

	for _, attestation := range p.Attestations {
		if trust.Facts[provenanceTrustFact(attestation.Issuer)] != "trusted" {
			return deny(ReasonEvidenceInvalid, "attestation issuer is not trusted by current provenance state")
		}
	}

	return allow()
}
