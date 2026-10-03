package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// AdmissionAttestation is a specialized form of the existing Attestation /
// Provenance primitive. It carries an already-adjudicated decision bound to the
// exact subject, state, target, and transition.
//
// The policy rules that produced the decision are not part of the kernel input
// in v11. They remain the responsibility of the trusted policy/evidence
// producer.
type AdmissionAttestation struct {
	ID            string
	Issuer        Identity
	Decision      AdmissionDecision
	BindingDigest string
	Valid         bool
}

func (a AdmissionAttestation) Complete() bool {
	return a.ID != "" &&
		a.Issuer.Complete() &&
		a.Decision != "" &&
		a.BindingDigest != ""
}

// ConstraintFreeProposal removes Capability, Evidence, and Constraint from the
// semantic admission input.
type ConstraintFreeProposal struct {
	Subject     Identity
	Current     StateRef
	Attestation AdmissionAttestation
	Transition  Transition
}

func ConstraintFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
}

func admissionDecisionBindingDigest(
	p ConstraintFreeProposal,
	issuer Identity,
	decision AdmissionDecision,
) string {
	parts := []string{
		issuer.ID,
		issuer.Kind,
		string(decision),
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
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildAdmissionAttestation is a migration / producer-side helper.
//
// It evaluates the richer v10 relation first. Only after that relation is
// admitted may a trusted policy issuer mint the compact v11 attestation.
//
// Runtime v11 admission does not consume the original constraints.
func BuildAdmissionAttestation(
	source EvidenceDecomposedProposal,
	trust StateRef,
	issuer Identity,
) (ConstraintFreeProposal, error) {
	if result := EvaluateTrustBoundAdmission(source, trust); result.Decision != DecisionAllow {
		return ConstraintFreeProposal{}, errors.New("source relation is not admitted")
	}
	if !issuer.Complete() ||
		trust.Facts[provenanceTrustFact(issuer)] != "trusted" {
		return ConstraintFreeProposal{}, errors.New("policy issuer is not trusted")
	}

	out := ConstraintFreeProposal{
		Subject: source.Subject,
		Current: source.Current,
		Transition: source.Transition,
	}
	out.Attestation = AdmissionAttestation{
		ID:       "admission:" + issuer.ID,
		Issuer:   issuer,
		Decision: DecisionAllow,
		Valid:    true,
	}
	out.Attestation.BindingDigest = admissionDecisionBindingDigest(
		out,
		issuer,
		out.Attestation.Decision,
	)
	return out, nil
}

// EvaluateConstraintFreeAdmission is intentionally small.
//
// The kernel no longer evaluates policy predicates directly. It verifies that a
// trusted issuer has attested to ALLOW for the exact state-bound transition.
// This tests whether Constraint is a semantic kernel primitive or a policy
// producer concern.
func EvaluateConstraintFreeAdmission(
	p ConstraintFreeProposal,
	trust StateRef,
) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case !p.Attestation.Complete():
		return deny(ReasonMissingEvidence, "admission attestation is incomplete")
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

	if !trust.Complete() ||
		trust.Namespace != provenanceTrustNamespace ||
		trust.ObjectID != "issuers" {
		return deny(ReasonMissingState, "provenance trust state is incomplete or invalid")
	}
	if trust.Facts[provenanceTrustFact(p.Attestation.Issuer)] != "trusted" {
		return deny(ReasonEvidenceInvalid, "admission issuer is not trusted")
	}
	if !p.Attestation.Valid {
		return deny(ReasonEvidenceInvalid, "admission attestation is invalid")
	}
	if p.Attestation.Decision != DecisionAllow {
		return deny(ReasonConstraintViolated, "attested decision is not ALLOW")
	}
	if p.Attestation.BindingDigest != admissionDecisionBindingDigest(
		p,
		p.Attestation.Issuer,
		p.Attestation.Decision,
	) {
		return deny(ReasonEvidenceInvalid, "admission attestation is stale or rebound")
	}

	return allow()
}
