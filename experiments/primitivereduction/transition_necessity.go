package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// TransitionFreeAttestation deliberately binds only subject + current state +
// issuer + decision. It contains no operation, desired after-state, effect
// identity, or transition digest.
//
// v12 uses this record to falsify the hypothesis that Transition can disappear
// from the semantic kernel surface without losing action identity.
type TransitionFreeAttestation struct {
	ID            string
	Issuer        Identity
	Decision      AdmissionDecision
	BindingDigest string
	Valid         bool
}

func (a TransitionFreeAttestation) Complete() bool {
	return a.ID != "" &&
		a.Issuer.Complete() &&
		a.Decision != "" &&
		a.BindingDigest != ""
}

// TransitionFreeProposal is the three-primitive candidate.
//
// It intentionally has no Transition field.
type TransitionFreeProposal struct {
	Subject     Identity
	Current     StateRef
	Attestation TransitionFreeAttestation
}

func TransitionFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
	}
}

func transitionFreeBindingDigest(
	p TransitionFreeProposal,
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
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildTransitionFreeAttestation is a reduction helper.
//
// It starts from an already-admitted v11 relation and then deliberately drops
// the transition semantics when minting the compact attestation. Runtime v12
// admission therefore cannot know which effect was originally authorized.
func BuildTransitionFreeAttestation(
	source ConstraintFreeProposal,
	trust StateRef,
) (TransitionFreeProposal, error) {
	if result := EvaluateConstraintFreeAdmission(source, trust); result.Decision != DecisionAllow {
		return TransitionFreeProposal{}, errors.New("source relation is not admitted")
	}

	out := TransitionFreeProposal{
		Subject: source.Subject,
		Current: source.Current,
	}
	out.Attestation = TransitionFreeAttestation{
		ID:       "transition-free:" + source.Attestation.Issuer.ID,
		Issuer:   source.Attestation.Issuer,
		Decision: source.Attestation.Decision,
		Valid:    source.Attestation.Valid,
	}
	out.Attestation.BindingDigest = transitionFreeBindingDigest(
		out,
		out.Attestation.Issuer,
		out.Attestation.Decision,
	)

	return out, nil
}

// EvaluateTransitionFreeAdmission can verify identity, state, provenance, and
// decision integrity, but it cannot distinguish one requested effect from
// another because no transition/effect identity exists in the input.
func EvaluateTransitionFreeAdmission(
	p TransitionFreeProposal,
	trust StateRef,
) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case !p.Attestation.Complete():
		return deny(ReasonMissingEvidence, "transition-free attestation is incomplete")
	}

	if !trust.Complete() ||
		trust.Namespace != provenanceTrustNamespace ||
		trust.ObjectID != "issuers" {
		return deny(ReasonMissingState, "provenance trust state is incomplete or invalid")
	}
	if trust.Facts[provenanceTrustFact(p.Attestation.Issuer)] != "trusted" {
		return deny(ReasonEvidenceInvalid, "attestation issuer is not trusted")
	}
	if !p.Attestation.Valid {
		return deny(ReasonEvidenceInvalid, "attestation is invalid")
	}
	if p.Attestation.Decision != DecisionAllow {
		return deny(ReasonConstraintViolated, "attested decision is not ALLOW")
	}
	if p.Attestation.BindingDigest != transitionFreeBindingDigest(
		p,
		p.Attestation.Issuer,
		p.Attestation.Decision,
	) {
		return deny(ReasonEvidenceInvalid, "attestation is stale or rebound")
	}

	return allow()
}
