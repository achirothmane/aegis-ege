package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// IdentityFreeAttestation deliberately removes both subject identity and issuer
// identity from the runtime authorization object.
//
// Valid therefore represents an opaque verification result. v14 uses this
// deliberately weak abstraction to test whether identity can disappear from
// the semantic kernel surface without creating bearer-style authority.
type IdentityFreeAttestation struct {
	ID            string
	Decision      AdmissionDecision
	BindingDigest string
	Valid         bool
}

func (a IdentityFreeAttestation) Complete() bool {
	return a.ID != "" &&
		a.Decision != "" &&
		a.BindingDigest != ""
}

// IdentityFreeProposal is the three-primitive candidate:
//
//   State + Attestation + Transition
//
// It intentionally has no subject, actor, executor, principal, issuer, key ID,
// tenant identity, or equivalent identity-bearing field.
type IdentityFreeProposal struct {
	Current     StateRef
	Attestation IdentityFreeAttestation
	Transition  Transition
}

func IdentityFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
}

func identityFreeBindingDigest(
	p IdentityFreeProposal,
	decision AdmissionDecision,
) string {
	parts := []string{
		string(decision),
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

// BuildIdentityFreeAdmission begins with an already-admitted v11 relation and
// then deliberately strips all identity semantics from the compact runtime
// authorization.
//
// The source trust relation is checked before stripping. Runtime v14 receives no
// subject or issuer identity at all.
func BuildIdentityFreeAdmission(
	source ConstraintFreeProposal,
	trust StateRef,
) (IdentityFreeProposal, error) {
	if result := EvaluateConstraintFreeAdmission(source, trust); result.Decision != DecisionAllow {
		return IdentityFreeProposal{}, errors.New("source relation is not admitted")
	}

	out := IdentityFreeProposal{
		Current:    source.Current,
		Transition: source.Transition,
	}
	out.Attestation = IdentityFreeAttestation{
		ID:       "identity-free:" + source.Attestation.ID,
		Decision: source.Attestation.Decision,
		Valid:    source.Attestation.Valid,
	}
	out.Attestation.BindingDigest = identityFreeBindingDigest(
		out,
		out.Attestation.Decision,
	)
	return out, nil
}

// EvaluateIdentityFreeAdmission can verify state binding, transition identity,
// and an opaque attestation result, but it cannot answer who is presenting or
// executing the authorization.
//
// Any actor that can present the same object is therefore indistinguishable.
func EvaluateIdentityFreeAdmission(p IdentityFreeProposal) AdmissionResult {
	switch {
	case !p.Current.Complete():
		return deny(ReasonMissingState, "current state binding is incomplete")
	case !p.Attestation.Complete():
		return deny(ReasonMissingEvidence, "identity-free attestation is incomplete")
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

	if !p.Attestation.Valid {
		return deny(ReasonEvidenceInvalid, "attestation verification failed")
	}
	if p.Attestation.Decision != DecisionAllow {
		return deny(ReasonConstraintViolated, "attested decision is not ALLOW")
	}
	if p.Attestation.BindingDigest != identityFreeBindingDigest(
		p,
		p.Attestation.Decision,
	) {
		return deny(ReasonEvidenceInvalid, "attestation is stale or rebound")
	}

	return allow()
}
