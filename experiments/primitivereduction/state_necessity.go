package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// StateFreeTransition preserves action/effect identity but deliberately removes
// all state-version and state-digest semantics.
type StateFreeTransition struct {
	Operation string
	TargetKey string
}

func (t StateFreeTransition) Complete() bool {
	return t.Operation != "" && t.TargetKey != ""
}

// StateFreeAttestation binds only subject + issuer + decision + state-free
// transition. It intentionally carries no state version, digest, epoch, or
// desired before/after state.
type StateFreeAttestation struct {
	ID            string
	Issuer        Identity
	Decision      AdmissionDecision
	BindingDigest string
	Valid         bool
}

func (a StateFreeAttestation) Complete() bool {
	return a.ID != "" &&
		a.Issuer.Complete() &&
		a.Decision != "" &&
		a.BindingDigest != ""
}

// StateFreeProposal is the three-primitive candidate:
//
//   Identity + Attestation + Transition
//
// It intentionally has no StateRef field.
type StateFreeProposal struct {
	Subject     Identity
	Attestation StateFreeAttestation
	Transition  StateFreeTransition
}

func StateFreeCandidatePrimitives() []Primitive {
	return []Primitive{
		PrimitiveIdentity,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
}

func stateFreeBindingDigest(
	p StateFreeProposal,
	issuer Identity,
	decision AdmissionDecision,
) string {
	parts := []string{
		issuer.ID,
		issuer.Kind,
		string(decision),
		p.Subject.ID,
		p.Subject.Kind,
		p.Transition.Operation,
		p.Transition.TargetKey,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildStateFreeAdmission starts from an already-admitted v11 relation, then
// deliberately strips state semantics from the runtime authorization object.
//
// trust is consumed only by this producer-side migration helper. The v13
// runtime evaluator receives a fixed trusted issuer identity as an external
// trust anchor so that State is not smuggled back into the candidate surface.
func BuildStateFreeAdmission(
	source ConstraintFreeProposal,
	trust StateRef,
) (StateFreeProposal, Identity, error) {
	if result := EvaluateConstraintFreeAdmission(source, trust); result.Decision != DecisionAllow {
		return StateFreeProposal{}, Identity{}, errors.New("source relation is not admitted")
	}

	out := StateFreeProposal{
		Subject: source.Subject,
		Transition: StateFreeTransition{
			Operation: source.Transition.Operation,
			TargetKey: source.Current.TargetKey(),
		},
	}
	out.Attestation = StateFreeAttestation{
		ID:       "state-free:" + source.Attestation.Issuer.ID,
		Issuer:   source.Attestation.Issuer,
		Decision: source.Attestation.Decision,
		Valid:    source.Attestation.Valid,
	}
	out.Attestation.BindingDigest = stateFreeBindingDigest(
		out,
		out.Attestation.Issuer,
		out.Attestation.Decision,
	)

	return out, source.Attestation.Issuer, nil
}

// EvaluateStateFreeAdmission verifies action identity and provenance but has no
// information about the target's current revision.
//
// Therefore a stale authorization can remain indistinguishable from a current
// one after the external target state advances, rolls back, or changes policy-
// relevant facts.
func EvaluateStateFreeAdmission(
	p StateFreeProposal,
	trustedIssuer Identity,
) AdmissionResult {
	switch {
	case !p.Subject.Complete():
		return deny(ReasonMissingIdentity, "subject identity is incomplete")
	case !p.Attestation.Complete():
		return deny(ReasonMissingEvidence, "state-free attestation is incomplete")
	case !p.Transition.Complete():
		return deny(ReasonMissingTransition, "state-free transition is incomplete")
	}

	if !trustedIssuer.Complete() ||
		p.Attestation.Issuer != trustedIssuer {
		return deny(ReasonEvidenceInvalid, "attestation issuer is not the trusted runtime issuer")
	}
	if !p.Attestation.Valid {
		return deny(ReasonEvidenceInvalid, "attestation is invalid")
	}
	if p.Attestation.Decision != DecisionAllow {
		return deny(ReasonConstraintViolated, "attested decision is not ALLOW")
	}
	if p.Attestation.BindingDigest != stateFreeBindingDigest(
		p,
		p.Attestation.Issuer,
		p.Attestation.Decision,
	) {
		return deny(ReasonEvidenceInvalid, "attestation is stale or rebound")
	}

	return allow()
}
