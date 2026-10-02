package primitivereduction

import (
	"reflect"
	"testing"
)

type attestationFreeWorld struct {
	Proposal   AttestationFreeProposal
	Authorized bool
}

func TestAttestationFreeCandidateHasOnlyThreeInputs(t *testing.T) {
	got := AttestationFreeCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v15 candidate = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveAttestation ||
			primitive == PrimitiveConstraint ||
			primitive == PrimitiveCapability ||
			primitive == PrimitiveEvidence {
			t.Fatalf("eliminated primitive survived: %q", primitive)
		}
	}
}

func TestAttestationFreeProposalContainsNoAuthorizationSignal(t *testing.T) {
	typ := reflect.TypeOf(AttestationFreeProposal{})
	for _, forbidden := range []string{
		"Attestation",
		"Evidence",
		"Capability",
		"Constraint",
		"Authority",
		"Decision",
		"Issuer",
		"Signature",
		"Proof",
	} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("attestation-free proposal smuggled authorization through %q", forbidden)
		}
	}
}

func TestThreeDomainsCannotDistinguishAuthorizedFromUnauthorizedWorld(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			source, trust, _ := constraintFreeFixture(t, fixture)
			reduced, err := BuildAttestationFreeAdmission(source, trust)
			if err != nil {
				t.Fatalf("build attestation-free admission: %v", err)
			}

			authorizedWorld := attestationFreeWorld{
				Proposal:   reduced,
				Authorized: true,
			}
			unauthorizedWorld := attestationFreeWorld{
				Proposal:   reduced,
				Authorized: false,
			}

			if authorizedWorld.Authorized == unauthorizedWorld.Authorized {
				t.Fatal("test requires different authorization reality")
			}
			if !reflect.DeepEqual(authorizedWorld.Proposal, unauthorizedWorld.Proposal) {
				t.Fatal("attestation-free kernel inputs unexpectedly differ")
			}

			authorizedDecision := EvaluateAttestationFreeAdmission(authorizedWorld.Proposal)
			unauthorizedDecision := EvaluateAttestationFreeAdmission(unauthorizedWorld.Proposal)
			if authorizedDecision.Decision != DecisionAllow ||
				unauthorizedDecision.Decision != DecisionAllow {
				t.Fatalf("indistinguishability demonstration failed: authorized=%+v unauthorized=%+v",
					authorizedDecision, unauthorizedDecision)
			}
		})
	}
}

func TestV11RejectsMissingAttestationThatV15CannotRepresent(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])

	v11Missing := source
	v11Missing.Attestation = AdmissionAttestation{}
	v11Result := EvaluateConstraintFreeAdmission(v11Missing, trust)
	if v11Result.Decision != DecisionDeny || v11Result.Reason != ReasonMissingEvidence {
		t.Fatalf("v11 unexpectedly accepted missing attestation: %+v", v11Result)
	}

	reduced, err := BuildAttestationFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build attestation-free admission: %v", err)
	}

	if got := EvaluateAttestationFreeAdmission(reduced); got.Decision != DecisionAllow {
		t.Fatalf("v15 structural evaluator did not admit baseline relation: %+v", got)
	}

	// There is no field in reduced that can represent "trusted authorization
	// exists" versus "trusted authorization absent".
	worldAuthorized := attestationFreeWorld{Proposal: reduced, Authorized: true}
	worldUnauthorized := attestationFreeWorld{Proposal: reduced, Authorized: false}
	if !reflect.DeepEqual(worldAuthorized.Proposal, worldUnauthorized.Proposal) {
		t.Fatal("v15 unexpectedly preserved authorization provenance")
	}
}

func TestIdentityWithoutAttestationDoesNotBindAuthorityToActor(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[1])
	reduced, err := BuildAttestationFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build attestation-free admission: %v", err)
	}

	attacked := reduced
	attacked.Subject = Identity{
		ID:   source.Subject.ID + ":substituted",
		Kind: source.Subject.Kind,
	}

	// Identity remains present, but nothing says this identity is authorized for
	// this transition. Structural admission therefore cannot reject the new
	// actor.
	got := EvaluateAttestationFreeAdmission(attacked)
	if got.Decision != DecisionAllow {
		t.Fatalf("identity-only structural admission unexpectedly rejected actor substitution: %+v", got)
	}
}

func TestStateAndTransitionRemainStructurallyEnforced(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[2])
	reduced, err := BuildAttestationFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build attestation-free admission: %v", err)
	}

	t.Run("state-transition-binding", func(t *testing.T) {
		attacked := reduced
		attacked.Current.Version += ":next"
		got := EvaluateAttestationFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
			t.Fatalf("state/transition mismatch admitted: %+v", got)
		}
	})

	t.Run("missing-transition", func(t *testing.T) {
		attacked := reduced
		attacked.Transition = Transition{}
		got := EvaluateAttestationFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonMissingTransition {
			t.Fatalf("missing transition admitted: %+v", got)
		}
	})

	t.Run("missing-identity", func(t *testing.T) {
		attacked := reduced
		attacked.Subject = Identity{}
		got := EvaluateAttestationFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonMissingIdentity {
			t.Fatalf("missing identity admitted: %+v", got)
		}
	})
}

func TestFailClosedAlternativeLosesPreviouslyAuthorizedWorld(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])
	reduced, err := BuildAttestationFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build attestation-free admission: %v", err)
	}

	authorized := attestationFreeWorld{Proposal: reduced, Authorized: true}
	unauthorized := attestationFreeWorld{Proposal: reduced, Authorized: false}

	if !reflect.DeepEqual(authorized.Proposal, unauthorized.Proposal) {
		t.Fatal("test requires identical reduced inputs")
	}

	// Any deterministic fail-closed evaluator over only the reduced proposal
	// must return the same decision for both. Denying the unauthorized world
	// therefore also denies the authorized one; the original semantic
	// distinction cannot be preserved.
	denyAll := func(AttestationFreeProposal) AdmissionResult {
		return deny(ReasonMissingEvidence, "no trusted authorization provenance exists")
	}

	a := denyAll(authorized.Proposal)
	b := denyAll(unauthorized.Proposal)
	if a != b || a.Decision != DecisionDeny {
		t.Fatalf("fail-closed indistinguishability premise failed: a=%+v b=%+v", a, b)
	}
}
