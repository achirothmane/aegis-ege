package primitivereduction

import (
	"reflect"
	"testing"
)

type identityFreeWorld struct {
	Proposal     IdentityFreeProposal
	RuntimeActor Identity
}

func TestIdentityFreeCandidateHasOnlyThreeInputs(t *testing.T) {
	got := IdentityFreeCandidatePrimitives()
	want := []Primitive{
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v14 candidate = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveIdentity ||
			primitive == PrimitiveConstraint ||
			primitive == PrimitiveCapability ||
			primitive == PrimitiveEvidence {
			t.Fatalf("eliminated primitive survived: %q", primitive)
		}
	}
}

func TestIdentityFreeProposalContainsNoIdentitySignal(t *testing.T) {
	proposalType := reflect.TypeOf(IdentityFreeProposal{})
	for _, forbidden := range []string{
		"Subject",
		"Identity",
		"Actor",
		"Executor",
		"Principal",
		"Issuer",
		"Tenant",
		"KeyID",
	} {
		if _, ok := proposalType.FieldByName(forbidden); ok {
			t.Fatalf("identity-free proposal smuggled identity through %q", forbidden)
		}
	}

	attestationType := reflect.TypeOf(IdentityFreeAttestation{})
	for _, forbidden := range []string{
		"Subject",
		"Identity",
		"Actor",
		"Executor",
		"Principal",
		"Issuer",
		"Tenant",
		"KeyID",
	} {
		if _, ok := attestationType.FieldByName(forbidden); ok {
			t.Fatalf("identity-free attestation smuggled identity through %q", forbidden)
		}
	}
}

func TestThreeDomainsCannotDistinguishAuthorizedFromSubstitutedActor(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			source, trust, _ := constraintFreeFixture(t, fixture)
			reduced, err := BuildIdentityFreeAdmission(source, trust)
			if err != nil {
				t.Fatalf("build identity-free admission: %v", err)
			}

			authorizedWorld := identityFreeWorld{
				Proposal:     reduced,
				RuntimeActor: source.Subject,
			}
			substitutedWorld := identityFreeWorld{
				Proposal: reduced,
				RuntimeActor: Identity{
					ID:   source.Subject.ID + ":substituted",
					Kind: source.Subject.Kind,
				},
			}

			if authorizedWorld.RuntimeActor == substitutedWorld.RuntimeActor {
				t.Fatal("test requires distinct runtime actors")
			}
			if !reflect.DeepEqual(authorizedWorld.Proposal, substitutedWorld.Proposal) {
				t.Fatal("identity-free kernel inputs unexpectedly differ")
			}

			authorizedDecision := EvaluateIdentityFreeAdmission(authorizedWorld.Proposal)
			substitutedDecision := EvaluateIdentityFreeAdmission(substitutedWorld.Proposal)
			if authorizedDecision.Decision != DecisionAllow ||
				substitutedDecision.Decision != DecisionAllow {
				t.Fatalf("indistinguishability demonstration failed: authorized=%+v substituted=%+v",
					authorizedDecision, substitutedDecision)
			}
		})
	}
}

func TestV11RejectsSubjectSubstitutionThatV14CannotRepresent(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])

	v11Substitution := source
	v11Substitution.Subject.ID += ":substituted"
	v11Result := EvaluateConstraintFreeAdmission(v11Substitution, trust)
	if v11Result.Decision != DecisionDeny || v11Result.Reason != ReasonEvidenceInvalid {
		t.Fatalf("v11 unexpectedly lost subject binding: %+v", v11Result)
	}

	reduced, err := BuildIdentityFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build identity-free admission: %v", err)
	}

	worldA := identityFreeWorld{
		Proposal:     reduced,
		RuntimeActor: source.Subject,
	}
	worldB := identityFreeWorld{
		Proposal: reduced,
		RuntimeActor: Identity{
			ID:   source.Subject.ID + ":substituted",
			Kind: source.Subject.Kind,
		},
	}

	if !reflect.DeepEqual(worldA.Proposal, worldB.Proposal) {
		t.Fatal("v14 unexpectedly preserved subject identity")
	}
	if got := EvaluateIdentityFreeAdmission(worldB.Proposal); got.Decision != DecisionAllow {
		t.Fatalf("identity-free evaluator somehow observed actor substitution: %+v", got)
	}
}

func TestIdentityFreeAuthorizationBecomesBearerAuthorityAcrossTenants(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[1])
	reduced, err := BuildIdentityFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build identity-free admission: %v", err)
	}

	tenantA := Identity{ID: "tenant-a:worker-7", Kind: "executor"}
	tenantB := Identity{ID: "tenant-b:worker-7", Kind: "executor"}

	worldA := identityFreeWorld{Proposal: reduced, RuntimeActor: tenantA}
	worldB := identityFreeWorld{Proposal: reduced, RuntimeActor: tenantB}

	if worldA.RuntimeActor == worldB.RuntimeActor {
		t.Fatal("test requires distinct tenant principals")
	}
	if !reflect.DeepEqual(worldA.Proposal, worldB.Proposal) {
		t.Fatal("bearer authorization unexpectedly changed with runtime actor")
	}

	a := EvaluateIdentityFreeAdmission(worldA.Proposal)
	b := EvaluateIdentityFreeAdmission(worldB.Proposal)
	if a.Decision != DecisionAllow || b.Decision != DecisionAllow {
		t.Fatalf("identity-free object did not behave as bearer authority: a=%+v b=%+v", a, b)
	}
}

func TestIdentityFreeModelStillProtectsStateAndTransitionBinding(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[2])
	reduced, err := BuildIdentityFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build identity-free admission: %v", err)
	}

	t.Run("state", func(t *testing.T) {
		attacked := reduced
		attacked.Current.Version += ":next"
		attacked.Transition.From.Version = attacked.Current.Version
		got := EvaluateIdentityFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("state substitution admitted: %+v", got)
		}
	})

	t.Run("operation", func(t *testing.T) {
		attacked := reduced
		attacked.Transition.Operation = "operation:substituted"
		got := EvaluateIdentityFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("operation substitution admitted: %+v", got)
		}
	})

	t.Run("target", func(t *testing.T) {
		attacked := reduced
		attacked.Transition.To.ObjectID = "target:substituted"
		got := EvaluateIdentityFreeAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
			t.Fatalf("target substitution admitted: %+v", got)
		}
	})
}

func TestIdentityFreeAttestedDenyStillFailsClosed(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])
	reduced, err := BuildIdentityFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build identity-free admission: %v", err)
	}

	reduced.Attestation.Decision = DecisionDeny
	reduced.Attestation.BindingDigest = identityFreeBindingDigest(
		reduced,
		reduced.Attestation.Decision,
	)

	got := EvaluateIdentityFreeAdmission(reduced)
	if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("attested DENY became executable: %+v", got)
	}
}

func TestIdentityFreeInvalidAttestationFailsClosed(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])
	reduced, err := BuildIdentityFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build identity-free admission: %v", err)
	}
	reduced.Attestation.Valid = false

	got := EvaluateIdentityFreeAdmission(reduced)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("invalid attestation admitted: %+v", got)
	}
}
