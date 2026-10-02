package primitivereduction

import (
	"reflect"
	"testing"
)

type stateFreeWorld struct {
	Proposal      StateFreeProposal
	ExternalState StateRef
}

func TestStateFreeCandidateHasOnlyThreeInputs(t *testing.T) {
	got := StateFreeCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v13 candidate = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveState ||
			primitive == PrimitiveConstraint ||
			primitive == PrimitiveCapability ||
			primitive == PrimitiveEvidence {
			t.Fatalf("eliminated primitive survived: %q", primitive)
		}
	}
}

func TestStateFreeProposalContainsNoStateRevisionSignal(t *testing.T) {
	proposalType := reflect.TypeOf(StateFreeProposal{})
	for _, forbidden := range []string{
		"Current",
		"State",
		"StateRef",
		"Version",
		"Digest",
		"Before",
		"After",
	} {
		if _, ok := proposalType.FieldByName(forbidden); ok {
			t.Fatalf("state-free proposal smuggled state semantics through %q", forbidden)
		}
	}

	transitionType := reflect.TypeOf(StateFreeTransition{})
	for _, forbidden := range []string{
		"From",
		"To",
		"State",
		"Version",
		"Digest",
		"Before",
		"After",
	} {
		if _, ok := transitionType.FieldByName(forbidden); ok {
			t.Fatalf("state-free transition smuggled state semantics through %q", forbidden)
		}
	}
}

func TestThreeDomainsCannotDistinguishCurrentFromAdvancedState(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			source, trust, _ := constraintFreeFixture(t, fixture)
			reduced, trustedIssuer, err := BuildStateFreeAdmission(source, trust)
			if err != nil {
				t.Fatalf("build state-free admission: %v", err)
			}

			currentWorld := stateFreeWorld{
				Proposal:      reduced,
				ExternalState: source.Current,
			}

			advanced := source.Current
			advanced.Version += ":advanced"
			advanced.Digest = "sha256:advanced-external-state"
			advancedWorld := stateFreeWorld{
				Proposal:      reduced,
				ExternalState: advanced,
			}

			if reflect.DeepEqual(currentWorld.ExternalState, advancedWorld.ExternalState) {
				t.Fatal("test requires different external states")
			}
			if !reflect.DeepEqual(currentWorld.Proposal, advancedWorld.Proposal) {
				t.Fatal("state-free kernel inputs unexpectedly differ")
			}

			currentDecision := EvaluateStateFreeAdmission(currentWorld.Proposal, trustedIssuer)
			advancedDecision := EvaluateStateFreeAdmission(advancedWorld.Proposal, trustedIssuer)
			if currentDecision.Decision != DecisionAllow ||
				advancedDecision.Decision != DecisionAllow {
				t.Fatalf("indistinguishability demonstration failed: current=%+v advanced=%+v",
					currentDecision, advancedDecision)
			}
		})
	}
}

func TestV11RejectsStateAdvanceThatV13CannotRepresent(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])

	v11Advanced := source
	v11Advanced.Current.Version += ":advanced"
	v11Advanced.Current.Digest = "sha256:advanced-external-state"
	v11Advanced.Transition.From.Version = v11Advanced.Current.Version
	v11Advanced.Transition.From.Digest = v11Advanced.Current.Digest

	v11Result := EvaluateConstraintFreeAdmission(v11Advanced, trust)
	if v11Result.Decision != DecisionDeny || v11Result.Reason != ReasonEvidenceInvalid {
		t.Fatalf("v11 unexpectedly failed to enforce state-bound attestation: %+v", v11Result)
	}

	reduced, trustedIssuer, err := BuildStateFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build state-free admission: %v", err)
	}

	worldBefore := stateFreeWorld{
		Proposal:      reduced,
		ExternalState: source.Current,
	}
	worldAfter := stateFreeWorld{
		Proposal:      reduced,
		ExternalState: v11Advanced.Current,
	}

	if !reflect.DeepEqual(worldBefore.Proposal, worldAfter.Proposal) {
		t.Fatal("v13 unexpectedly retained state identity")
	}
	if got := EvaluateStateFreeAdmission(worldAfter.Proposal, trustedIssuer); got.Decision != DecisionAllow {
		t.Fatalf("state-free evaluator somehow observed external state advance: %+v", got)
	}
}

func TestSameValueDifferentRevisionRemainsInvisibleWithoutState(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[1])
	reduced, trustedIssuer, err := BuildStateFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build state-free admission: %v", err)
	}

	revision1 := source.Current
	revision3 := source.Current
	revision3.Version = source.Current.Version + ":rev3"
	// Keep the same digest and facts to model ABA-like return to the same
	// visible value under a distinct revision identity.

	if revision1.Digest != revision3.Digest {
		t.Fatal("test requires same visible state digest")
	}
	if revision1.Version == revision3.Version {
		t.Fatal("test requires distinct revision identity")
	}

	world1 := stateFreeWorld{Proposal: reduced, ExternalState: revision1}
	world3 := stateFreeWorld{Proposal: reduced, ExternalState: revision3}

	if !reflect.DeepEqual(world1.Proposal, world3.Proposal) {
		t.Fatal("state-free input unexpectedly preserved revision identity")
	}
	if a, b := EvaluateStateFreeAdmission(world1.Proposal, trustedIssuer),
		EvaluateStateFreeAdmission(world3.Proposal, trustedIssuer); a != b {
		t.Fatalf("state-free evaluator distinguished invisible revision identity: a=%+v b=%+v", a, b)
	}
}

func TestStateFreeModelStillProtectsSubjectOperationTargetAndIssuer(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[2])
	reduced, trustedIssuer, err := BuildStateFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build state-free admission: %v", err)
	}

	t.Run("subject", func(t *testing.T) {
		attacked := reduced
		attacked.Subject.ID = "subject:substituted"
		got := EvaluateStateFreeAdmission(attacked, trustedIssuer)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("subject substitution admitted: %+v", got)
		}
	})

	t.Run("operation", func(t *testing.T) {
		attacked := reduced
		attacked.Transition.Operation = "operation:substituted"
		got := EvaluateStateFreeAdmission(attacked, trustedIssuer)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("operation substitution admitted: %+v", got)
		}
	})

	t.Run("target", func(t *testing.T) {
		attacked := reduced
		attacked.Transition.TargetKey = "target:substituted"
		got := EvaluateStateFreeAdmission(attacked, trustedIssuer)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("target substitution admitted: %+v", got)
		}
	})

	t.Run("issuer", func(t *testing.T) {
		attacked := reduced
		attacker := Identity{ID: "policy:untrusted", Kind: "policy"}
		attacked.Attestation.Issuer = attacker
		attacked.Attestation.BindingDigest = stateFreeBindingDigest(
			attacked,
			attacker,
			attacked.Attestation.Decision,
		)
		got := EvaluateStateFreeAdmission(attacked, trustedIssuer)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("issuer substitution admitted: %+v", got)
		}
	})
}

func TestStateFreeAttestedDenyStillFailsClosed(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])
	reduced, trustedIssuer, err := BuildStateFreeAdmission(source, trust)
	if err != nil {
		t.Fatalf("build state-free admission: %v", err)
	}

	reduced.Attestation.Decision = DecisionDeny
	reduced.Attestation.BindingDigest = stateFreeBindingDigest(
		reduced,
		reduced.Attestation.Issuer,
		reduced.Attestation.Decision,
	)

	got := EvaluateStateFreeAdmission(reduced, trustedIssuer)
	if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("attested DENY became executable: %+v", got)
	}
}
