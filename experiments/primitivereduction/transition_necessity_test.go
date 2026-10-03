package primitivereduction

import (
	"reflect"
	"testing"
)

type transitionFreeWorld struct {
	Proposal           TransitionFreeProposal
	RequestedOperation string
	ObservedAfter      StateRef
}

func TestTransitionFreeCandidateHasOnlyThreeInputs(t *testing.T) {
	got := TransitionFreeCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v12 candidate = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveTransition ||
			primitive == PrimitiveConstraint ||
			primitive == PrimitiveCapability ||
			primitive == PrimitiveEvidence {
			t.Fatalf("eliminated primitive survived: %q", primitive)
		}
	}
}

func TestTransitionFreeProposalContainsNoActionIdentity(t *testing.T) {
	typ := reflect.TypeOf(TransitionFreeProposal{})
	for _, forbidden := range []string{
		"Transition",
		"Operation",
		"Effect",
		"Action",
		"DesiredState",
		"After",
	} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("transition-free proposal smuggled action semantics through %q", forbidden)
		}
	}

	attestationType := reflect.TypeOf(TransitionFreeAttestation{})
	for _, forbidden := range []string{
		"Transition",
		"Operation",
		"Effect",
		"Action",
		"DesiredState",
		"After",
	} {
		if _, ok := attestationType.FieldByName(forbidden); ok {
			t.Fatalf("transition-free attestation smuggled action semantics through %q", forbidden)
		}
	}
}

func TestThreeDomainsLoseOperationDistinctionWhenTransitionRemoved(t *testing.T) {
	alternatives := map[string]string{
		"github":     "github.repository.delete",
		"kubernetes": "kubernetes.namespace.delete",
		"postgres":   "postgres.database.drop",
	}

	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			source, trust, _ := constraintFreeFixture(t, fixture)
			reduced, err := BuildTransitionFreeAttestation(source, trust)
			if err != nil {
				t.Fatalf("build transition-free proposal: %v", err)
			}

			alternative := alternatives[fixture.name]
			if alternative == "" {
				alternative = "unmodeled.alternative.effect"
			}
			if alternative == source.Transition.Operation {
				t.Fatal("alternative operation unexpectedly equals admitted operation")
			}

			trustedWorld := transitionFreeWorld{
				Proposal:           reduced,
				RequestedOperation: source.Transition.Operation,
				ObservedAfter:      reduced.Current,
			}
			substitutedWorld := transitionFreeWorld{
				Proposal:           reduced,
				RequestedOperation: alternative,
				ObservedAfter:      reduced.Current,
			}

			if !reflect.DeepEqual(trustedWorld.Proposal, substitutedWorld.Proposal) {
				t.Fatal("transition-free kernel inputs unexpectedly differ")
			}
			if !reflect.DeepEqual(trustedWorld.ObservedAfter, substitutedWorld.ObservedAfter) {
				t.Fatal("same-state external effects unexpectedly produced different modeled state")
			}

			first := EvaluateTransitionFreeAdmission(trustedWorld.Proposal, trust)
			second := EvaluateTransitionFreeAdmission(substitutedWorld.Proposal, trust)
			if first.Decision != DecisionAllow || second.Decision != DecisionAllow {
				t.Fatalf("indistinguishability demonstration failed: admitted=%+v substituted=%+v",
					first, second)
			}
		})
	}
}

func TestV11RejectsOperationSubstitutionThatV12CannotRepresent(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])

	v11Substitution := source
	v11Substitution.Transition.Operation = "github.repository.delete"
	v11Result := EvaluateConstraintFreeAdmission(v11Substitution, trust)
	if v11Result.Decision != DecisionDeny || v11Result.Reason != ReasonEvidenceInvalid {
		t.Fatalf("v11 lost operation binding unexpectedly: %+v", v11Result)
	}

	reduced, err := BuildTransitionFreeAttestation(source, trust)
	if err != nil {
		t.Fatalf("build transition-free proposal: %v", err)
	}
	if got := EvaluateTransitionFreeAdmission(reduced, trust); got.Decision != DecisionAllow {
		t.Fatalf("baseline transition-free relation not admitted: %+v", got)
	}

	// There is no field in reduced into which the substituted operation can be
	// placed. Both operations therefore map to the same kernel input.
	worldA := transitionFreeWorld{Proposal: reduced, RequestedOperation: source.Transition.Operation}
	worldB := transitionFreeWorld{Proposal: reduced, RequestedOperation: "github.repository.delete"}
	if !reflect.DeepEqual(worldA.Proposal, worldB.Proposal) {
		t.Fatal("v12 unexpectedly preserved operation identity")
	}
}

func TestBeforeAfterStatePairCannotRecoverExternalEffectIdentity(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[2])
	reduced, err := BuildTransitionFreeAttestation(source, trust)
	if err != nil {
		t.Fatalf("build transition-free proposal: %v", err)
	}

	before := reduced.Current
	after := reduced.Current // opaque/non-idempotent external effect may leave modeled state unchanged.

	worldA := transitionFreeWorld{
		Proposal:           reduced,
		RequestedOperation: "external.effect.alpha",
		ObservedAfter:      after,
	}
	worldB := transitionFreeWorld{
		Proposal:           reduced,
		RequestedOperation: "external.effect.beta",
		ObservedAfter:      after,
	}

	if worldA.RequestedOperation == worldB.RequestedOperation {
		t.Fatal("test requires distinct external effects")
	}
	if before.Digest != worldA.ObservedAfter.Digest ||
		before.Digest != worldB.ObservedAfter.Digest {
		t.Fatal("test requires identical before/after modeled state")
	}
	if !reflect.DeepEqual(worldA.Proposal, worldB.Proposal) {
		t.Fatal("kernel inputs differ despite removed transition")
	}

	if a, b := EvaluateTransitionFreeAdmission(worldA.Proposal, trust),
		EvaluateTransitionFreeAdmission(worldB.Proposal, trust); a != b {
		t.Fatalf("transition-free evaluator somehow distinguished identical inputs: a=%+v b=%+v", a, b)
	}
}

func TestTransitionFreeModelStillProtectsOtherDimensions(t *testing.T) {
	base, trust, _ := constraintFreeFixture(t, fixtures()[1])
	reduced, err := BuildTransitionFreeAttestation(base, trust)
	if err != nil {
		t.Fatalf("build transition-free proposal: %v", err)
	}

	t.Run("subject", func(t *testing.T) {
		attacked := reduced
		attacked.Subject.ID = "subject:substituted"
		got := EvaluateTransitionFreeAdmission(attacked, trust)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("subject substitution admitted: %+v", got)
		}
	})

	t.Run("state", func(t *testing.T) {
		attacked := reduced
		attacked.Current.Version += ":next"
		got := EvaluateTransitionFreeAdmission(attacked, trust)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("state substitution admitted: %+v", got)
		}
	})

	t.Run("issuer", func(t *testing.T) {
		attacked := reduced
		attacker := Identity{ID: "policy:untrusted", Kind: "policy"}
		attacked.Attestation.Issuer = attacker
		attacked.Attestation.BindingDigest = transitionFreeBindingDigest(
			attacked,
			attacker,
			attacked.Attestation.Decision,
		)
		got := EvaluateTransitionFreeAdmission(attacked, trust)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("untrusted issuer admitted: %+v", got)
		}
	})
}

func TestTransitionFreeAttestedDenyStillFailsClosed(t *testing.T) {
	source, trust, _ := constraintFreeFixture(t, fixtures()[0])
	reduced, err := BuildTransitionFreeAttestation(source, trust)
	if err != nil {
		t.Fatalf("build transition-free proposal: %v", err)
	}

	reduced.Attestation.Decision = DecisionDeny
	reduced.Attestation.BindingDigest = transitionFreeBindingDigest(
		reduced,
		reduced.Attestation.Issuer,
		reduced.Attestation.Decision,
	)

	got := EvaluateTransitionFreeAdmission(reduced, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("attested DENY became executable: %+v", got)
	}
}
