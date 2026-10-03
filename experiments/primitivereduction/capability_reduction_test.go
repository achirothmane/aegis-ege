package primitivereduction

import (
	"reflect"
	"testing"
)

func reducedFixtures() []domainFixture {
	return fixtures()
}

func TestReducedCandidatePrimitivesRemoveCapability(t *testing.T) {
	got := ReducedCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveConstraint,
		PrimitiveEvidence,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reduced primitives = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveCapability {
			t.Fatal("capability survived as semantic primitive in reduced basis")
		}
	}
}

func TestThreeDomainsAdmitWithoutCapabilityField(t *testing.T) {
	for _, fixture := range reducedFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			reduced := ReduceCapability(fixture.new())
			if result := EvaluateReducedAdmission(reduced); result.Decision != DecisionAllow {
				t.Fatalf("reduced admission = %+v", result)
			}
		})
	}
}

func TestReducedProposalTypeHasNoCapabilityField(t *testing.T) {
	typ := reflect.TypeOf(ReducedProposal{})
	if _, ok := typ.FieldByName("Capability"); ok {
		t.Fatal("ReducedProposal still contains Capability field")
	}
}

func TestAuthorityRelationSurvivesCapabilityElimination(t *testing.T) {
	for _, fixture := range reducedFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			reduced := ReduceCapability(fixture.new())

			t.Run("subject-substitution", func(t *testing.T) {
				attacked := reduced
				attacked.Subject.ID = "attacker:substitute"
				got := EvaluateReducedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
					t.Fatalf("subject substitution not rejected: %+v", got)
				}
			})

			t.Run("operation-substitution", func(t *testing.T) {
				attacked := reduced
				attacked.Transition.Operation = "different-operation"
				got := EvaluateReducedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
					t.Fatalf("operation substitution not rejected: %+v", got)
				}
			})

			t.Run("target-substitution", func(t *testing.T) {
				attacked := reduced
				attacked.Transition.To.ObjectID = "other-target"
				got := EvaluateReducedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
					t.Fatalf("target substitution not rejected: %+v", got)
				}
			})

			t.Run("authority-evidence-removal", func(t *testing.T) {
				attacked := reduced
				filtered := make([]Evidence, 0, len(attacked.Evidence))
				for _, evidence := range attacked.Evidence {
					if evidence.Type != authorityEvidenceType {
						filtered = append(filtered, evidence)
					}
				}
				attacked.Evidence = filtered
				got := EvaluateReducedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("missing authority evidence not rejected: %+v", got)
				}
			})

			t.Run("authority-constraint-removal", func(t *testing.T) {
				attacked := reduced
				attacked.Constraints = append([]Constraint(nil), reduced.Constraints[1:]...)
				got := EvaluateReducedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("unused authority evidence not rejected: %+v", got)
				}
			})
		})
	}
}

func TestStaleEvidenceStillFailsClosedWithoutCapabilityPrimitive(t *testing.T) {
	for _, fixture := range reducedFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			reduced := ReduceCapability(fixture.new())
			reduced.Evidence[0].StateDigest = "sha256:stale"
			got := EvaluateReducedAdmission(reduced)
			if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
				t.Fatalf("stale evidence admitted: %+v", got)
			}
		})
	}
}

func TestDerivedCapabilityCanBeMintedAfterAdmission(t *testing.T) {
	for _, fixture := range reducedFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			original := fixture.new()
			reduced := ReduceCapability(original)

			minted, err := MintDerivedCapability(reduced)
			if err != nil {
				t.Fatalf("mint derived capability: %v", err)
			}
			if minted.Name != original.Capability.Name ||
				minted.SubjectID != original.Capability.SubjectID ||
				minted.TargetKey != original.Capability.TargetKey {
				t.Fatalf("derived capability = %+v, original = %+v", minted, original.Capability)
			}
		})
	}
}

func TestDerivedCapabilityCannotBeMintedFromUnauthorizedRelation(t *testing.T) {
	reduced := ReduceCapability(githubMergeProposal())
	reduced.Subject.ID = "attacker:substitute"

	if _, err := MintDerivedCapability(reduced); err == nil {
		t.Fatal("minted mechanical capability from unauthorized reduced relation")
	}
}

func TestFivePrimitiveAblationStillFailsClosed(t *testing.T) {
	for _, fixture := range reducedFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base := ReduceCapability(fixture.new())

			cases := []struct {
				name   Primitive
				mutate func(*ReducedProposal)
				reason Reason
			}{
				{
					name: PrimitiveIdentity,
					mutate: func(p *ReducedProposal) { p.Subject = Identity{} },
					reason: ReasonMissingIdentity,
				},
				{
					name: PrimitiveState,
					mutate: func(p *ReducedProposal) { p.Current = StateRef{} },
					reason: ReasonMissingState,
				},
				{
					name: PrimitiveConstraint,
					mutate: func(p *ReducedProposal) { p.Constraints = nil },
					reason: ReasonMissingConstraint,
				},
				{
					name: PrimitiveEvidence,
					mutate: func(p *ReducedProposal) { p.Evidence = nil },
					reason: ReasonMissingEvidence,
				},
				{
					name: PrimitiveTransition,
					mutate: func(p *ReducedProposal) { p.Transition = Transition{} },
					reason: ReasonMissingTransition,
				},
			}

			for _, tc := range cases {
				t.Run(string(tc.name), func(t *testing.T) {
					attacked := base
					tc.mutate(&attacked)
					got := EvaluateReducedAdmission(attacked)
					if got.Decision != DecisionDeny || got.Reason != tc.reason {
						t.Fatalf("ablation %s = %+v, want DENY/%s", tc.name, got, tc.reason)
					}
				})
			}
		})
	}
}

func TestCapabilityEliminationDoesNotClaimMechanicalCapabilitiesAreUnnecessary(t *testing.T) {
	reduced := ReduceCapability(postgresMigrationProposal())
	minted, err := MintDerivedCapability(reduced)
	if err != nil {
		t.Fatal(err)
	}
	if !minted.Complete() {
		t.Fatal("post-admission mechanical capability should remain representable")
	}
}
