package primitivereduction

import (
	"reflect"
	"testing"
)

func evidenceDecomposedFixture(fixture domainFixture) EvidenceDecomposedProposal {
	return DecomposeEvidence(ReduceCapability(fixture.new()))
}

func TestEvidenceDecomposedCandidatePrimitivesReplaceEvidenceWithAttestation(t *testing.T) {
	got := EvidenceDecomposedCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveConstraint,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v9 primitives = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveEvidence {
			t.Fatal("opaque Evidence survived as a v9 semantic primitive")
		}
		if primitive == PrimitiveCapability {
			t.Fatal("Capability reappeared after v8 elimination")
		}
	}
}

func TestThreeDomainsAdmitWithoutEvidenceField(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := evidenceDecomposedFixture(fixture)
			if got := EvaluateEvidenceDecomposedAdmission(proposal); got.Decision != DecisionAllow {
				t.Fatalf("v9 admission = %+v", got)
			}
		})
	}
}

func TestEvidenceDecomposedProposalHasNoEvidenceOrCapabilityField(t *testing.T) {
	typ := reflect.TypeOf(EvidenceDecomposedProposal{})
	if _, ok := typ.FieldByName("Evidence"); ok {
		t.Fatal("EvidenceDecomposedProposal still contains Evidence")
	}
	if _, ok := typ.FieldByName("Capability"); ok {
		t.Fatal("EvidenceDecomposedProposal reintroduced Capability")
	}
}

func TestClaimsWithoutProvenanceFailClosed(t *testing.T) {
	proposal := evidenceDecomposedFixture(fixtures()[0])
	proposal.Attestations = nil

	got := EvaluateEvidenceDecomposedAdmission(proposal)
	if got.Decision != DecisionDeny || got.Reason != ReasonMissingEvidence {
		t.Fatalf("unattested claims admitted: %+v", got)
	}
}

func TestEveryConstraintRequiresAttestation(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := evidenceDecomposedFixture(fixture)
			if len(proposal.Attestations) < 2 {
				t.Fatalf("fixture has too few attestations for ablation: %d", len(proposal.Attestations))
			}
			proposal.Attestations = append([]Attestation(nil), proposal.Attestations[1:]...)

			got := EvaluateEvidenceDecomposedAdmission(proposal)
			if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
				t.Fatalf("constraint without provenance admitted: %+v", got)
			}
		})
	}
}

func TestClaimMutationInvalidatesExistingAttestation(t *testing.T) {
	proposal := evidenceDecomposedFixture(fixtures()[0])
	if len(proposal.Constraints) == 0 || len(proposal.Constraints[0].Predicates) == 0 {
		t.Fatal("fixture has no mutable constraint")
	}

	proposal.Constraints[0].Predicates[0].Value = "attacker-substitution"

	got := EvaluateEvidenceDecomposedAdmission(proposal)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("mutated claim retained old provenance: %+v", got)
	}
}

func TestIssuerSubstitutionInvalidatesAttestationBinding(t *testing.T) {
	proposal := evidenceDecomposedFixture(fixtures()[1])
	proposal.Attestations[0].Issuer = Identity{
		ID:   "attestor:attacker",
		Kind: "attestor",
	}

	got := EvaluateEvidenceDecomposedAdmission(proposal)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("issuer substitution admitted: %+v", got)
	}
}

func TestAttestationIsBoundToExactProposalRelation(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base := evidenceDecomposedFixture(fixture)

			t.Run("subject", func(t *testing.T) {
				attacked := base
				attacked.Subject = Identity{ID: "attacker:subject", Kind: base.Subject.Kind}
				got := EvaluateEvidenceDecomposedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("subject substitution admitted: %+v", got)
				}
			})

			t.Run("operation", func(t *testing.T) {
				attacked := base
				attacked.Transition.Operation = "attacker-operation"
				got := EvaluateEvidenceDecomposedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("operation substitution admitted: %+v", got)
				}
			})

			t.Run("state", func(t *testing.T) {
				attacked := base
				attacked.Current.Digest = "sha256:advanced-state"
				attacked.Transition.From.Digest = attacked.Current.Digest
				got := EvaluateEvidenceDecomposedAdmission(attacked)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("state substitution retained stale attestations: %+v", got)
				}
			})
		})
	}
}

func TestInvalidOrForeignAttestationFailsClosed(t *testing.T) {
	base := evidenceDecomposedFixture(fixtures()[2])

	t.Run("invalid", func(t *testing.T) {
		attacked := base
		attacked.Attestations = append([]Attestation(nil), base.Attestations...)
		attacked.Attestations[0].Valid = false
		got := EvaluateEvidenceDecomposedAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("invalid attestation admitted: %+v", got)
		}
	})

	t.Run("foreign-constraint", func(t *testing.T) {
		attacked := base
		attacked.Attestations = append([]Attestation(nil), base.Attestations...)
		attacked.Attestations[0].ConstraintID = "constraint:foreign"
		got := EvaluateEvidenceDecomposedAdmission(attacked)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("foreign attestation admitted: %+v", got)
		}
	})
}

func TestAttestationCannotBeReplayedAcrossDomains(t *testing.T) {
	github := evidenceDecomposedFixture(fixtures()[0])
	kube := evidenceDecomposedFixture(fixtures()[1])

	kube.Attestations[0] = github.Attestations[0]
	got := EvaluateEvidenceDecomposedAdmission(kube)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("cross-domain attestation replay admitted: %+v", got)
	}
}

func TestEvidenceCanBeMaterializedAfterAttestationValidation(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := evidenceDecomposedFixture(fixture)
			if got := EvaluateEvidenceDecomposedAdmission(proposal); got.Decision != DecisionAllow {
				t.Fatalf("proposal not admitted before materialization: %+v", got)
			}

			evidence, err := MaterializeEvidence(proposal, proposal.Attestations[0])
			if err != nil {
				t.Fatalf("materialize Evidence: %v", err)
			}
			if !evidence.Complete() || !evidence.Valid || evidence.StateDigest != proposal.Current.Digest {
				t.Fatalf("derived Evidence is incomplete: %+v", evidence)
			}
		})
	}
}

func TestMaterializedEvidenceRejectsStaleAttestation(t *testing.T) {
	proposal := evidenceDecomposedFixture(fixtures()[0])
	attestation := proposal.Attestations[0]
	attestation.BindingDigest = "sha256:stale"

	if _, err := MaterializeEvidence(proposal, attestation); err == nil {
		t.Fatal("materialized Evidence from stale attestation")
	}
}

func TestV9AblationShowsProvenanceStillNecessary(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base := evidenceDecomposedFixture(fixture)

			cases := []struct {
				name   Primitive
				mutate func(*EvidenceDecomposedProposal)
				reason Reason
			}{
				{
					name: PrimitiveIdentity,
					mutate: func(p *EvidenceDecomposedProposal) { p.Subject = Identity{} },
					reason: ReasonMissingIdentity,
				},
				{
					name: PrimitiveState,
					mutate: func(p *EvidenceDecomposedProposal) { p.Current = StateRef{} },
					reason: ReasonMissingState,
				},
				{
					name: PrimitiveConstraint,
					mutate: func(p *EvidenceDecomposedProposal) { p.Constraints = nil },
					reason: ReasonMissingConstraint,
				},
				{
					name: PrimitiveAttestation,
					mutate: func(p *EvidenceDecomposedProposal) { p.Attestations = nil },
					reason: ReasonMissingEvidence,
				},
				{
					name: PrimitiveTransition,
					mutate: func(p *EvidenceDecomposedProposal) { p.Transition = Transition{} },
					reason: ReasonMissingTransition,
				},
			}

			for _, tc := range cases {
				t.Run(string(tc.name), func(t *testing.T) {
					attacked := base
					tc.mutate(&attacked)
					got := EvaluateEvidenceDecomposedAdmission(attacked)
					if got.Decision != DecisionDeny || got.Reason != tc.reason {
						t.Fatalf("ablation %s = %+v, want DENY/%s", tc.name, got, tc.reason)
					}
				})
			}
		})
	}
}
