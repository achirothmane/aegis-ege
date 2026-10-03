package primitivereduction

import (
	"reflect"
	"testing"
)

func constraintFreeFixture(t *testing.T, fixture domainFixture) (ConstraintFreeProposal, StateRef, Identity) {
	t.Helper()

	source := DecomposeEvidence(ReduceCapability(fixture.new()))
	policyIssuer := Identity{ID: "policy:" + fixture.name, Kind: "policy"}

	trusted := make([]Identity, 0, len(source.Attestations)+1)
	for _, attestation := range source.Attestations {
		trusted = append(trusted, attestation.Issuer)
	}
	trusted = append(trusted, policyIssuer)

	trust := BuildProvenanceTrustState("trust-v11", trusted)
	out, err := BuildAdmissionAttestation(source, trust, policyIssuer)
	if err != nil {
		t.Fatalf("build constraint-free fixture: %v", err)
	}
	return out, trust, policyIssuer
}

func TestConstraintFreeCandidateDropsConstraint(t *testing.T) {
	got := ConstraintFreeCandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v11 primitives = %v, want %v", got, want)
	}
	for _, primitive := range got {
		if primitive == PrimitiveConstraint ||
			primitive == PrimitiveCapability ||
			primitive == PrimitiveEvidence {
			t.Fatalf("eliminated primitive reappeared: %q", primitive)
		}
	}
}

func TestThreeDomainsAdmitWithoutConstraintField(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal, trust, _ := constraintFreeFixture(t, fixture)
			if got := EvaluateConstraintFreeAdmission(proposal, trust); got.Decision != DecisionAllow {
				t.Fatalf("constraint-free admission = %+v", got)
			}
		})
	}
}

func TestConstraintFreeProposalContainsNoConstraintEvidenceOrCapability(t *testing.T) {
	typ := reflect.TypeOf(ConstraintFreeProposal{})
	for _, forbidden := range []string{
		"Constraint",
		"Constraints",
		"Evidence",
		"Capability",
	} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("v11 smuggled eliminated semantic input through %q", forbidden)
		}
	}
}

func TestPolicyViolationCannotMintAdmissionAttestation(t *testing.T) {
	source := DecomposeEvidence(ReduceCapability(githubMergeProposal()))
	if len(source.Constraints) == 0 || len(source.Constraints[0].Predicates) == 0 {
		t.Fatal("fixture has no policy predicate")
	}

	// Change one rule into a false rule and recompute its provenance binding so
	// the failure is the policy predicate itself, not stale attestation bytes.
	source.Constraints[0].Predicates[0].Value = "__definitely_not_actual__"
	for i := range source.Attestations {
		if source.Attestations[i].ConstraintID == source.Constraints[0].ID {
			source.Attestations[i].BindingDigest = attestationBindingDigest(
				source,
				source.Constraints[0],
				source.Attestations[i].Issuer,
			)
		}
	}

	policyIssuer := Identity{ID: "policy:github", Kind: "policy"}
	trusted := []Identity{policyIssuer}
	for _, attestation := range source.Attestations {
		trusted = append(trusted, attestation.Issuer)
	}
	trust := BuildProvenanceTrustState("trust-v11", trusted)

	if got := EvaluateTrustBoundAdmission(source, trust); got.Decision != DecisionDeny ||
		got.Reason != ReasonConstraintViolated {
		t.Fatalf("source policy violation did not fail as expected: %+v", got)
	}
	if _, err := BuildAdmissionAttestation(source, trust, policyIssuer); err == nil {
		t.Fatal("minted compact admission from a policy-violating source relation")
	}
}

func TestConstraintFreeBindingRejectsProposalSubstitution(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base, trust, _ := constraintFreeFixture(t, fixture)

			t.Run("subject", func(t *testing.T) {
				attacked := base
				attacked.Subject.ID = "subject:substituted"
				got := EvaluateConstraintFreeAdmission(attacked, trust)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("subject substitution admitted: %+v", got)
				}
			})

			t.Run("operation", func(t *testing.T) {
				attacked := base
				attacked.Transition.Operation = "operation:substituted"
				got := EvaluateConstraintFreeAdmission(attacked, trust)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("operation substitution admitted: %+v", got)
				}
			})

			t.Run("state-version", func(t *testing.T) {
				attacked := base
				attacked.Current.Version = attacked.Current.Version + ":next"
				attacked.Transition.From.Version = attacked.Current.Version
				got := EvaluateConstraintFreeAdmission(attacked, trust)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("state revision substitution admitted: %+v", got)
				}
			})

			t.Run("target", func(t *testing.T) {
				attacked := base
				attacked.Transition.To.ObjectID = "target:substituted"
				got := EvaluateConstraintFreeAdmission(attacked, trust)
				if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
					t.Fatalf("target substitution admitted: %+v", got)
				}
			})
		})
	}
}

func TestUntrustedPolicyIssuerCannotAuthorize(t *testing.T) {
	proposal, trust, _ := constraintFreeFixture(t, fixtures()[0])

	attacker := Identity{ID: "policy:untrusted", Kind: "policy"}
	proposal.Attestation.Issuer = attacker
	proposal.Attestation.BindingDigest = admissionDecisionBindingDigest(
		proposal,
		attacker,
		proposal.Attestation.Decision,
	)

	got := EvaluateConstraintFreeAdmission(proposal, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("untrusted issuer admitted: %+v", got)
	}
}

func TestPolicyIssuerRevocationFailsClosed(t *testing.T) {
	proposal, _, policyIssuer := constraintFreeFixture(t, fixtures()[1])

	revokedTrust := BuildProvenanceTrustState(
		"trust-v12",
		[]Identity{{ID: "another:issuer", Kind: "policy"}},
	)
	got := EvaluateConstraintFreeAdmission(proposal, revokedTrust)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("revoked policy issuer remained authoritative: %+v", got)
	}

	_ = policyIssuer
}

func TestAttestedDenyCannotGrantAuthority(t *testing.T) {
	proposal, trust, _ := constraintFreeFixture(t, fixtures()[2])

	proposal.Attestation.Decision = DecisionDeny
	proposal.Attestation.BindingDigest = admissionDecisionBindingDigest(
		proposal,
		proposal.Attestation.Issuer,
		proposal.Attestation.Decision,
	)

	got := EvaluateConstraintFreeAdmission(proposal, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("attested DENY became executable authority: %+v", got)
	}
}

func TestFourPrimitiveAblationFailsClosed(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base, trust, _ := constraintFreeFixture(t, fixture)

			cases := []struct {
				name   Primitive
				mutate func(*ConstraintFreeProposal)
				reason Reason
			}{
				{
					name: PrimitiveIdentity,
					mutate: func(p *ConstraintFreeProposal) { p.Subject = Identity{} },
					reason: ReasonMissingIdentity,
				},
				{
					name: PrimitiveState,
					mutate: func(p *ConstraintFreeProposal) { p.Current = StateRef{} },
					reason: ReasonMissingState,
				},
				{
					name: PrimitiveAttestation,
					mutate: func(p *ConstraintFreeProposal) { p.Attestation = AdmissionAttestation{} },
					reason: ReasonMissingEvidence,
				},
				{
					name: PrimitiveTransition,
					mutate: func(p *ConstraintFreeProposal) { p.Transition = Transition{} },
					reason: ReasonMissingTransition,
				},
			}

			for _, tc := range cases {
				t.Run(string(tc.name), func(t *testing.T) {
					attacked := base
					tc.mutate(&attacked)
					got := EvaluateConstraintFreeAdmission(attacked, trust)
					if got.Decision != DecisionDeny || got.Reason != tc.reason {
						t.Fatalf("ablation %s = %+v, want DENY/%s", tc.name, got, tc.reason)
					}
				})
			}
		})
	}
}
