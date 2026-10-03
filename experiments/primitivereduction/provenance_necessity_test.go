package primitivereduction

import (
	"reflect"
	"testing"
)

func TestFourPrimitiveReductionCannotDistinguishTrustedFromCopiedClaims(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			v9 := DecomposeEvidence(ReduceCapability(fixture.new()))

			trustedWorld := StripProvenance(v9)

			// In the forged world an untrusted actor copied the exact claim
			// content. Once provenance is stripped, the semantic input is
			// byte-for-byte the same relation.
			forgedWorld := StripProvenance(v9)

			if !reflect.DeepEqual(trustedWorld, forgedWorld) {
				t.Fatal("provenance-free worlds unexpectedly differ")
			}

			trustedDecision := EvaluateProvenanceFreeAdmission(trustedWorld)
			forgedDecision := EvaluateProvenanceFreeAdmission(forgedWorld)

			if trustedDecision.Decision != DecisionAllow ||
				forgedDecision.Decision != DecisionAllow {
				t.Fatalf("indistinguishability demonstration failed: trusted=%+v forged=%+v",
					trustedDecision, forgedDecision)
			}
		})
	}
}

func TestProvenanceFreeProposalActuallyContainsNoOriginSignal(t *testing.T) {
	typ := reflect.TypeOf(ProvenanceFreeProposal{})
	for _, forbidden := range []string{
		"Attestation",
		"Attestations",
		"Evidence",
		"Issuer",
		"Provenance",
	} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("four-primitive candidate smuggled provenance through field %q", forbidden)
		}
	}
}

func TestV9ValidBooleanCanHideIssuerTrustDecision(t *testing.T) {
	p := DecomposeEvidence(ReduceCapability(githubMergeProposal()))
	if len(p.Attestations) == 0 {
		t.Fatal("fixture has no attestation")
	}

	attacker := Identity{ID: "attestor:untrusted-self", Kind: "attestor"}
	p.Attestations[0].Issuer = attacker

	var claim SemanticConstraint
	found := false
	for _, c := range p.Constraints {
		if c.ID == p.Attestations[0].ConstraintID {
			claim = c
			found = true
			break
		}
	}
	if !found {
		t.Fatal("attested constraint not found")
	}

	// Recompute a perfectly self-consistent binding and mark its integrity as
	// verified. v9 itself has no explicit trusted-issuer state, so this passes.
	p.Attestations[0].BindingDigest = attestationBindingDigest(p, claim, attacker)
	p.Attestations[0].Valid = true

	got := EvaluateEvidenceDecomposedAdmission(p)
	if got.Decision != DecisionAllow {
		t.Fatalf("expected v9 hidden-trust counterexample to pass base evaluator, got %+v", got)
	}
}

func TestTrustBoundAdmissionRejectsUntrustedSelfAttestation(t *testing.T) {
	p := DecomposeEvidence(ReduceCapability(githubMergeProposal()))
	trustedIssuers := make([]Identity, 0, len(p.Attestations))
	for _, attestation := range p.Attestations {
		trustedIssuers = append(trustedIssuers, attestation.Issuer)
	}

	trust := BuildProvenanceTrustState("trust-v1", trustedIssuers)

	if got := EvaluateTrustBoundAdmission(p, trust); got.Decision != DecisionAllow {
		t.Fatalf("trusted original issuer rejected: %+v", got)
	}

	attacker := Identity{ID: "attestor:untrusted-self", Kind: "attestor"}
	p.Attestations[0].Issuer = attacker

	var claim SemanticConstraint
	for _, c := range p.Constraints {
		if c.ID == p.Attestations[0].ConstraintID {
			claim = c
			break
		}
	}
	p.Attestations[0].BindingDigest = attestationBindingDigest(p, claim, attacker)
	p.Attestations[0].Valid = true

	// The base v9 evaluator still accepts the self-consistent attestation.
	if got := EvaluateEvidenceDecomposedAdmission(p); got.Decision != DecisionAllow {
		t.Fatalf("base v9 evaluator unexpectedly rejected counterexample: %+v", got)
	}

	got := EvaluateTrustBoundAdmission(p, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("untrusted self-attestation not rejected by explicit trust state: %+v", got)
	}
}

func TestIssuerRevocationFailsClosedWithoutChangingClaim(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			p := DecomposeEvidence(ReduceCapability(fixture.new()))
			if len(p.Attestations) == 0 {
				t.Fatal("fixture has no attestation")
			}

			trustedIssuers := make([]Identity, 0, len(p.Attestations))
			for _, a := range p.Attestations {
				trustedIssuers = append(trustedIssuers, a.Issuer)
			}
			trustV1 := BuildProvenanceTrustState("trust-v1", trustedIssuers)
			if got := EvaluateTrustBoundAdmission(p, trustV1); got.Decision != DecisionAllow {
				t.Fatalf("trusted proposal rejected: %+v", got)
			}

			revoked := trustedIssuers[0]
			remaining := make([]Identity, 0, len(trustedIssuers)-1)
			for _, issuer := range trustedIssuers {
				if issuer != revoked {
					remaining = append(remaining, issuer)
				}
			}
			trustV2 := BuildProvenanceTrustState("trust-v2", remaining)

			got := EvaluateTrustBoundAdmission(p, trustV2)
			if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
				t.Fatalf("revoked issuer remained trusted: %+v", got)
			}
		})
	}
}

func TestTrustedIssuerStateCannotReplaceAttestationItself(t *testing.T) {
	p := DecomposeEvidence(ReduceCapability(kubernetesDeleteProposal()))
	trustedIssuers := make([]Identity, 0, len(p.Attestations))
	for _, a := range p.Attestations {
		trustedIssuers = append(trustedIssuers, a.Issuer)
	}
	trust := BuildProvenanceTrustState("trust-v1", trustedIssuers)

	p.Attestations = nil
	got := EvaluateTrustBoundAdmission(p, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonMissingEvidence {
		t.Fatalf("trust state alone replaced provenance binding: %+v", got)
	}
}

func TestTrustStateReusesStatePrimitiveRatherThanAddingSixth(t *testing.T) {
	trust := BuildProvenanceTrustState(
		"trust-v1",
		[]Identity{{ID: "attestor:test", Kind: "attestor"}},
	)
	if !trust.Complete() || trust.Namespace != provenanceTrustNamespace {
		t.Fatalf("trust state is not a valid StateRef: %+v", trust)
	}

	got := EvidenceDecomposedCandidatePrimitives()
	if len(got) != 5 {
		t.Fatalf("v10 unexpectedly changed candidate count: %v", got)
	}
	foundAttestation := false
	for _, primitive := range got {
		if primitive == PrimitiveAttestation {
			foundAttestation = true
		}
		if primitive == "trust" || primitive == "trust_root" || primitive == "verification" {
			t.Fatalf("trust mechanics incorrectly promoted to semantic primitive: %q", primitive)
		}
	}
	if !foundAttestation {
		t.Fatal("v10 incorrectly eliminated provenance/attestation")
	}
}

func TestFourPrimitiveCandidateIsFalsifiedNotPromoted(t *testing.T) {
	got := ProvenanceFreeCandidatePrimitives()
	if len(got) != 4 {
		t.Fatalf("expected four-primitive falsification candidate, got %v", got)
	}
	for _, primitive := range got {
		if primitive == PrimitiveAttestation {
			t.Fatal("provenance-free candidate still contains attestation")
		}
	}
}
