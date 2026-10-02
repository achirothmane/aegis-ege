package primitivereduction

import "testing"

func testLinearizationWitness(custody StateRef, domain string) LinearizationWitness {
	return LinearizationWitness{
		DomainID:  domain,
		Epoch:     "epoch-1",
		Authority: Identity{ID: "authority:" + domain, Kind: "service"},
		Evidence: Evidence{
			ID:          "linearization-witness:" + domain,
			Type:        "shared-commit-domain-attestation",
			StateDigest: custody.Digest,
			Valid:       true,
		},
	}
}

func TestIndependentLocalCASAuthoritiesPermitSplitBrainCounterexample(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			executor := Identity{ID: "executor:shared", Kind: "process"}
			reserved, err := PrepareEffectCustody(proposal, executor, "001")
			if err != nil {
				t.Fatal(err)
			}

			claimA, resultA := ClaimEffectBoundary(proposal, executor, reserved)
			if resultA.Decision != DecisionAllow {
				t.Fatalf("derive claim A: %+v", resultA)
			}
			claimB, resultB := ClaimEffectBoundary(proposal, executor, reserved)
			if resultB.Decision != DecisionAllow {
				t.Fatalf("derive claim B: %+v", resultB)
			}

			// Two disconnected authorities each hold the same stale RESERVED
			// snapshot. Local CAS at each site succeeds independently.
			siteA := reserved
			siteB := reserved

			nextA, err := ApplyStateTransitionCAS(siteA, claimA)
			if err != nil {
				t.Fatalf("site A local CAS: %v", err)
			}
			nextB, err := ApplyStateTransitionCAS(siteB, claimB)
			if err != nil {
				t.Fatalf("site B local CAS: %v", err)
			}

			if nextA.Facts[factCustodyPhase] != CustodyCrossing ||
				nextB.Facts[factCustodyPhase] != CustodyCrossing {
				t.Fatal("counterexample failed: both independent sites should reach CROSSING locally")
			}
		})
	}
}

func TestDistributedPreconditionRequiresDeclaredSharedCommitDomain(t *testing.T) {
	proposal := githubMergeProposal()
	executor := Identity{ID: "executor:github", Kind: "process"}
	reserved, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing-domain", func(t *testing.T) {
		got := EvaluateDistributedPrecondition(reserved, "", LinearizationWitness{})
		if got.Decision != DecisionDeny || got.Reason != ReasonConstraintUnknown {
			t.Fatalf("missing linearization domain must fail closed: %+v", got)
		}
	})

	t.Run("wrong-domain", func(t *testing.T) {
		witness := testLinearizationWitness(reserved, "site-a")
		got := EvaluateDistributedPrecondition(reserved, "global-effect-commit", witness)
		if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
			t.Fatalf("local-only witness must not satisfy global domain: %+v", got)
		}
	})

	t.Run("stale-custody-binding", func(t *testing.T) {
		witness := testLinearizationWitness(reserved, "global-effect-commit")
		witness.Evidence.StateDigest = "sha256:stale"
		got := EvaluateDistributedPrecondition(reserved, "global-effect-commit", witness)
		if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
			t.Fatalf("stale witness must fail binding: %+v", got)
		}
	})

	t.Run("exact-shared-domain", func(t *testing.T) {
		witness := testLinearizationWitness(reserved, "global-effect-commit")
		got := EvaluateDistributedPrecondition(reserved, "global-effect-commit", witness)
		if got.Decision != DecisionAllow {
			t.Fatalf("exact shared-domain witness should satisfy the precondition: %+v", got)
		}
	})
}

func TestSharedLinearizationAuthorityAllowsOnlyOneConcurrentCommit(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			executor := Identity{ID: "executor:shared", Kind: "process"}
			reserved, err := PrepareEffectCustody(proposal, executor, "001")
			if err != nil {
				t.Fatal(err)
			}

			claimA, resultA := ClaimEffectBoundary(proposal, executor, reserved)
			if resultA.Decision != DecisionAllow {
				t.Fatalf("derive claim A: %+v", resultA)
			}
			claimB, resultB := ClaimEffectBoundary(proposal, executor, reserved)
			if resultB.Decision != DecisionAllow {
				t.Fatalf("derive claim B: %+v", resultB)
			}

			witness := testLinearizationWitness(reserved, "global-effect-commit")
			if got := EvaluateDistributedPrecondition(reserved, "global-effect-commit", witness); got.Decision != DecisionAllow {
				t.Fatalf("shared-domain precondition failed: %+v", got)
			}

			authority := &LinearizationAuthority{
				DomainID: "global-effect-commit",
				Current:  reserved,
			}
			if _, err := authority.Commit(witness, claimA); err != nil {
				t.Fatalf("first shared commit failed: %v", err)
			}
			if _, err := authority.Commit(witness, claimB); err == nil {
				t.Fatal("second stale concurrent claim committed through shared authority")
			}
		})
	}
}

func TestWitnessAloneDoesNotMagicallySerializeIndependentAuthorities(t *testing.T) {
	proposal := postgresMigrationProposal()
	executor := Identity{ID: "executor:postgres", Kind: "process"}
	reserved, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}
	claim, result := ClaimEffectBoundary(proposal, executor, reserved)
	if result.Decision != DecisionAllow {
		t.Fatalf("derive claim: %+v", result)
	}

	witness := testLinearizationWitness(reserved, "global-effect-commit")
	if got := EvaluateDistributedPrecondition(reserved, "global-effect-commit", witness); got.Decision != DecisionAllow {
		t.Fatalf("witness should satisfy admission precondition: %+v", got)
	}

	// This intentionally demonstrates the limit: if the substrate lies and
	// provides two disconnected "global" authorities, the witness itself
	// cannot enforce uniqueness.
	a := &LinearizationAuthority{DomainID: "global-effect-commit", Current: reserved}
	b := &LinearizationAuthority{DomainID: "global-effect-commit", Current: reserved}

	if _, err := a.Commit(witness, claim); err != nil {
		t.Fatalf("authority A commit: %v", err)
	}
	if _, err := b.Commit(witness, claim); err != nil {
		t.Fatalf("authority B commit: %v", err)
	}
}

func TestDistributedExperimentAddsNoConsensusPrimitive(t *testing.T) {
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("distributed experiment expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{
		"consensus",
		"linearization",
		"quorum",
		"leader",
		"epoch",
		"fencing_token",
	} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain an enforcement mechanism or derived relation in v5", forbidden)
			}
		}
	}
}
