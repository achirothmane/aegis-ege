package primitivereduction

import "testing"

func TestDuplicateWorkersSameIdentityOnlyOneCrossesBoundary(t *testing.T) {
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
				t.Fatalf("worker A claim rejected: %+v", resultA)
			}
			claimB, resultB := ClaimEffectBoundary(proposal, executor, reserved)
			if resultB.Decision != DecisionAllow {
				t.Fatalf("worker B should derive same claim from same stale snapshot: %+v", resultB)
			}

			current, err := ApplyStateTransitionCAS(reserved, claimA)
			if err != nil {
				t.Fatalf("first claim CAS failed: %v", err)
			}
			if current.Facts[factCustodyPhase] != CustodyCrossing {
				t.Fatalf("first claim did not enter CROSSING: %+v", current)
			}

			if _, err := ApplyStateTransitionCAS(current, claimB); err == nil {
				t.Fatal("second concurrent claim committed from stale RESERVED state")
			}
		})
	}
}

func TestTakeoverIdentityCannotClaimAnotherOwnersReservation(t *testing.T) {
	proposal := githubMergeProposal()
	owner := Identity{ID: "executor:owner", Kind: "process"}
	takeover := Identity{ID: "executor:takeover", Kind: "process"}

	reserved, err := PrepareEffectCustody(proposal, owner, "001")
	if err != nil {
		t.Fatal(err)
	}
	if _, got := ClaimEffectBoundary(proposal, takeover, reserved); got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
		t.Fatalf("takeover silently inherited claimable custody: %+v", got)
	}
}

func TestIndependentSiblingEffectsMayCrossWithoutInventedOrdering(t *testing.T) {
	first := githubMergeProposal()
	second := postgresMigrationProposal()
	firstExec := Identity{ID: "executor:first", Kind: "process"}
	secondExec := Identity{ID: "executor:second", Kind: "process"}

	firstReserved, err := PrepareEffectCustody(first, firstExec, "001")
	if err != nil {
		t.Fatal(err)
	}
	secondReserved, err := PrepareEffectCustody(second, secondExec, "001")
	if err != nil {
		t.Fatal(err)
	}

	firstClaim, got := ClaimEffectBoundary(first, firstExec, firstReserved)
	if got.Decision != DecisionAllow {
		t.Fatalf("first sibling claim rejected: %+v", got)
	}
	secondClaim, got := ClaimEffectBoundary(second, secondExec, secondReserved)
	if got.Decision != DecisionAllow {
		t.Fatalf("second sibling claim rejected: %+v", got)
	}

	firstCrossing, err := ApplyStateTransitionCAS(firstReserved, firstClaim)
	if err != nil {
		t.Fatal(err)
	}
	secondCrossing, err := ApplyStateTransitionCAS(secondReserved, secondClaim)
	if err != nil {
		t.Fatal(err)
	}

	if firstCrossing.Facts[factCustodyPhase] != CustodyCrossing ||
		secondCrossing.Facts[factCustodyPhase] != CustodyCrossing {
		t.Fatal("independent siblings did not both reach CROSSING")
	}
}

func TestJoinRequiresEveryConcurrentPredecessorClosed(t *testing.T) {
	first := githubMergeProposal()
	second := postgresMigrationProposal()
	firstExec := Identity{ID: "executor:first", Kind: "process"}
	secondExec := Identity{ID: "executor:second", Kind: "process"}

	firstReserved, _ := PrepareEffectCustody(first, firstExec, "001")
	secondReserved, _ := PrepareEffectCustody(second, secondExec, "001")

	if got := EvaluateConcurrentJoin([]StateRef{firstReserved, secondReserved}); got != JoinBlocked {
		t.Fatalf("all reserved join = %s, want BLOCKED", got)
	}

	firstClosed := closedCustody(t, firstReserved)
	if got := EvaluateConcurrentJoin([]StateRef{firstClosed, secondReserved}); got != JoinBlocked {
		t.Fatalf("one closed + one reserved join = %s, want BLOCKED", got)
	}

	secondUnknown := unknownCustody(t, secondReserved)
	if got := EvaluateConcurrentJoin([]StateRef{firstClosed, secondUnknown}); got != JoinUnknown {
		t.Fatalf("closed + unknown join = %s, want UNKNOWN", got)
	}

	secondClosedTransition, err := AdvanceEffectCustody(secondUnknown, CustodyClosed)
	if err != nil {
		t.Fatal(err)
	}
	if got := EvaluateConcurrentJoin([]StateRef{firstClosed, secondClosedTransition.To}); got != JoinReady {
		t.Fatalf("all closed join = %s, want READY", got)
	}
}

func TestConflictingExternalOrderingEvidenceRemainsUnknown(t *testing.T) {
	first := githubMergeProposal()
	second := postgresMigrationProposal()
	firstID, err := EffectIdentity(first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := EffectIdentity(second)
	if err != nil {
		t.Fatal(err)
	}

	aBeforeB := OrderingObservation{
		BeforeEffectID: firstID,
		AfterEffectID:  secondID,
		Evidence: Evidence{
			ID:          "observer-a",
			Type:        "external-ordering",
			StateDigest: "sha256:ordering-a",
			Valid:       true,
		},
	}
	bBeforeA := OrderingObservation{
		BeforeEffectID: secondID,
		AfterEffectID:  firstID,
		Evidence: Evidence{
			ID:          "observer-b",
			Type:        "external-ordering",
			StateDigest: "sha256:ordering-b",
			Valid:       true,
		},
	}

	if got := ReconcileOrdering([]OrderingObservation{aBeforeB}); got != ClosureClosed {
		t.Fatalf("single coherent ordering observation = %s, want CLOSED", got)
	}
	if got := ReconcileOrdering([]OrderingObservation{aBeforeB, bBeforeA}); got != ClosureUnknown {
		t.Fatalf("conflicting ordering observations = %s, want UNKNOWN", got)
	}
}

func TestStaleConcurrentClaimAfterCrashDoesNotReplay(t *testing.T) {
	proposal := kubernetesDeleteProposal()
	executor := Identity{ID: "executor:kube", Kind: "process"}
	reserved, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	staleClaim, result := ClaimEffectBoundary(proposal, executor, reserved)
	if result.Decision != DecisionAllow {
		t.Fatalf("derive pre-crash claim: %+v", result)
	}

	crossing, err := ApplyStateTransitionCAS(reserved, staleClaim)
	if err != nil {
		t.Fatal(err)
	}
	unknownTransition, err := AdvanceEffectCustody(crossing, CustodyUnknown)
	if err != nil {
		t.Fatal(err)
	}
	afterCrash := unknownTransition.To

	if _, err := ApplyStateTransitionCAS(afterCrash, staleClaim); err == nil {
		t.Fatal("stale pre-crash claim replayed after custody advanced to UNKNOWN")
	}
}

func TestConcurrencyExperimentStillUsesSixPrimitives(t *testing.T) {
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("concurrency experiment expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{
		"lock",
		"mutex",
		"cas",
		"ordering",
		"causality",
		"join",
		"fence",
	} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain derived mechanism in v4", forbidden)
			}
		}
	}
}
