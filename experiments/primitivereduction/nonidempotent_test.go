package primitivereduction

import "testing"

func TestNonIdempotentExternalEffectDoesNotRequireBusinessStateMutation(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			executor := Identity{ID: "executor:" + fixture.name, Kind: "process"}

			custody, err := PrepareEffectCustody(proposal, executor, "001")
			if err != nil {
				t.Fatalf("prepare custody: %v", err)
			}
			if got := EvaluateNonIdempotentBoundary(proposal, executor, custody); got.Decision != DecisionAllow {
				t.Fatalf("reserved exact custody should admit boundary: %+v", got)
			}

			crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
			if err != nil {
				t.Fatalf("advance to crossing: %v", err)
			}

			// The provider may accept the non-idempotent effect here while the
			// response is lost. The business target remains exactly unchanged.
			unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
			if err != nil {
				t.Fatalf("advance to unknown: %v", err)
			}

			if got := EvaluateAdmission(proposal); got.Decision != DecisionAllow {
				t.Fatalf("ordinary target-state admission should still look unchanged in this attack, got %+v", got)
			}

			// The extra custody State instance, not the business target, blocks
			// duplicate delivery at the actual effect boundary.
			if got := EvaluateNonIdempotentBoundary(proposal, executor, unknown.To); got.Decision != DecisionDeny {
				t.Fatalf("UNKNOWN custody must block duplicate non-idempotent effect, got %+v", got)
			}

			// Lack of external evidence must not manufacture closure.
			if got := ReconcileExternalEffect(unknown.To, Evidence{}); got != ClosureUnknown {
				t.Fatalf("missing external evidence must remain UNKNOWN, got %s", got)
			}

			effectID, err := EffectIdentity(proposal)
			if err != nil {
				t.Fatalf("derive effect identity: %v", err)
			}
			providerObservation := Evidence{
				ID:          effectID,
				Type:        "provider-effect-observation",
				StateDigest: unknown.To.Digest,
				Valid:       true,
			}
			if got := ReconcileExternalEffect(unknown.To, providerObservation); got != ClosureClosed {
				t.Fatalf("exact external observation should close custody, got %s", got)
			}
		})
	}
}

func TestUnknownCustodyNeverBecomesReplayPermissionByRetry(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			executor := Identity{ID: "executor:" + fixture.name, Kind: "process"}
			custody, err := PrepareEffectCustody(proposal, executor, "001")
			if err != nil {
				t.Fatal(err)
			}
			crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
			if err != nil {
				t.Fatal(err)
			}
			unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := AdvanceEffectCustody(unknown.To, CustodyReserved); err == nil {
				t.Fatal("UNKNOWN custody must not transition back to RESERVED")
			}
			if got := EvaluateNonIdempotentBoundary(proposal, executor, unknown.To); got.Decision != DecisionDeny {
				t.Fatalf("retry must not convert uncertainty into replay permission: %+v", got)
			}
		})
	}
}

func TestExecutorTakeoverCannotStealReservedCustody(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			first := Identity{ID: "executor:first", Kind: "process"}
			takeover := Identity{ID: "executor:takeover", Kind: "process"}

			custody, err := PrepareEffectCustody(proposal, first, "001")
			if err != nil {
				t.Fatal(err)
			}
			if got := EvaluateNonIdempotentBoundary(proposal, first, custody); got.Decision != DecisionAllow {
				t.Fatalf("original owner should be admitted: %+v", got)
			}
			if got := EvaluateNonIdempotentBoundary(proposal, takeover, custody); got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
				t.Fatalf("takeover must not silently inherit custody: %+v", got)
			}
		})
	}
}

func TestExternalObservationMustBindExactLogicalEffect(t *testing.T) {
	proposal := githubMergeProposal()
	executor := Identity{ID: "executor:github", Kind: "process"}
	custody, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}
	crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
	if err != nil {
		t.Fatal(err)
	}

	wrongEffect := Evidence{
		ID:          "different-effect-id",
		Type:        "provider-effect-observation",
		StateDigest: unknown.To.Digest,
		Valid:       true,
	}
	if got := ReconcileExternalEffect(unknown.To, wrongEffect); got != ClosureUnknown {
		t.Fatalf("evidence for another logical effect must not close this custody, got %s", got)
	}

	effectID, err := EffectIdentity(proposal)
	if err != nil {
		t.Fatal(err)
	}
	staleState := Evidence{
		ID:          effectID,
		Type:        "provider-effect-observation",
		StateDigest: custody.Digest,
		Valid:       true,
	}
	if got := ReconcileExternalEffect(unknown.To, staleState); got != ClosureUnknown {
		t.Fatalf("stale custody-bound evidence must not close current UNKNOWN state, got %s", got)
	}
}

func TestCustodyIsAnotherStateInstanceNotASeventhPrimitive(t *testing.T) {
	proposal := postgresMigrationProposal()
	executor := Identity{ID: "executor:postgres", Kind: "process"}
	custody, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	if custody.Namespace != custodyNamespace || custody.ObjectID == "" || custody.Digest == "" {
		t.Fatalf("custody must be represented as ordinary StateRef: %+v", custody)
	}
	if got := CandidatePrimitives(); len(got) != 6 {
		t.Fatalf("non-idempotent experiment unexpectedly expanded primitive basis: %v", got)
	}
}

func TestCustodyTransitionIsOrdinaryTransition(t *testing.T) {
	proposal := kubernetesDeleteProposal()
	executor := Identity{ID: "executor:kube", Kind: "process"}
	custody, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	transition, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		t.Fatal(err)
	}
	if !transition.Complete() {
		t.Fatalf("custody phase change must be represented as ordinary Transition: %+v", transition)
	}
	if transition.From.TargetKey() != transition.To.TargetKey() {
		t.Fatal("custody transition changed logical custody object")
	}
	if transition.From.Digest == transition.To.Digest {
		t.Fatal("custody transition must change state digest")
	}
}
