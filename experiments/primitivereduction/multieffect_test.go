package primitivereduction

import "testing"

func threeDomainEffectPlan(t *testing.T) EffectPlan {
	t.Helper()

	github := githubMergeProposal()
	kube := kubernetesDeleteProposal()
	postgres := postgresMigrationProposal()

	githubExec := Identity{ID: "executor:github", Kind: "process"}
	kubeExec := Identity{ID: "executor:kube", Kind: "process"}
	postgresExec := Identity{ID: "executor:postgres", Kind: "process"}

	githubCustody, err := PrepareEffectCustody(github, githubExec, "001")
	if err != nil {
		t.Fatalf("prepare github custody: %v", err)
	}
	kubeCustody, err := PrepareEffectCustody(kube, kubeExec, "001")
	if err != nil {
		t.Fatalf("prepare kube custody: %v", err)
	}
	postgresCustody, err := PrepareEffectCustody(postgres, postgresExec, "001")
	if err != nil {
		t.Fatalf("prepare postgres custody: %v", err)
	}

	githubID, err := EffectIdentity(github)
	if err != nil {
		t.Fatal(err)
	}
	kubeID, err := EffectIdentity(kube)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := BuildEffectPlan([]EffectPlanStep{
		{
			Proposal: github,
			Executor: githubExec,
			Custody:  githubCustody,
		},
		{
			Proposal:  kube,
			Executor:  kubeExec,
			Custody:   kubeCustody,
			DependsOn: []string{githubID},
		},
		{
			Proposal:  postgres,
			Executor:  postgresExec,
			Custody:   postgresCustody,
			DependsOn: []string{kubeID},
		},
	}, "001")
	if err != nil {
		t.Fatalf("build three-domain plan: %v", err)
	}
	return plan
}

func closedCustody(t *testing.T, custody StateRef) StateRef {
	t.Helper()
	crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		t.Fatalf("advance custody to crossing: %v", err)
	}
	closed, err := AdvanceEffectCustody(crossing.To, CustodyClosed)
	if err != nil {
		t.Fatalf("advance custody to closed: %v", err)
	}
	return closed.To
}

func unknownCustody(t *testing.T, custody StateRef) StateRef {
	t.Helper()
	crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		t.Fatalf("advance custody to crossing: %v", err)
	}
	unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
	if err != nil {
		t.Fatalf("advance custody to unknown: %v", err)
	}
	return unknown.To
}

func TestCausalMultiEffectPlanAcrossThreeDomains(t *testing.T) {
	plan := threeDomainEffectPlan(t)

	if got := PlanDisposition(plan); got != PlanOpen {
		t.Fatalf("fresh plan disposition = %s, want OPEN", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 0); got.Decision != DecisionAllow {
		t.Fatalf("first effect should be admitted: %+v", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 1); got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("second effect must wait for first closure: %+v", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 2); got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("third effect must wait for predecessors: %+v", got)
	}

	firstClosed := closedCustody(t, plan.Steps[0].Custody)
	var err error
	plan, err = ReplaceStepCustody(plan, 0, firstClosed)
	if err != nil {
		t.Fatal(err)
	}

	if got := PlanDisposition(plan); got != PlanPartial {
		t.Fatalf("one closed + remaining reserved = %s, want PARTIAL", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 0); got.Decision != DecisionDeny {
		t.Fatalf("closed first effect must not be replayable: %+v", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 1); got.Decision != DecisionAllow {
		t.Fatalf("second effect should be admitted after first closure: %+v", got)
	}

	secondUnknown := unknownCustody(t, plan.Steps[1].Custody)
	plan, err = ReplaceStepCustody(plan, 1, secondUnknown)
	if err != nil {
		t.Fatal(err)
	}

	if got := PlanDisposition(plan); got != PlanUnknown {
		t.Fatalf("ambiguous second effect must make whole plan UNKNOWN, got %s", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 2); got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("third effect must not cross while predecessor is UNKNOWN: %+v", got)
	}

	effectID, err := EffectIdentity(plan.Steps[1].Proposal)
	if err != nil {
		t.Fatal(err)
	}
	providerObservation := Evidence{
		ID:          effectID,
		Type:        "provider-effect-observation",
		StateDigest: secondUnknown.Digest,
		Valid:       true,
	}
	if got := ReconcileExternalEffect(secondUnknown, providerObservation); got != ClosureClosed {
		t.Fatalf("exact provider evidence should establish closure, got %s", got)
	}
	secondClosedTransition, err := AdvanceEffectCustody(secondUnknown, CustodyClosed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = ReplaceStepCustody(plan, 1, secondClosedTransition.To)
	if err != nil {
		t.Fatal(err)
	}

	if got := PlanDisposition(plan); got != PlanPartial {
		t.Fatalf("two closed + final reserved = %s, want PARTIAL", got)
	}
	if got := EvaluatePlannedEffectBoundary(plan, 2); got.Decision != DecisionAllow {
		t.Fatalf("third effect should resume only after predecessor closure: %+v", got)
	}

	thirdClosed := closedCustody(t, plan.Steps[2].Custody)
	plan, err = ReplaceStepCustody(plan, 2, thirdClosed)
	if err != nil {
		t.Fatal(err)
	}
	if got := PlanDisposition(plan); got != PlanClosed {
		t.Fatalf("all effects closed = %s, want CLOSED", got)
	}
}

func TestPartialCompletionSurvivesRestartWithoutReplayingClosedEffect(t *testing.T) {
	plan := threeDomainEffectPlan(t)

	firstClosed := closedCustody(t, plan.Steps[0].Custody)
	recovered, err := ReplaceStepCustody(plan, 0, firstClosed)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a new process reconstructing from durable plan State/Evidence and
	// durable custody State, with no in-memory "already sent" flag.
	restarted := EffectPlan{
		State:    recovered.State,
		Evidence: recovered.Evidence,
		Steps:    append([]EffectPlanStep(nil), recovered.Steps...),
	}

	if got := EvaluatePlannedEffectBoundary(restarted, 0); got.Decision != DecisionDeny {
		t.Fatalf("restart must not replay already-closed first effect: %+v", got)
	}
	if got := EvaluatePlannedEffectBoundary(restarted, 1); got.Decision != DecisionAllow {
		t.Fatalf("restart should allow next safely-reserved effect: %+v", got)
	}
}

func TestPlanDependencyRemovalFailsAgainstBoundEvidence(t *testing.T) {
	plan := threeDomainEffectPlan(t)

	secondID, err := EffectIdentity(plan.Steps[1].Proposal)
	if err != nil {
		t.Fatal(err)
	}
	key := planFactStepPrefix + secondID + planFactDependsSuffix

	t.Run("tamper-without-rehash", func(t *testing.T) {
		attacked := plan
		attacked.State = copyState(plan.State)
		attacked.State.Facts[key] = ""

		got := EvaluatePlannedEffectBoundary(attacked, 1)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("tampered plan topology must invalidate plan binding: %+v", got)
		}
	})

	t.Run("rehash-with-stale-attestation", func(t *testing.T) {
		attacked := plan
		attacked.State = copyState(plan.State)
		attacked.State.Facts[key] = ""
		attacked.State.Digest = planDigest(attacked.State)

		got := EvaluatePlannedEffectBoundary(attacked, 1)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("weakened topology with stale evidence must fail closed: %+v", got)
		}
	})
}

func TestForeignCustodyCannotBeInsertedIntoAnotherPlanStep(t *testing.T) {
	plan := threeDomainEffectPlan(t)

	if _, err := ReplaceStepCustody(plan, 1, plan.Steps[0].Custody); err == nil {
		t.Fatal("foreign custody was accepted for a different logical effect")
	}
}

func TestUnknownMiddleEffectBlocksLaterEffectsEvenWhenEarlierEffectClosed(t *testing.T) {
	plan := threeDomainEffectPlan(t)

	firstClosed := closedCustody(t, plan.Steps[0].Custody)
	var err error
	plan, err = ReplaceStepCustody(plan, 0, firstClosed)
	if err != nil {
		t.Fatal(err)
	}
	secondUnknown := unknownCustody(t, plan.Steps[1].Custody)
	plan, err = ReplaceStepCustody(plan, 1, secondUnknown)
	if err != nil {
		t.Fatal(err)
	}

	if got := EvaluatePlannedEffectBoundary(plan, 2); got.Decision != DecisionDeny {
		t.Fatalf("later effect crossed ambiguous causal predecessor: %+v", got)
	}
	if got := PlanDisposition(plan); got != PlanUnknown {
		t.Fatalf("partial completion plus ambiguity must remain UNKNOWN, got %s", got)
	}
}

func TestThreeDomainPlanStillUsesOnlySixCandidatePrimitives(t *testing.T) {
	_ = threeDomainEffectPlan(t)
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("multi-effect composition expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{
		"plan",
		"effect_step",
		"causality",
		"partial_completion",
		"effect_custody",
		"effect_identity",
	} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain derived composition in v3", forbidden)
			}
		}
	}
}
