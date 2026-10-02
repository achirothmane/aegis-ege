package primitivereduction

import "testing"

func compensationProposalFor(original Proposal) Proposal {
	current := original.Transition.To
	current.Facts = make(map[string]string, len(original.Current.Facts)+1)
	for key, value := range original.Current.Facts {
		current.Facts[key] = value
	}
	current.Facts["compensation.allowed"] = "true"

	operation := "compensate:" + original.Transition.Operation
	subject := Identity{ID: "service:compensator", Kind: "service"}

	return Proposal{
		Subject: subject,
		Current: current,
		Capability: Capability{
			Name:      operation,
			SubjectID: subject.ID,
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "compensation-authorized",
				Predicates: []Predicate{
					{Fact: "compensation.allowed", Op: OpEqual, Value: "true"},
				},
				EvidenceIDs: []string{"compensation-authority"},
			},
		},
		Evidence: []Evidence{
			{
				ID:          "compensation-authority",
				Type:        "compensation-authority-attestation",
				StateDigest: current.Digest,
				Valid:       true,
			},
		},
		Transition: Transition{
			Operation: operation,
			From:      current,
			To: StateRef{
				Namespace: current.Namespace,
				ObjectID:  current.ObjectID,
				Version:   "compensated:" + current.Version,
				Digest:    current.Digest + ":compensated",
			},
		},
	}
}

func closedOriginalForFixture(t *testing.T, fixture domainFixture) (Proposal, StateRef) {
	t.Helper()
	original := fixture.new()
	executor := Identity{ID: "executor:original:" + fixture.name, Kind: "process"}
	reserved, err := PrepareEffectCustody(original, executor, "001")
	if err != nil {
		t.Fatal(err)
	}
	return original, closedCustody(t, reserved)
}

func TestCompensationIsDistinctGovernedEffectAcrossDomains(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			original, originalClosed := closedOriginalForFixture(t, fixture)
			compensation := compensationProposalFor(original)
			compExecutor := Identity{ID: "executor:compensation:" + fixture.name, Kind: "process"}

			binding, err := BuildCompensationBinding(original, originalClosed, compensation)
			if err != nil {
				t.Fatalf("build compensation binding: %v", err)
			}
			compCustody, err := PrepareEffectCustody(compensation, compExecutor, "001")
			if err != nil {
				t.Fatalf("prepare compensation custody: %v", err)
			}

			got := EvaluateCompensationBoundary(
				original,
				originalClosed,
				compensation,
				compExecutor,
				compCustody,
				binding,
			)
			if got.Decision != DecisionAllow {
				t.Fatalf("compensation boundary rejected: %+v", got)
			}

			originalID, _ := EffectIdentity(original)
			compensationID, _ := EffectIdentity(compensation)
			if originalID == compensationID {
				t.Fatal("compensation reused original logical effect identity")
			}
			if got := DeriveCompensationStatus(originalClosed, compCustody); got != CompensationRequired {
				t.Fatalf("fresh compensation status = %s, want REQUIRED", got)
			}
		})
	}
}

func TestUnknownOriginalEffectCannotBeAutomaticallyCompensated(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			original, originalUnknown := unknownCustodyForFixture(t, fixture)
			compensation := compensationProposalFor(original)

			if _, err := BuildCompensationBinding(original, originalUnknown, compensation); err == nil {
				t.Fatal("UNKNOWN original effect incorrectly justified compensation binding")
			}

			compExecutor := Identity{ID: "executor:compensation:" + fixture.name, Kind: "process"}
			compCustody, err := PrepareEffectCustody(compensation, compExecutor, "001")
			if err != nil {
				t.Fatal(err)
			}
			forged := CompensationBinding{
				OriginalEffectID:     originalUnknown.ObjectID,
				CompensationEffectID: compCustody.ObjectID,
				Evidence: Evidence{
					ID:          "forged",
					Type:        "compensation-binding-attestation",
					StateDigest: originalUnknown.Digest,
					Valid:       true,
				},
			}

			got := EvaluateCompensationBoundary(
				original,
				originalUnknown,
				compensation,
				compExecutor,
				compCustody,
				forged,
			)
			if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
				t.Fatalf("UNKNOWN original effect must block compensation, got %+v", got)
			}
			if status := DeriveCompensationStatus(originalUnknown, compCustody); status != CompensationNotJustified {
				t.Fatalf("UNKNOWN original status = %s, want NOT_JUSTIFIED", status)
			}
		})
	}
}

func TestCompensationBindingIsStateAndEffectSpecific(t *testing.T) {
	original, originalClosed := closedOriginalForFixture(t, fixtures()[0])
	compensation := compensationProposalFor(original)
	compExecutor := Identity{ID: "executor:compensation", Kind: "process"}
	compCustody, err := PrepareEffectCustody(compensation, compExecutor, "001")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := BuildCompensationBinding(original, originalClosed, compensation)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("stale-original-custody-digest", func(t *testing.T) {
		attacked := binding
		attacked.Evidence.StateDigest = "sha256:stale"
		got := EvaluateCompensationBoundary(
			original,
			originalClosed,
			compensation,
			compExecutor,
			compCustody,
			attacked,
		)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("stale compensation binding admitted: %+v", got)
		}
	})

	t.Run("foreign-compensation-effect", func(t *testing.T) {
		attacked := binding
		attacked.CompensationEffectID = "another-effect"
		got := EvaluateCompensationBoundary(
			original,
			originalClosed,
			compensation,
			compExecutor,
			compCustody,
			attacked,
		)
		if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
			t.Fatalf("foreign compensation effect admitted: %+v", got)
		}
	})
}

func TestCompensationCannotBeTheOriginalEffect(t *testing.T) {
	original, originalClosed := closedOriginalForFixture(t, fixtures()[1])
	if _, err := BuildCompensationBinding(original, originalClosed, original); err == nil {
		t.Fatal("original effect accepted as its own compensation")
	}
}

func TestAmbiguousCompensationDoesNotEraseOriginalHistory(t *testing.T) {
	original, originalClosed := closedOriginalForFixture(t, fixtures()[2])
	compensation := compensationProposalFor(original)
	compExecutor := Identity{ID: "executor:compensation", Kind: "process"}
	compReserved, err := PrepareEffectCustody(compensation, compExecutor, "001")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := BuildCompensationBinding(original, originalClosed, compensation)
	if err != nil {
		t.Fatal(err)
	}

	crossing, err := AdvanceEffectCustody(compReserved, CustodyCrossing)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
	if err != nil {
		t.Fatal(err)
	}

	if status := DeriveCompensationStatus(originalClosed, unknown.To); status != CompensationUnknown {
		t.Fatalf("ambiguous compensation status = %s, want UNKNOWN", status)
	}
	if got := EvaluateCompensationBoundary(
		original,
		originalClosed,
		compensation,
		compExecutor,
		unknown.To,
		binding,
	); got.Decision != DecisionDeny {
		t.Fatalf("ambiguous compensation became replay permission: %+v", got)
	}

	if originalClosed.Facts[factCustodyPhase] != CustodyClosed {
		t.Fatal("compensation ambiguity rewrote original effect history")
	}
}

func TestClosedCompensationMeansNewEffectClosedNotOriginalReversed(t *testing.T) {
	original, originalClosed := closedOriginalForFixture(t, fixtures()[0])
	compensation := compensationProposalFor(original)
	compExecutor := Identity{ID: "executor:compensation", Kind: "process"}
	compReserved, err := PrepareEffectCustody(compensation, compExecutor, "001")
	if err != nil {
		t.Fatal(err)
	}
	compClosed := closedCustody(t, compReserved)

	if status := DeriveCompensationStatus(originalClosed, compClosed); status != CompensationClosed {
		t.Fatalf("closed compensation status = %s, want CLOSED", status)
	}
	if originalClosed.Facts[factCustodyPhase] != CustodyClosed {
		t.Fatal("closing compensation changed original custody history")
	}
}

func TestPartialPlanOnlyCompensatesTruthfullyClosedEffects(t *testing.T) {
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

	firstComp := compensationProposalFor(plan.Steps[0].Proposal)
	if _, err := BuildCompensationBinding(plan.Steps[0].Proposal, firstClosed, firstComp); err != nil {
		t.Fatalf("truthfully closed first effect should be compensatable: %v", err)
	}

	secondComp := compensationProposalFor(plan.Steps[1].Proposal)
	if _, err := BuildCompensationBinding(plan.Steps[1].Proposal, secondUnknown, secondComp); err == nil {
		t.Fatal("UNKNOWN middle effect was automatically compensatable")
	}
}

func TestCompensationExperimentStillUsesSixPrimitives(t *testing.T) {
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("compensation experiment expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{
		"rollback",
		"compensation",
		"saga",
		"inverse",
		"irreversibility",
	} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain derived semantics in v7", forbidden)
			}
		}
	}
}
