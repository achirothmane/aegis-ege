package primitivereduction

import "testing"

type agenticWorkforceFixture struct {
	name string
	new  func() Proposal
}

func agenticWorkforceFixtures() []agenticWorkforceFixture {
	return []agenticWorkforceFixture{
		{name: "sales-send-email", new: func() Proposal {
			return agenticProposal(
				"agent:sales",
				"crm.contact",
				"lead-42",
				"send_email",
				"outbound/email/welcome/lead-42",
				"state:lead-42:ready",
				"state:lead-42:emailed",
			)
		}},
		{name: "finance-issue-invoice", new: func() Proposal {
			return agenticProposal(
				"agent:finance",
				"billing.invoice",
				"invoice-9001",
				"issue_invoice",
				"billing/invoice/9001/issue",
				"state:invoice-9001:draft",
				"state:invoice-9001:issued",
			)
		}},
		{name: "developer-deploy-release", new: func() Proposal {
			return agenticProposal(
				"agent:developer",
				"deployment.service",
				"prod/api",
				"deploy_release",
				"deployment/prod-api/release-42",
				"state:prod-api:r41",
				"state:prod-api:r42",
			)
		}},
		{name: "community-publish-post", new: func() Proposal {
			return agenticProposal(
				"agent:community",
				"social.post",
				"campaign-7",
				"publish_post",
				"social/campaign-7/post-1",
				"state:campaign-7:draft",
				"state:campaign-7:published",
			)
		}},
	}
}

func agenticProposal(subjectID, namespace, objectID, operation, effectSlot, fromVersion, toVersion string) Proposal {
	current := StateRef{
		Namespace: namespace,
		ObjectID:  objectID,
		Version:   fromVersion,
		Digest:    "sha256:" + fromVersion,
		Facts: map[string]string{
			factEffectSlot:          effectSlot,
			"authority.revoked":     "false",
			"budget.remaining":      "5",
			"clock.monotonic_tick":  "100",
			"execution.environment": "production",
		},
	}
	return Proposal{
		Subject: Identity{ID: subjectID, Kind: "agent"},
		Current: current,
		Capability: Capability{
			Name:      operation,
			SubjectID: subjectID,
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "authority-current",
				Predicates: []Predicate{
					{Fact: "authority.revoked", Op: OpEqual, Value: "false"},
					{Fact: "clock.monotonic_tick", Op: OpLessThanInt, Value: "150"},
				},
				EvidenceIDs: []string{"authority"},
			},
			{
				ID: "budget-available",
				Predicates: []Predicate{
					{Fact: "budget.remaining", Op: OpGreaterOrEqualInt, Value: "1"},
				},
				EvidenceIDs: []string{"budget"},
			},
			{
				ID: "effect-slot-bound",
				Predicates: []Predicate{
					{Fact: factEffectSlot, Op: OpEqual, Value: effectSlot},
				},
				EvidenceIDs: []string{"plan"},
			},
		},
		Evidence: []Evidence{
			{ID: "authority", Type: "authority-attestation", StateDigest: current.Digest, Valid: true},
			{ID: "budget", Type: "budget-attestation", StateDigest: current.Digest, Valid: true},
			{ID: "plan", Type: "effect-plan-attestation", StateDigest: current.Digest, Valid: true},
		},
		Transition: Transition{
			Operation: operation,
			From:      current,
			To: StateRef{
				Namespace: namespace,
				ObjectID:  objectID,
				Version:   toVersion,
				Digest:    "sha256:" + toVersion,
			},
		},
	}
}

func duplicateEmailProposal(subjectID string) Proposal {
	return agenticProposal(
		subjectID,
		"crm.contact",
		"lead-99",
		"send_email",
		"outbound/email/welcome/lead-99",
		"state:lead-99:ready",
		"state:lead-99:emailed",
	)
}

func TestAgenticWorkforceFourthDomainUsesSameFivePrimitiveEvaluator(t *testing.T) {
	if got := len(ReducedCandidatePrimitives()); got != 5 {
		t.Fatalf("reduced primitive count = %d, want 5", got)
	}

	for _, fixture := range agenticWorkforceFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			reduced := ReduceCapability(fixture.new())
			if result := EvaluateReducedAdmission(reduced); result.Decision != DecisionAllow {
				t.Fatalf("agentic reduced admission = %+v", result)
			}
			capability, err := MintDerivedCapability(reduced)
			if err != nil {
				t.Fatalf("mint post-admission capability: %v", err)
			}
			if !capability.Complete() {
				t.Fatal("post-admission mechanical capability is incomplete")
			}
			if _, err := ReducedEffectSlotIdentity(reduced); err != nil {
				t.Fatalf("derive effect slot identity: %v", err)
			}
		})
	}
}

func TestAgenticWorkforceAuthorityRevocationFailsClosedAtBoundary(t *testing.T) {
	reduced := ReduceCapability(agenticWorkforceFixtures()[0].new())
	executor := Identity{ID: "executor:agentic-boundary", Kind: "process"}

	custody, err := PrepareReducedEffectSlotCustody(reduced, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	revoked := reduced
	revoked.Current = copyState(reduced.Current)
	revoked.Current.Facts["authority.revoked"] = "true"

	if _, got := ClaimReducedEffectSlotBoundary(revoked, executor, custody); got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
		t.Fatalf("revoked authority crossed effect boundary: %+v", got)
	}
}

func TestAgenticWorkforceStaleEvidenceFailsClosed(t *testing.T) {
	reduced := ReduceCapability(agenticWorkforceFixtures()[1].new())
	reduced.Evidence = append([]Evidence(nil), reduced.Evidence...)
	reduced.Evidence[0].StateDigest = "sha256:stale"

	if got := EvaluateReducedAdmission(reduced); got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
		t.Fatalf("stale agent evidence admitted: %+v", got)
	}
}

func TestCrossSubjectDuplicateExposesAuthorityScopedEffectIdentityBoundary(t *testing.T) {
	primary := duplicateEmailProposal("agent:sales-primary")
	backup := duplicateEmailProposal("agent:sales-backup")

	primaryID, err := EffectIdentity(primary)
	if err != nil {
		t.Fatal(err)
	}
	backupID, err := EffectIdentity(backup)
	if err != nil {
		t.Fatal(err)
	}
	if primaryID == backupID {
		t.Fatal("legacy authority-scoped EffectIdentity unexpectedly collapsed different subjects")
	}

	primarySlotID, err := ReducedEffectSlotIdentity(ReduceCapability(primary))
	if err != nil {
		t.Fatal(err)
	}
	backupSlotID, err := ReducedEffectSlotIdentity(ReduceCapability(backup))
	if err != nil {
		t.Fatal(err)
	}
	if primarySlotID != backupSlotID {
		t.Fatalf("same trusted external effect slot split across subjects: primary=%s backup=%s", primarySlotID, backupSlotID)
	}
}

func TestSharedEffectSlotAllowsOnlyOneAuthorizedAgentToCross(t *testing.T) {
	primary := ReduceCapability(duplicateEmailProposal("agent:sales-primary"))
	backup := ReduceCapability(duplicateEmailProposal("agent:sales-backup"))
	executor := Identity{ID: "executor:agentic-boundary", Kind: "process"}

	reserved, err := PrepareReducedEffectSlotCustody(primary, executor, "001")
	if err != nil {
		t.Fatal(err)
	}

	claimA, gotA := ClaimReducedEffectSlotBoundary(primary, executor, reserved)
	if gotA.Decision != DecisionAllow {
		t.Fatalf("primary claim rejected: %+v", gotA)
	}
	claimB, gotB := ClaimReducedEffectSlotBoundary(backup, executor, reserved)
	if gotB.Decision != DecisionAllow {
		t.Fatalf("backup should contend on same stale RESERVED slot: %+v", gotB)
	}

	crossing, err := ApplyStateTransitionCAS(reserved, claimA)
	if err != nil {
		t.Fatalf("primary CAS claim failed: %v", err)
	}
	if crossing.Facts[factCustodyPhase] != CustodyCrossing {
		t.Fatalf("primary did not enter CROSSING: %+v", crossing)
	}
	if _, err := ApplyStateTransitionCAS(crossing, claimB); err == nil {
		t.Fatal("second authorized agent crossed the same shared external effect slot")
	}
}

func TestCrashAfterBoundaryBlocksBlindCrossAgentReplay(t *testing.T) {
	primary := ReduceCapability(duplicateEmailProposal("agent:sales-primary"))
	backup := ReduceCapability(duplicateEmailProposal("agent:sales-backup"))
	executor := Identity{ID: "executor:agentic-boundary", Kind: "process"}

	reserved, err := PrepareReducedEffectSlotCustody(primary, executor, "001")
	if err != nil {
		t.Fatal(err)
	}
	claim, got := ClaimReducedEffectSlotBoundary(primary, executor, reserved)
	if got.Decision != DecisionAllow {
		t.Fatalf("primary claim rejected: %+v", got)
	}
	crossing, err := ApplyStateTransitionCAS(reserved, claim)
	if err != nil {
		t.Fatal(err)
	}
	unknownTransition, err := AdvanceEffectCustody(crossing, CustodyUnknown)
	if err != nil {
		t.Fatal(err)
	}
	unknown := unknownTransition.To

	if _, got := ClaimReducedEffectSlotBoundary(backup, executor, unknown); got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
		t.Fatalf("backup replayed an UNKNOWN shared effect after crash: %+v", got)
	}
	if got := ReconcileExternalEffect(unknown, Evidence{}); got != ClosureUnknown {
		t.Fatalf("missing provider evidence manufactured closure: %s", got)
	}

	slotID, err := ReducedEffectSlotIdentity(primary)
	if err != nil {
		t.Fatal(err)
	}
	observation := Evidence{
		ID:          slotID,
		Type:        "provider-final-observation",
		StateDigest: unknown.Digest,
		Valid:       true,
	}
	if got := ReconcileExternalEffect(unknown, observation); got != ClosureClosed {
		t.Fatalf("valid final observation did not close UNKNOWN custody: %s", got)
	}
}

func TestDistinctAgenticSlotsRemainIndependent(t *testing.T) {
	first := ReduceCapability(duplicateEmailProposal("agent:sales"))
	secondOriginal := duplicateEmailProposal("agent:sales")
	secondOriginal.Current = copyState(secondOriginal.Current)
	secondOriginal.Current.ObjectID = "lead-100"
	secondOriginal.Current.Version = "state:lead-100:ready"
	secondOriginal.Current.Digest = "sha256:state:lead-100:ready"
	secondOriginal.Current.Facts[factEffectSlot] = "outbound/email/welcome/lead-100"
	secondOriginal.Capability.TargetKey = secondOriginal.Current.TargetKey()
	secondOriginal.Transition.From = secondOriginal.Current
	secondOriginal.Transition.To.ObjectID = "lead-100"
	secondOriginal.Transition.To.Version = "state:lead-100:emailed"
	secondOriginal.Transition.To.Digest = "sha256:state:lead-100:emailed"
	for i := range secondOriginal.Evidence {
		secondOriginal.Evidence[i].StateDigest = secondOriginal.Current.Digest
	}
	secondOriginal.Constraints[2].Predicates[0].Value = secondOriginal.Current.Facts[factEffectSlot]
	second := ReduceCapability(secondOriginal)

	firstID, err := ReducedEffectSlotIdentity(first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := ReducedEffectSlotIdentity(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("distinct external effect slots collapsed into one identity")
	}
}

func TestMissingEffectSlotFailsClosed(t *testing.T) {
	reduced := ReduceCapability(agenticWorkforceFixtures()[2].new())
	reduced.Current = copyState(reduced.Current)
	delete(reduced.Current.Facts, factEffectSlot)

	executor := Identity{ID: "executor:agentic-boundary", Kind: "process"}
	if _, err := PrepareReducedEffectSlotCustody(reduced, executor, "001"); err == nil {
		t.Fatal("missing trusted effect slot created executable custody")
	}
}
