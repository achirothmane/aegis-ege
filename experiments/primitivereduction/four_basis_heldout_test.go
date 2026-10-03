package primitivereduction

import (
	"reflect"
	"strings"
	"testing"
)

func terraformHeldoutProposal() Proposal {
	current := StateRef{
		Namespace: "terraform.aws_bedrockagentcore_memory_strategy",
		ObjectID:  "memory:mem-123/strategy:semantic",
		Version:   "tfstate:absent:plan-001",
		Digest:    "sha256:terraform-memory-strategy-absent-plan-001",
		Facts: map[string]string{
			"plan.hash":            "sha256:plan-001",
			"policy.revoked":       "false",
			"clock.monotonic_tick": "1000",
		},
	}

	return Proposal{
		Subject: Identity{
			ID:   "service:terraform-provider-aws",
			Kind: "service",
		},
		Current: current,
		Capability: Capability{
			Name:      "create_strategy",
			SubjectID: "service:terraform-provider-aws",
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "exact-plan",
				Predicates: []Predicate{
					{Fact: "plan.hash", Op: OpEqual, Value: "sha256:plan-001"},
				},
				EvidenceIDs: []string{"plan"},
			},
			{
				ID: "authority-current",
				Predicates: []Predicate{
					{Fact: "policy.revoked", Op: OpEqual, Value: "false"},
					{Fact: "clock.monotonic_tick", Op: OpLessThanInt, Value: "1100"},
				},
				EvidenceIDs: []string{"authority"},
			},
		},
		Evidence: []Evidence{
			{
				ID:          "plan",
				Type:        "terraform-plan",
				StateDigest: current.Digest,
				Valid:       true,
			},
			{
				ID:          "authority",
				Type:        "authority-and-clock-attestation",
				StateDigest: current.Digest,
				Valid:       true,
			},
		},
		Transition: Transition{
			Operation: "create_strategy",
			From:      current,
			To: StateRef{
				Namespace: current.Namespace,
				ObjectID:  current.ObjectID,
				Version:   "tfstate:present:strategy-001",
				Digest:    "sha256:terraform-memory-strategy-present-001",
			},
		},
	}
}

func terraformHeldoutFourFixture(t *testing.T) (Proposal, ConstraintFreeProposal, StateRef) {
	t.Helper()

	source := terraformHeldoutProposal()
	decomposed := DecomposeEvidence(ReduceCapability(source))
	policyIssuer := Identity{ID: "policy:terraform-heldout", Kind: "policy"}

	trusted := make([]Identity, 0, len(decomposed.Attestations)+1)
	for _, attestation := range decomposed.Attestations {
		trusted = append(trusted, attestation.Issuer)
	}
	trusted = append(trusted, policyIssuer)

	trust := BuildProvenanceTrustState("trust-v16", trusted)
	four, err := BuildAdmissionAttestation(decomposed, trust, policyIssuer)
	if err != nil {
		t.Fatalf("build four-primitive terraform fixture: %v", err)
	}
	return source, four, trust
}

func TestFourPrimitiveBasisExact(t *testing.T) {
	got := FourPrimitiveBasis()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveAttestation,
		PrimitiveTransition,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("four-primitive basis = %v, want %v", got, want)
	}
}

func TestTerraformHeldOutWasNotOriginalReductionFixture(t *testing.T) {
	for _, fixture := range fixtures() {
		if strings.Contains(strings.ToLower(fixture.name), "terraform") {
			t.Fatalf("terraform unexpectedly exists in original reduction fixtures: %q", fixture.name)
		}
	}
}

func TestHeldOutTerraformAdmitsThroughSameFourPrimitiveKernelSurface(t *testing.T) {
	_, four, trust := terraformHeldoutFourFixture(t)

	if got := EvaluateConstraintFreeAdmission(four, trust); got.Decision != DecisionAllow {
		t.Fatalf("held-out terraform relation rejected: %+v", got)
	}
	if got := FourPrimitiveBasis(); len(got) != 4 {
		t.Fatalf("held-out domain expanded primitive basis: %v", got)
	}
}

func TestTerraformOrphanedEffectIsBlockedByStateCustodyWithoutNewPrimitive(t *testing.T) {
	_, four, trust := terraformHeldoutFourFixture(t)
	executor := Identity{ID: "executor:terraform-provider-aws", Kind: "process"}

	custody, err := PrepareFourPrimitiveCustody(four, executor, "001")
	if err != nil {
		t.Fatalf("prepare four-primitive custody: %v", err)
	}
	if got := EvaluateFourPrimitiveEffectBoundary(four, trust, executor, custody); got.Decision != DecisionAllow {
		t.Fatalf("initial exact boundary should admit: %+v", got)
	}

	crossing, err := AdvanceEffectCustody(custody, CustodyCrossing)
	if err != nil {
		t.Fatalf("advance custody to crossing: %v", err)
	}
	unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
	if err != nil {
		t.Fatalf("advance custody to unknown: %v", err)
	}

	// This models the held-out Terraform incident: the provider API may have
	// created the external strategy, but the local Terraform state write failed.
	// The business/local target still looks absent and the original admission
	// relation therefore remains structurally current.
	if got := EvaluateConstraintFreeAdmission(four, trust); got.Decision != DecisionAllow {
		t.Fatalf("unchanged local state should still look admissible without custody: %+v", got)
	}

	// The generic custody State preserves the possible prior effect and blocks a
	// second create even though local business state still says "absent".
	got := EvaluateFourPrimitiveEffectBoundary(four, trust, executor, unknown.To)
	if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
		t.Fatalf("UNKNOWN possible-effect custody did not block duplicate create: %+v", got)
	}

	if _, err := AdvanceEffectCustody(unknown.To, CustodyReserved); err == nil {
		t.Fatal("UNKNOWN custody became replay permission")
	}

	if unknown.To.Namespace != custodyNamespace {
		t.Fatalf("custody is not ordinary State: %+v", unknown.To)
	}
	if crossing.Operation == "" || !crossing.Complete() {
		t.Fatalf("custody phase change is not ordinary Transition: %+v", crossing)
	}
}

func TestFourPrimitiveEffectIdentitySurvivesAuthorizationPathButChangesOnMaterialEffect(t *testing.T) {
	_, base, _ := terraformHeldoutFourFixture(t)

	baseline, err := FourPrimitiveEffectIdentity(base)
	if err != nil {
		t.Fatal(err)
	}

	// A different trusted authorization record for the same logical effect must
	// not manufacture a second logical effect identity.
	otherAttestation := base
	otherAttestation.Attestation.ID = "admission:alternate-policy-path"
	if got, err := FourPrimitiveEffectIdentity(otherAttestation); err != nil || got != baseline {
		t.Fatalf("authorization path changed logical effect identity: got=%q err=%v", got, err)
	}

	cases := map[string]func(*ConstraintFreeProposal){
		"subject": func(p *ConstraintFreeProposal) {
			p.Subject.ID += ":other"
		},
		"operation": func(p *ConstraintFreeProposal) {
			p.Transition.Operation = "delete_strategy"
		},
		"state-revision": func(p *ConstraintFreeProposal) {
			p.Current.Version += ":next"
			p.Current.Digest = "sha256:next-state"
			p.Transition.From.Version = p.Current.Version
			p.Transition.From.Digest = p.Current.Digest
		},
		"target": func(p *ConstraintFreeProposal) {
			p.Current.ObjectID = "memory:mem-456/strategy:semantic"
			p.Transition.From.ObjectID = p.Current.ObjectID
			p.Transition.To.ObjectID = p.Current.ObjectID
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := FourPrimitiveEffectIdentity(changed)
			if err != nil {
				t.Fatalf("derive changed effect identity: %v", err)
			}
			if got == baseline {
				t.Fatalf("%s substitution did not change logical effect identity", name)
			}
		})
	}
}

func TestHeldOutTerraformSubstitutionsStillFailAtFourPrimitiveAdmission(t *testing.T) {
	_, base, trust := terraformHeldoutFourFixture(t)

	tests := map[string]func(*ConstraintFreeProposal){
		"subject": func(p *ConstraintFreeProposal) {
			p.Subject.ID = "service:other-provider"
		},
		"operation": func(p *ConstraintFreeProposal) {
			p.Transition.Operation = "delete_strategy"
		},
		"state": func(p *ConstraintFreeProposal) {
			p.Current.Version += ":next"
			p.Transition.From.Version = p.Current.Version
		},
		"target": func(p *ConstraintFreeProposal) {
			p.Transition.To.ObjectID = "memory:other/strategy:semantic"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := EvaluateConstraintFreeAdmission(changed, trust); got.Decision != DecisionDeny {
				t.Fatalf("%s substitution admitted: %+v", name, got)
			}
		})
	}
}

func TestHeldOutTerraformMissingAttestationFailsClosed(t *testing.T) {
	_, four, trust := terraformHeldoutFourFixture(t)
	four.Attestation = AdmissionAttestation{}

	got := EvaluateConstraintFreeAdmission(four, trust)
	if got.Decision != DecisionDeny || got.Reason != ReasonMissingEvidence {
		t.Fatalf("missing authorization provenance admitted: %+v", got)
	}
}
