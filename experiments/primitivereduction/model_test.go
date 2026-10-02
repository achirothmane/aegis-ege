package primitivereduction

import "testing"

type domainFixture struct {
	name string
	new  func() Proposal
}

func fixtures() []domainFixture {
	return []domainFixture{
		{name: "github-merge", new: githubMergeProposal},
		{name: "kubernetes-delete", new: kubernetesDeleteProposal},
		{name: "postgres-schema-migration", new: postgresMigrationProposal},
	}
}

func githubMergeProposal() Proposal {
	current := StateRef{
		Namespace: "github.pull_request",
		ObjectID:  "achirothmane/aegis-ege#138",
		Version:   "head:abc123",
		Digest:    "sha256:github-state-abc123",
		Facts: map[string]string{
			"ci.required_checks":   "green",
			"approvals.count":      "2",
			"policy.revoked":       "false",
			"clock.monotonic_tick": "100",
		},
	}
	return Proposal{
		Subject: Identity{ID: "agent:merge-bot", Kind: "agent"},
		Current: current,
		Capability: Capability{
			Name:      "merge",
			SubjectID: "agent:merge-bot",
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "required-checks-green",
				Predicates: []Predicate{
					{Fact: "ci.required_checks", Op: OpEqual, Value: "green"},
				},
				EvidenceIDs: []string{"ci"},
			},
			{
				ID: "two-approvals",
				Predicates: []Predicate{
					{Fact: "approvals.count", Op: OpGreaterOrEqualInt, Value: "2"},
				},
				EvidenceIDs: []string{"approvals"},
			},
			{
				ID: "authority-current",
				Predicates: []Predicate{
					{Fact: "policy.revoked", Op: OpEqual, Value: "false"},
					{Fact: "clock.monotonic_tick", Op: OpLessThanInt, Value: "150"},
				},
				EvidenceIDs: []string{"authority"},
			},
		},
		Evidence: []Evidence{
			{ID: "ci", Type: "ci-check-set", StateDigest: current.Digest, Valid: true},
			{ID: "approvals", Type: "review-approval-set", StateDigest: current.Digest, Valid: true},
			{ID: "authority", Type: "authority-and-clock-attestation", StateDigest: current.Digest, Valid: true},
		},
		Transition: Transition{
			Operation: "merge",
			From:      current,
			To: StateRef{
				Namespace: current.Namespace,
				ObjectID:  current.ObjectID,
				Version:   "merged:def456",
				Digest:    "sha256:github-state-def456",
			},
		},
	}
}

func kubernetesDeleteProposal() Proposal {
	current := StateRef{
		Namespace: "kubernetes.deployment",
		ObjectID:  "prod/payments",
		Version:   "resourceVersion:4102",
		Digest:    "sha256:kube-state-4102",
		Facts: map[string]string{
			"namespace.allowed":    "true",
			"resource.protected":   "false",
			"policy.revoked":       "false",
			"clock.monotonic_tick": "220",
		},
	}
	return Proposal{
		Subject: Identity{ID: "workload:deployment-controller", Kind: "workload"},
		Current: current,
		Capability: Capability{
			Name:      "delete",
			SubjectID: "workload:deployment-controller",
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "namespace-allowed",
				Predicates: []Predicate{
					{Fact: "namespace.allowed", Op: OpEqual, Value: "true"},
				},
				EvidenceIDs: []string{"live-read"},
			},
			{
				ID: "not-protected",
				Predicates: []Predicate{
					{Fact: "resource.protected", Op: OpEqual, Value: "false"},
				},
				EvidenceIDs: []string{"live-read"},
			},
			{
				ID: "lease-current",
				Predicates: []Predicate{
					{Fact: "policy.revoked", Op: OpEqual, Value: "false"},
					{Fact: "clock.monotonic_tick", Op: OpLessThanInt, Value: "260"},
				},
				EvidenceIDs: []string{"authority"},
			},
		},
		Evidence: []Evidence{
			{ID: "live-read", Type: "kubernetes-live-state", StateDigest: current.Digest, Valid: true},
			{ID: "authority", Type: "authority-and-clock-attestation", StateDigest: current.Digest, Valid: true},
		},
		Transition: Transition{
			Operation: "delete",
			From:      current,
			To: StateRef{
				Namespace: current.Namespace,
				ObjectID:  current.ObjectID,
				Version:   "tombstone:4103",
				Digest:    "sha256:kube-state-absent-4103",
			},
		},
	}
}

func postgresMigrationProposal() Proposal {
	current := StateRef{
		Namespace: "postgres.schema",
		ObjectID:  "billing.public",
		Version:   "schema:41",
		Digest:    "sha256:postgres-schema-41",
		Facts: map[string]string{
			"migration.hash":       "sha256:migration-42",
			"approvals.count":      "2",
			"policy.revoked":       "false",
			"clock.monotonic_tick": "700",
		},
	}
	return Proposal{
		Subject: Identity{ID: "service:migration-executor", Kind: "service"},
		Current: current,
		Capability: Capability{
			Name:      "alter_schema",
			SubjectID: "service:migration-executor",
			TargetKey: current.TargetKey(),
		},
		Constraints: []Constraint{
			{
				ID: "approved-migration-hash",
				Predicates: []Predicate{
					{Fact: "migration.hash", Op: OpEqual, Value: "sha256:migration-42"},
				},
				EvidenceIDs: []string{"migration-approval"},
			},
			{
				ID: "two-approvals",
				Predicates: []Predicate{
					{Fact: "approvals.count", Op: OpGreaterOrEqualInt, Value: "2"},
				},
				EvidenceIDs: []string{"migration-approval"},
			},
			{
				ID: "authority-current",
				Predicates: []Predicate{
					{Fact: "policy.revoked", Op: OpEqual, Value: "false"},
					{Fact: "clock.monotonic_tick", Op: OpLessThanInt, Value: "760"},
				},
				EvidenceIDs: []string{"authority"},
			},
		},
		Evidence: []Evidence{
			{ID: "migration-approval", Type: "migration-approval", StateDigest: current.Digest, Valid: true},
			{ID: "authority", Type: "authority-and-clock-attestation", StateDigest: current.Digest, Valid: true},
		},
		Transition: Transition{
			Operation: "alter_schema",
			From:      current,
			To: StateRef{
				Namespace: current.Namespace,
				ObjectID:  current.ObjectID,
				Version:   "schema:42",
				Digest:    "sha256:postgres-schema-42",
			},
		},
	}
}

func TestCandidatePrimitivesExact(t *testing.T) {
	got := CandidatePrimitives()
	want := []Primitive{
		PrimitiveIdentity,
		PrimitiveState,
		PrimitiveCapability,
		PrimitiveConstraint,
		PrimitiveEvidence,
		PrimitiveTransition,
	}
	if len(got) != len(want) {
		t.Fatalf("primitive count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("primitive[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestThreeDomainsUseSameEvaluator(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			result := EvaluateAdmission(fixture.new())
			if result.Decision != DecisionAllow {
				t.Fatalf("decision = %s reason=%s detail=%s", result.Decision, result.Reason, result.Detail)
			}
		})
	}
}

func TestPrimitiveAblationFailsClosed(t *testing.T) {
	expect := map[Primitive]Reason{
		PrimitiveIdentity:   ReasonMissingIdentity,
		PrimitiveState:      ReasonMissingState,
		PrimitiveCapability: ReasonMissingCapability,
		PrimitiveConstraint: ReasonMissingConstraint,
		PrimitiveEvidence:   ReasonMissingEvidence,
		PrimitiveTransition: ReasonMissingTransition,
	}

	for _, fixture := range fixtures() {
		for _, primitive := range CandidatePrimitives() {
			t.Run(fixture.name+"/"+string(primitive), func(t *testing.T) {
				proposal := fixture.new()
				ablate(&proposal, primitive)
				result := EvaluateAdmission(proposal)
				if result.Decision != DecisionDeny {
					t.Fatalf("ablation %s unexpectedly allowed", primitive)
				}
				if result.Reason != expect[primitive] {
					t.Fatalf("ablation %s reason = %s, want %s; detail=%s", primitive, result.Reason, expect[primitive], result.Detail)
				}
			})
		}
	}
}

func ablate(p *Proposal, primitive Primitive) {
	switch primitive {
	case PrimitiveIdentity:
		p.Subject = Identity{}
	case PrimitiveState:
		p.Current = StateRef{}
	case PrimitiveCapability:
		p.Capability = Capability{}
	case PrimitiveConstraint:
		p.Constraints = nil
	case PrimitiveEvidence:
		p.Evidence = nil
	case PrimitiveTransition:
		p.Transition = Transition{}
	}
}

func TestTimeCanBeRepresentedAsStatePlusConstraint(t *testing.T) {
	proposal := githubMergeProposal()
	if result := EvaluateAdmission(proposal); result.Decision != DecisionAllow {
		t.Fatalf("fresh lease should allow: %+v", result)
	}

	proposal.Current.Facts["clock.monotonic_tick"] = "151"
	result := EvaluateAdmission(proposal)
	if result.Decision != DecisionDeny || result.Reason != ReasonConstraintViolated {
		t.Fatalf("expired lease should fail closed through State+Constraint, got %+v", result)
	}
}

func TestTargetObjectIsCarriedByStateBinding(t *testing.T) {
	proposal := kubernetesDeleteProposal()
	proposal.Transition.To.ObjectID = "prod/other"

	result := EvaluateAdmission(proposal)
	if result.Decision != DecisionDeny || result.Reason != ReasonBindingMismatch {
		t.Fatalf("target substitution should fail binding integrity, got %+v", result)
	}
}

func TestLifecycleRelationsAreDerived(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()

			intent := DeriveIntent(proposal)
			if intent.SubjectID != proposal.Subject.ID ||
				intent.Operation != proposal.Transition.Operation ||
				intent.TargetKey != proposal.Current.TargetKey() {
				t.Fatalf("intent not derived from primitive bindings: %+v", intent)
			}

			authority := DeriveAuthority(proposal)
			if authority.SubjectID != proposal.Subject.ID ||
				authority.Capability != proposal.Capability.Name ||
				authority.StateDigest != proposal.Current.Digest ||
				len(authority.ConstraintIDs) != len(proposal.Constraints) {
				t.Fatalf("authority not derived from primitives: %+v", authority)
			}

			lease := DeriveExecutionLease(proposal, proposal.Constraints[len(proposal.Constraints)-1].ID, proposal.Constraints[len(proposal.Constraints)-1].ID)
			if lease.StateDigest != proposal.Current.Digest ||
				lease.Authority.TargetKey != proposal.Current.TargetKey() {
				t.Fatalf("lease not state-bound: %+v", lease)
			}
		})
	}
}

func TestReconciliationRequiresExactObservedAfterState(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal := fixture.new()
			observation := Observation{
				State: proposal.Transition.To,
				Evidence: Evidence{
					ID:          "post-effect-observation",
					Type:        "domain-observation",
					StateDigest: proposal.Transition.To.Digest,
					Valid:       true,
				},
			}
			if got := Reconcile(proposal.Transition, observation); got != ClosureClosed {
				t.Fatalf("exact observed after-state should close, got %s", got)
			}

			stale := observation
			stale.State = proposal.Current
			stale.Evidence.StateDigest = proposal.Current.Digest
			if got := Reconcile(proposal.Transition, stale); got != ClosureUnknown {
				t.Fatalf("stale observation must remain UNKNOWN, got %s", got)
			}

			invalid := observation
			invalid.Evidence.Valid = false
			if got := Reconcile(proposal.Transition, invalid); got != ClosureUnknown {
				t.Fatalf("invalid observation must remain UNKNOWN, got %s", got)
			}
		})
	}
}

func TestReceiptRequiresEvidenceBoundToObservedState(t *testing.T) {
	proposal := postgresMigrationProposal()
	executor := Identity{ID: "process:migration-42", Kind: "process"}

	if _, err := BuildReceipt(executor, proposal, proposal.Transition.To, Evidence{
		ID:          "effect-observation",
		Type:        "postgres-observation",
		StateDigest: proposal.Transition.To.Digest,
		Valid:       true,
	}); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	if _, err := BuildReceipt(executor, proposal, proposal.Transition.To, Evidence{
		ID:          "stale-observation",
		Type:        "postgres-observation",
		StateDigest: proposal.Current.Digest,
		Valid:       true,
	}); err == nil {
		t.Fatal("receipt accepted evidence bound to the wrong observed state")
	}
}
