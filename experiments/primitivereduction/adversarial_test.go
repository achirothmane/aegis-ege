package primitivereduction

import "testing"

func TestAdversarialBoundaryCorpusAcrossDomains(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			base := fixture.new()

			t.Run("stale-evidence", func(t *testing.T) {
				p := fixture.new()
				p.Evidence[0].StateDigest = "sha256:stale"
				got := EvaluateAdmission(p)
				if got.Decision != DecisionDeny || got.Reason != ReasonEvidenceInvalid {
					t.Fatalf("stale evidence must fail closed, got %+v", got)
				}
			})

			t.Run("capability-substitution", func(t *testing.T) {
				p := fixture.new()
				p.Capability.SubjectID = "attacker:substitute"
				got := EvaluateAdmission(p)
				if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
					t.Fatalf("capability substitution must fail binding integrity, got %+v", got)
				}
			})

			t.Run("target-substitution", func(t *testing.T) {
				p := fixture.new()
				p.Capability.TargetKey = "other.namespace:other-target"
				got := EvaluateAdmission(p)
				if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
					t.Fatalf("target substitution must fail binding integrity, got %+v", got)
				}
			})

			t.Run("authority-revoked-before-effect", func(t *testing.T) {
				p := fixture.new()
				p.Current.Facts["policy.revoked"] = "true"
				got := EvaluateAdmission(p)
				if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
					t.Fatalf("revoked authority must fail closed, got %+v", got)
				}
			})

			t.Run("expired-before-effect", func(t *testing.T) {
				p := fixture.new()
				p.Current.Facts["clock.monotonic_tick"] = "999999"
				got := EvaluateAdmission(p)
				if got.Decision != DecisionDeny || got.Reason != ReasonConstraintViolated {
					t.Fatalf("expired authority must fail closed, got %+v", got)
				}
			})

			t.Run("stale-pre-crash-proposal-after-state-advance", func(t *testing.T) {
				p := fixture.new()
				advanced := p.Transition.To
				advanced.Facts = map[string]string{"post_effect": "true"}
				got := EvaluateAtBoundary(p, advanced)
				if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
					t.Fatalf("stale proposal must not cross a changed effect boundary, got %+v", got)
				}
			})

			t.Run("lost-receipt-but-effect-observed", func(t *testing.T) {
				p := fixture.new()
				observation := Observation{
					State: p.Transition.To,
					Evidence: Evidence{
						ID:          "fresh-post-effect",
						Type:        "fresh-observation",
						StateDigest: p.Transition.To.Digest,
						Valid:       true,
					},
				}
				if got := Reconcile(p.Transition, observation); got != ClosureClosed {
					t.Fatalf("fresh exact observation should recover truth after lost receipt, got %s", got)
				}
			})

			t.Run("contradictory-observations", func(t *testing.T) {
				p := fixture.new()
				exact := Observation{
					State: p.Transition.To,
					Evidence: Evidence{
						ID:          "after",
						Type:        "observer-a",
						StateDigest: p.Transition.To.Digest,
						Valid:       true,
					},
				}
				stale := Observation{
					State: p.Current,
					Evidence: Evidence{
						ID:          "before",
						Type:        "observer-b",
						StateDigest: p.Current.Digest,
						Valid:       true,
					},
				}
				if got := ReconcileAll(p.Transition, []Observation{exact, stale}); got != ClosureUnknown {
					t.Fatalf("contradictory observations must remain UNKNOWN, got %s", got)
				}
			})

			t.Run("executor-takeover-preserves-logical-effect-id", func(t *testing.T) {
				first, err := EffectIdentity(base)
				if err != nil {
					t.Fatalf("derive first effect identity: %v", err)
				}
				takeover := fixture.new()
				second, err := EffectIdentity(takeover)
				if err != nil {
					t.Fatalf("derive takeover effect identity: %v", err)
				}
				if first != second {
					t.Fatalf("same logical effect changed identity across executor takeover: %s != %s", first, second)
				}
			})

			t.Run("material-transition-change-changes-effect-id", func(t *testing.T) {
				p := fixture.new()
				first, err := EffectIdentity(p)
				if err != nil {
					t.Fatalf("derive first effect identity: %v", err)
				}
				p.Transition.To.Digest += "-mutated"
				second, err := EffectIdentity(p)
				if err != nil {
					t.Fatalf("derive second effect identity: %v", err)
				}
				if first == second {
					t.Fatal("material transition change must change derived effect identity")
				}
			})
		})
	}
}

func TestDuplicateDeliveryAfterEffectCannotReuseStaleBoundaryState(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			p := fixture.new()

			// First effect has already advanced the world to the expected after-state.
			after := p.Transition.To
			after.Facts = map[string]string{"effect.status": "observed"}

			// A duplicate delivery carrying the pre-effect proposal must be rejected
			// before another effect can escape.
			got := EvaluateAtBoundary(p, after)
			if got.Decision != DecisionDeny || got.Reason != ReasonBindingMismatch {
				t.Fatalf("duplicate stale delivery unexpectedly admitted: %+v", got)
			}
		})
	}
}

func TestMonotonicityStaysWithinStateAndConstraintCandidate(t *testing.T) {
	previous := StateRef{
		Namespace: "runtime.clock",
		ObjectID:  "host-7",
		Version:   "sample:1",
		Digest:    "sha256:clock-1",
		Facts: map[string]string{
			"boot_id":              "boot-A",
			"clock.monotonic_tick": "100",
		},
	}
	relation := StateRelation{
		Fact:      "clock.monotonic_tick",
		Op:        OpGreaterOrEqualInt,
		ScopeFact: "boot_id",
	}

	t.Run("forward-on-same-boot", func(t *testing.T) {
		current := StateRef{
			Namespace: previous.Namespace,
			ObjectID:  previous.ObjectID,
			Version:   "sample:2",
			Digest:    "sha256:clock-2",
			Facts: map[string]string{
				"boot_id":              "boot-A",
				"clock.monotonic_tick": "140",
			},
		}
		ok, known := EvaluateStateRelation(previous, current, relation)
		if !known || !ok {
			t.Fatalf("forward monotonic relation should hold, ok=%v known=%v", ok, known)
		}
	})

	t.Run("rollback-on-same-boot", func(t *testing.T) {
		current := StateRef{
			Namespace: previous.Namespace,
			ObjectID:  previous.ObjectID,
			Version:   "sample:2",
			Digest:    "sha256:clock-rollback",
			Facts: map[string]string{
				"boot_id":              "boot-A",
				"clock.monotonic_tick": "99",
			},
		}
		ok, known := EvaluateStateRelation(previous, current, relation)
		if !known || ok {
			t.Fatalf("rollback must be known false, ok=%v known=%v", ok, known)
		}
	})

	t.Run("boot-change-is-not-comparable", func(t *testing.T) {
		current := StateRef{
			Namespace: previous.Namespace,
			ObjectID:  previous.ObjectID,
			Version:   "sample:2",
			Digest:    "sha256:clock-new-boot",
			Facts: map[string]string{
				"boot_id":              "boot-B",
				"clock.monotonic_tick": "1",
			},
		}
		ok, known := EvaluateStateRelation(previous, current, relation)
		if known || ok {
			t.Fatalf("cross-boot monotonic relation must be unknown, ok=%v known=%v", ok, known)
		}
	})
}

func TestNoSeventhPrimitiveAddedByAdversarialHelpers(t *testing.T) {
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("adversarial helpers accidentally expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{"time", "object", "effect_identity", "receipt", "authority", "lease"} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain derived in this experiment", forbidden)
			}
		}
	}
}
