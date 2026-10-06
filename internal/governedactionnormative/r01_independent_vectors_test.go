package governedactionnormative

import "testing"

// Each R01 vector is executed as an independent falsification experiment.
// No vector may borrow state or a verdict from another vector.
type r01Vector struct {
	id       string
	expected string
	world    r01World
	assert   func(*testing.T, r01Decision)
}

func r01IndependentVectors() []r01Vector {
	noSuccess := func(want string) func(*testing.T, r01Decision) {
		return func(t *testing.T, d r01Decision) {
			t.Helper()
			if d.compoundSuccess || d.disposition != want {
				t.Fatalf("unexpected decision: %+v; want disposition=%s and no compound success", d, want)
			}
		}
	}
	return []r01Vector{
		{
			id: "R01-01", expected: "E2_POSSIBLE_REPLAY_BLOCKED",
			world: r01World{possibleE2: true, replayE2: true, authorityCurrent: true, takeoverExclusive: true, e1StillExact: true},
			assert: func(t *testing.T, d r01Decision) {
				if d.replayBlocked || d.compoundSuccess || d.disposition != "REJECT_SECOND_EFFECT" {
					t.Fatalf("blind replay not exposed: %+v", d)
				}
			},
		},
		{
			id: "R01-02", expected: "NO_SILENT_AUTHORITY_REUSE",
			world: r01World{authorityCurrent: false, takeoverExclusive: true, e1StillExact: true},
			assert: noSuccess("REJECT_BEFORE_EFFECT"),
		},
		{
			id: "R01-03", expected: "E3_BLOCKED_UNLESS_CURRENT_EXCLUSIVITY_AND_AUTHORITY",
			world: r01World{authorityCurrent: true, takeoverExclusive: false, staleWorkerE3: true, e1StillExact: true},
			assert: func(t *testing.T, d r01Decision) {
				if d.staleE3Blocked || d.compoundSuccess || d.disposition != "REJECT_BEFORE_EFFECT" {
					t.Fatalf("stale worker attempt was not exposed: %+v", d)
				}
			},
		},
		{
			id: "R01-04", expected: "NO_DUPLICATE_EFFECT_OR_FALSE_CERTAINTY",
			world: r01World{authorityCurrent: true, takeoverExclusive: true, duplicateObservation: true, e1StillExact: true},
			assert: noSuccess("UNKNOWN"),
		},
		{
			id: "R01-05", expected: "VALUE_EQUALITY_NOT_EXACT_EFFECT_PROOF",
			world: r01World{authorityCurrent: true, takeoverExclusive: true, aggregateValueMatches: true, exactE2LineageObserved: false, e1StillExact: true},
			assert: noSuccess("UNKNOWN"),
		},
		{
			id: "R01-06", expected: "NO_COMPOUND_SUCCESS",
			world: r01World{authorityCurrent: true, takeoverExclusive: true, exactE2LineageObserved: true, e1StillExact: false, exactPostcondition: true},
			assert: noSuccess("OPEN"),
		},
		{
			id: "R01-07", expected: "NO_FALSE_VERIFIED",
			world: r01World{authorityCurrent: true, takeoverExclusive: true, conflictingObservations: true, e1StillExact: true},
			assert: noSuccess("UNKNOWN"),
		},
		{
			id: "R01-08", expected: "USEFUL_EFFECTS_PERMITTED_AND_EXACT_POSTCONDITION_REQUIRED",
			world: r01World{authorityCurrent: true, takeoverExclusive: true, exactE2LineageObserved: true, e1StillExact: true, exactPostcondition: true, clean: true},
			assert: func(t *testing.T, d r01Decision) {
				if !d.compoundSuccess || !d.useful || d.disposition != "CLOSED_VERIFIED" {
					t.Fatalf("clean control was denied or falsely classified: %+v", d)
				}
			},
		},
	}
}

func TestR01VectorsExecuteIndependentlyAndMatchFrozenFixture(t *testing.T) {
	f := loadR01(t)
	vectors := r01IndependentVectors()
	if len(vectors) != len(f.Attacks) {
		t.Fatalf("vector count=%d fixture count=%d", len(vectors), len(f.Attacks))
	}
	seen := map[string]bool{}
	for i, v := range vectors {
		v := v
		if seen[v.id] {
			t.Fatalf("duplicate vector %s", v.id)
		}
		seen[v.id] = true
		if f.Attacks[i].ID != v.id || f.Attacks[i].Expected != v.expected {
			t.Fatalf("vector/fixture drift at %d: vector=%s/%s fixture=%s/%s", i, v.id, v.expected, f.Attacks[i].ID, f.Attacks[i].Expected)
		}
		t.Run(v.id, func(t *testing.T) {
			d := evaluateR01(v.world)
			v.assert(t, d)
		})
	}
}
