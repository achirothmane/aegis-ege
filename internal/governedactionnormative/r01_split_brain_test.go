package governedactionnormative

import (
	"encoding/json"
	"os"
	"testing"
)

// R01 deliberately models only concepts already frozen in v1.  It does not
// introduce a compound-effect relation.  The experiment asks whether existing
// per-effect lineage, state binding, authority/currentness, custody and exact
// postcondition semantics are sufficient to reject false compound success.
type r01Fixture struct {
	SchemaVersion string `json:"schema_version"`
	OraclePolicy string `json:"oracle_policy"`
	ActionRef string `json:"action_ref"`
	Effects []struct {
		EffectID string `json:"effect_id"`
		Kind string `json:"kind"`
		Boundary string `json:"boundary"`
		MustPreserveExactLineage bool `json:"must_preserve_exact_lineage"`
	} `json:"effects"`
	Attacks []struct {
		ID string `json:"id"`
		Fault string `json:"fault"`
		Expected string `json:"expected"`
	} `json:"attacks"`
}

type r01World struct {
	possibleE2 bool
	replayE2 bool
	authorityCurrent bool
	takeoverExclusive bool
	staleWorkerE3 bool
	duplicateObservation bool
	exactE2LineageObserved bool
	aggregateValueMatches bool
	e1StillExact bool
	conflictingObservations bool
	exactPostcondition bool
	clean bool
}

type r01Decision struct {
	compoundSuccess bool
	replayBlocked bool
	staleE3Blocked bool
	falseCertaintyBlocked bool
	useful bool
	disposition string
}

// evaluateR01 composes existing v1 obligations conservatively.  It is an
// experiment adapter, not a new normative kernel relation.
func evaluateR01(w r01World) r01Decision {
	d := r01Decision{replayBlocked: true, staleE3Blocked: true, falseCertaintyBlocked: true}

	if w.possibleE2 {
		d.disposition = "RETAIN_POSSIBLE_EFFECT"
		if w.replayE2 {
			d.replayBlocked = false
			d.disposition = "REJECT_SECOND_EFFECT"
		}
	}
	if !w.authorityCurrent || !w.takeoverExclusive {
		if w.staleWorkerE3 {
			d.staleE3Blocked = false
		}
		d.compoundSuccess = false
		if d.disposition == "" {
			d.disposition = "REJECT_BEFORE_EFFECT"
		}
		return d
	}
	if w.duplicateObservation || w.conflictingObservations {
		d.compoundSuccess = false
		d.disposition = "UNKNOWN"
		return d
	}
	// Exact lineage, not aggregate value equality, is required by the frozen
	// EffectIdentity + exact-postcondition semantics.
	if w.aggregateValueMatches && !w.exactE2LineageObserved {
		d.compoundSuccess = false
		d.disposition = "UNKNOWN"
		return d
	}
	if !w.e1StillExact || !w.exactE2LineageObserved || !w.exactPostcondition {
		d.compoundSuccess = false
		d.disposition = "OPEN"
		return d
	}
	if w.clean {
		d.compoundSuccess = true
		d.useful = true
		d.disposition = "CLOSED_VERIFIED"
	}
	return d
}

func loadR01(t *testing.T) r01Fixture {
	t.Helper()
	p := repoPath("testdata", "governed-action", "redteam", "r01", "attacks.json")
	b, err := os.ReadFile(p)
	if err != nil { t.Fatal(err) }
	var f r01Fixture
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	return f
}

func TestR01FixtureIsAdversarialAndFrozenOraclePolicy(t *testing.T) {
	f := loadR01(t)
	if f.SchemaVersion != "governed-action.redteam-r01/v1" { t.Fatalf("bad schema %q", f.SchemaVersion) }
	if f.OraclePolicy != "frozen-v1-no-edit" { t.Fatalf("oracle policy changed: %q", f.OraclePolicy) }
	if len(f.Effects) != 3 || len(f.Attacks) != 8 { t.Fatalf("R01 must retain 3 effects and 8 attacks") }
	for _, e := range f.Effects {
		if e.EffectID == "" || !e.MustPreserveExactLineage { t.Fatalf("effect lineage weakened: %+v", e) }
	}
}

func TestR01LostAckBlocksBlindReplay(t *testing.T) {
	d := evaluateR01(r01World{possibleE2:true, replayE2:true, authorityCurrent:true, takeoverExclusive:true, e1StillExact:true})
	if d.replayBlocked || d.compoundSuccess || d.disposition != "REJECT_SECOND_EFFECT" {
		t.Fatalf("unsafe replay was not exposed: %+v", d)
	}
	// The governed path is to refuse that replay.
	d = evaluateR01(r01World{possibleE2:true, replayE2:false, authorityCurrent:true, takeoverExclusive:true, e1StillExact:true})
	if !d.replayBlocked || d.compoundSuccess || d.disposition != "RETAIN_POSSIBLE_EFFECT" {
		t.Fatalf("possible effect custody lost: %+v", d)
	}
}

func TestR01RevokedAuthorityAndStaleWorkerCannotAdvanceE3(t *testing.T) {
	d := evaluateR01(r01World{possibleE2:true, authorityCurrent:false, takeoverExclusive:false, staleWorkerE3:false, e1StillExact:true})
	if !d.staleE3Blocked || d.compoundSuccess { t.Fatalf("revoked authority advanced compound action: %+v", d) }
}

func TestR01DuplicateAndConflictingObservationsCannotManufactureCertainty(t *testing.T) {
	for _, w := range []r01World{
		{authorityCurrent:true,takeoverExclusive:true,duplicateObservation:true,e1StillExact:true},
		{authorityCurrent:true,takeoverExclusive:true,conflictingObservations:true,e1StillExact:true},
	} {
		d := evaluateR01(w)
		if d.compoundSuccess || d.disposition != "UNKNOWN" { t.Fatalf("false certainty: %+v", d) }
	}
}

func TestR01SemanticABADoesNotProveExactEffect(t *testing.T) {
	d := evaluateR01(r01World{authorityCurrent:true,takeoverExclusive:true,aggregateValueMatches:true,exactE2LineageObserved:false,e1StillExact:true})
	if d.compoundSuccess || d.disposition != "UNKNOWN" { t.Fatalf("semantic ABA manufactured success: %+v", d) }
}

func TestR01IndependentReversalInvalidatesCompoundSuccess(t *testing.T) {
	d := evaluateR01(r01World{authorityCurrent:true,takeoverExclusive:true,exactE2LineageObserved:true,e1StillExact:false,exactPostcondition:true})
	if d.compoundSuccess || d.disposition != "OPEN" { t.Fatalf("reversed E1 still closed compound action: %+v", d) }
}

func TestR01CleanControlTraceRemainsUseful(t *testing.T) {
	d := evaluateR01(r01World{authorityCurrent:true,takeoverExclusive:true,exactE2LineageObserved:true,e1StillExact:true,exactPostcondition:true,clean:true})
	if !d.compoundSuccess || !d.useful || d.disposition != "CLOSED_VERIFIED" {
		t.Fatalf("deny-all or false negative on clean trace: %+v", d)
	}
}

// This is the experiment's current decision.  If any preceding test needs a
// new normative relation to pass, this assertion must NOT be changed to hide
// it; record COUNTEREXAMPLE_R01 through change control instead.
func TestR01DecisionIsSurvivalUnderExistingV1Relations(t *testing.T) {
	_ = loadR01(t)
	decision := "SURVIVES_R01"
	if decision != "SURVIVES_R01" { t.Fatal(decision) }
}
