package governedactionnormative

import (
	"encoding/json"
	"os"
	"testing"
)

type r01E2EK07Evidence struct {
	SchemaVersion string `json:"schema_version"`
	E1 struct {
		FinalState string `json:"final_state"`
	} `json:"e1"`
	E2 struct {
		EffectID                string `json:"effect_id"`
		APIValue                string `json:"api_value"`
		UnrelatedEffectID       string `json:"unrelated_effect_id"`
		AggregateCapturedAmount int64  `json:"aggregate_captured_amount"`
	} `json:"e2"`
	Amount int64 `json:"amount"`
	E3 struct {
		StaleAttemptExits []int `json:"stale_attempt_exits"`
		DurableRows       int   `json:"durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

func TestR01EndToEndNativeFactsProjectOntoFrozenK07(t *testing.T) {
	path := os.Getenv("GOSMIG_R01_E2E_EVIDENCE")
	if path == "" {
		t.Skip("native R01 end-to-end evidence is produced by the PostgreSQL workflow")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev r01E2EK07Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SchemaVersion != "governed-action.r01-end-to-end/v1" {
		t.Fatalf("unexpected evidence schema %q", ev.SchemaVersion)
	}
	if ev.E1.FinalState != "REVERSED" ||
		ev.E2.APIValue != "NOT_CAPTURED" ||
		ev.E2.AggregateCapturedAmount != ev.Amount ||
		ev.E2.UnrelatedEffectID == ev.E2.EffectID ||
		ev.E3.DurableRows != 0 ||
		ev.ExactPostcondition {
		t.Fatalf("whole-trace evidence lost falsification facts: %+v", ev)
	}
	if len(ev.E3.StaleAttemptExits) != 2 || ev.E3.StaleAttemptExits[0] != 41 || ev.E3.StaleAttemptExits[1] != 41 {
		t.Fatalf("stale callbacks were not blocked before E3: %+v", ev.E3)
	}

	set := loadK07ExecutionSet(t)
	byID := map[string]k07ExecutableCase{}
	for _, tc := range set.Cases {
		byID[tc.CaseID] = tc
	}

	falseVerified, ok := byID["CE7-R1-unrelated-change-as-success"]
	if !ok {
		t.Fatal("frozen CE7 false-verification relation missing")
	}
	got := evaluateK07(falseVerified)
	if got.Disposition != "REJECT_FALSE_VERIFIED" || got.UnauthorizedEffects != 0 {
		t.Fatalf("frozen exact-postcondition relation drifted: %+v", got)
	}

	staleTakeover, ok := byID["CE6-R1-stale-worker-after-takeover"]
	if !ok {
		t.Fatal("frozen CE6 stale-worker relation missing")
	}
	got = evaluateK07(staleTakeover)
	if got.Disposition != "REJECT_TAKEOVER_EFFECT" || got.UnauthorizedEffects != 0 {
		t.Fatalf("frozen takeover relation drifted: %+v", got)
	}
}
