package governedactionnormative

import (
	"encoding/json"
	"os"
	"testing"
)

type r02EvidenceK07 struct {
	SchemaVersion string `json:"schema_version"`
	FailureDomains struct {
		Distinct bool `json:"distinct"`
	} `json:"failure_domains"`
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
		StaleStatus        int `json:"stale_status"`
		TargetDurableRows  int `json:"target_durable_rows"`
		ControlDurableRows int `json:"control_durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

func TestR02NativeFactsProjectOntoFrozenRelations(t *testing.T) {
	path := os.Getenv("GOSMIG_R02_EVIDENCE")
	if path == "" {
		t.Skip("R02 native evidence is produced by the PostgreSQL workflow")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev r02EvidenceK07
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SchemaVersion != "governed-action.r02-failure-domains/v1" ||
		!ev.FailureDomains.Distinct ||
		ev.E1.FinalState != "REVERSED" ||
		ev.E2.APIValue != "NOT_CAPTURED" ||
		ev.E2.AggregateCapturedAmount != ev.Amount ||
		ev.E2.UnrelatedEffectID == ev.E2.EffectID ||
		ev.E3.TargetDurableRows != 0 ||
		ev.E3.ControlDurableRows != 1 ||
		ev.ExactPostcondition {
		t.Fatalf("R02 native evidence lost required facts: %+v", ev)
	}

	set := loadK07ExecutionSet(t)
	byID := map[string]k07ExecutableCase{}
	for _, tc := range set.Cases {
		byID[tc.CaseID] = tc
	}

	for caseID, want := range map[string]string{
		"CE6-R1-stale-worker-after-takeover":       "REJECT_TAKEOVER_EFFECT",
		"CE7-R1-unrelated-change-as-success":       "REJECT_FALSE_VERIFIED",
		"CE10-R1-required-independence-unknown":    "DEFER_INSUFFICIENT_INDEPENDENCE",
	} {
		tc, ok := byID[caseID]
		if !ok {
			t.Fatalf("frozen relation %s missing", caseID)
		}
		got := evaluateK07(tc)
		if got.Disposition != want || got.UnauthorizedEffects != 0 {
			t.Fatalf("%s drifted: %+v want disposition=%s", caseID, got, want)
		}
	}
}
