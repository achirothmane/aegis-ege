package governedactionnormative

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

type d02ScheduleSet struct {
	SchemaVersion string        `json:"schema_version"`
	FrozenContract string       `json:"frozen_contract"`
	FrozenOracleBlob string      `json:"frozen_oracle_blob"`
	Schedules []d02Schedule      `json:"schedules"`
}

type d02Schedule struct {
	ID             string   `json:"id"`
	Counterexample string   `json:"counterexample"`
	Domain         string   `json:"domain"`
	Fault          string   `json:"fault"`
	Expected       string   `json:"expected"`
	Test           string   `json:"test"`
	Tests          []string `json:"tests"`
}

func TestD02FaultScheduleIsPinnedAndCoversCE3ThroughCE8(t *testing.T) {
	payload, err := os.ReadFile(repoPath("testdata", "governed-action", "d02", "fault-schedules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set d02ScheduleSet
	if err := json.Unmarshal(payload, &set); err != nil {
		t.Fatal(err)
	}
	if set.SchemaVersion != "governed-action.d02-fault-schedules/v1" {
		t.Fatalf("unexpected D02 schedule version %q", set.SchemaVersion)
	}
	if set.FrozenContract != "candidate-kernel-contract-v1" {
		t.Fatalf("unexpected D02 frozen contract %q", set.FrozenContract)
	}
	if set.FrozenOracleBlob != "37e2e0a0867fa78df37f9d4243a1c4107d62094b" {
		t.Fatalf("D02 schedule drifted from frozen oracle: %s", set.FrozenOracleBlob)
	}

	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, item := range set.Schedules {
		if item.ID == "" || ids[item.ID] {
			t.Fatalf("missing or duplicate D02 schedule id %q", item.ID)
		}
		ids[item.ID] = true
		if item.Domain == "" || item.Fault == "" || item.Expected == "" {
			t.Fatalf("incomplete D02 schedule %+v", item)
		}
		if item.Test == "" && len(item.Tests) == 0 {
			t.Fatalf("D02 schedule %s has no executable evidence reference", item.ID)
		}
		if item.Counterexample != "" {
			seen[item.Counterexample] = true
		}
	}

	got := make([]string, 0, len(seen))
	for id := range seen {
		got = append(got, id)
	}
	sort.Strings(got)
	want := []string{"CE3", "CE4", "CE5", "CE6", "CE7", "CE8"}
	if len(got) != len(want) {
		t.Fatalf("D02 CE coverage = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("D02 CE coverage = %v, want %v", got, want)
		}
	}
}
