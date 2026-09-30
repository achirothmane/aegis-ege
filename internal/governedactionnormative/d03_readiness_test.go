package governedactionnormative

import (
	"encoding/json"
	"os"
	"testing"
)

type d03ReadinessRecord struct {
	SchemaVersion string `json:"schema_version"`
	Status string `json:"status"`
	FrozenContract string `json:"frozen_contract"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	PrerequisiteEvidence []struct {
		ID string `json:"id"`
		Status string `json:"status"`
	} `json:"prerequisite_evidence"`
	OperationalPrerequisite struct {
		Satisfied bool `json:"satisfied"`
	} `json:"operational_prerequisite"`
	CohortSelection struct {
		Selected bool `json:"selected"`
	} `json:"cohort_selection"`
	NormativeChange bool `json:"normative_change"`
	RuntimeChange bool `json:"runtime_change"`
}

func TestD03ReadinessRemainsBlockedUntilIndependentCohortIsRecorded(t *testing.T) {
	payload, err := os.ReadFile(repoPath("testdata", "governed-action", "d03", "readiness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record d03ReadinessRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != "governed-action.d03-readiness/v1" {
		t.Fatalf("unexpected schema %q", record.SchemaVersion)
	}
	if record.Status != "BLOCKED_UNSTARTED" {
		t.Fatalf("D03 status = %q, want BLOCKED_UNSTARTED", record.Status)
	}
	if record.FrozenContract != "candidate-kernel-contract-v1" {
		t.Fatalf("unexpected frozen contract %q", record.FrozenContract)
	}
	if record.FrozenOracleBlob != "37e2e0a0867fa78df37f9d4243a1c4107d62094b" {
		t.Fatalf("D03 readiness drifted from frozen oracle: %s", record.FrozenOracleBlob)
	}
	want := map[string]bool{"K06":false,"K07":false,"D00":false,"D01":false,"D02":false}
	for _, item := range record.PrerequisiteEvidence {
		if _, ok := want[item.ID]; ok && item.Status == "COMPLETE" {
			want[item.ID] = true
		}
	}
	for id, complete := range want {
		if !complete {
			t.Fatalf("D03 readiness is missing completed prerequisite %s", id)
		}
	}
	if record.OperationalPrerequisite.Satisfied {
		t.Fatal("D03 readiness must not claim an independent participant before cohort selection")
	}
	if record.CohortSelection.Selected {
		t.Fatal("D03 readiness unexpectedly selected a cohort")
	}
	if record.NormativeChange || record.RuntimeChange {
		t.Fatalf("readiness gate must be evidence-only: normative=%v runtime=%v", record.NormativeChange, record.RuntimeChange)
	}
}
