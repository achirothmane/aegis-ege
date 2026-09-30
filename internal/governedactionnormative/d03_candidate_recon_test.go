package governedactionnormative

import (
	"encoding/json"
	"os"
	"testing"
)

type d03CandidateRecon struct {
	SchemaVersion string `json:"schema_version"`
	Status string `json:"status"`
	FrozenContract string `json:"frozen_contract"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	SelectionStatus string `json:"selection_status"`
	Candidates []struct {
		Repository string `json:"repository"`
		Owner string `json:"owner"`
		ParticipationStatus string `json:"participation_status"`
		Selected bool `json:"selected"`
	} `json:"candidates"`
	NormativeChange bool `json:"normative_change"`
	RuntimeChange bool `json:"runtime_change"`
}

func TestD03CandidateReconDoesNotSelectOrConsumeHeldOutCohort(t *testing.T) {
	payload, err := os.ReadFile(repoPath("testdata", "governed-action", "d03", "candidate-recon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record d03CandidateRecon
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != "governed-action.d03-candidate-recon/v1" {
		t.Fatalf("unexpected schema %q", record.SchemaVersion)
	}
	if record.Status != "RECRUITMENT_RECON_ONLY" {
		t.Fatalf("candidate recon status = %q", record.Status)
	}
	if record.FrozenContract != "candidate-kernel-contract-v1" {
		t.Fatalf("unexpected frozen contract %q", record.FrozenContract)
	}
	if record.FrozenOracleBlob != "37e2e0a0867fa78df37f9d4243a1c4107d62094b" {
		t.Fatalf("candidate recon drifted from frozen oracle: %s", record.FrozenOracleBlob)
	}
	if record.SelectionStatus != "NONE_SELECTED" {
		t.Fatalf("candidate recon unexpectedly selected a cohort: %s", record.SelectionStatus)
	}
	if len(record.Candidates) == 0 {
		t.Fatal("candidate recon must contain at least one recruitment candidate")
	}
	seen := map[string]bool{}
	for _, candidate := range record.Candidates {
		if candidate.Repository == "" || candidate.Owner == "" {
			t.Fatalf("candidate identity incomplete: %+v", candidate)
		}
		if seen[candidate.Repository] {
			t.Fatalf("duplicate candidate %s", candidate.Repository)
		}
		seen[candidate.Repository] = true
		if candidate.Selected {
			t.Fatalf("candidate %s is marked selected before participation", candidate.Repository)
		}
		if candidate.ParticipationStatus != "NOT_CONTACTED_NOT_CONFIRMED" {
			t.Fatalf("candidate %s participation status = %q", candidate.Repository, candidate.ParticipationStatus)
		}
	}
	if record.NormativeChange || record.RuntimeChange {
		t.Fatalf("candidate recon must be evidence-only: normative=%v runtime=%v", record.NormativeChange, record.RuntimeChange)
	}
}
