package governedactionnormative

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type d03PublicIncidentCorpus struct {
	SchemaVersion string `json:"schema_version"`
	Status string `json:"status"`
	FrozenContract string `json:"frozen_contract"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	CountsAsD03IndependentValidation bool `json:"counts_as_d03_independent_validation"`
	Incidents []struct {
		ID string `json:"id"`
		SourceRepository string `json:"source_repository"`
		SourceIssue int `json:"source_issue"`
		SourceResolutionPR int `json:"source_resolution_pr"`
		SourceResolutionMerge string `json:"source_resolution_merge"`
		Observed struct {
			SameHeadDiffRerunPassed bool `json:"same_head_diff_rerun_passed"`
		} `json:"observed"`
		CorrectedGroundTruth struct {
			Class string `json:"class"`
			StepsExecuted int `json:"steps_executed"`
			RunnerID int `json:"runner_id"`
			RunnerNameEmpty bool `json:"runner_name_empty"`
		} `json:"corrected_ground_truth"`
		RetryGateExpectation struct {
			Decision string `json:"decision"`
			Precondition string `json:"precondition"`
			ForbiddenInference string `json:"forbidden_inference"`
		} `json:"retry_gate_expectation"`
		SecondaryDefect struct {
			Class string `json:"class"`
			RequiredGateBehavior string `json:"required_gate_behavior"`
		} `json:"secondary_defect"`
		HeldOutCohort bool `json:"held_out_cohort"`
		IndependentParticipant bool `json:"independent_participant"`
	} `json:"incidents"`
	NormativeChange bool `json:"normative_change"`
	RuntimeChange bool `json:"runtime_change"`
}

func TestD03PublicIncidentCorpusPreservesClaimBoundaryAndGroundTruth(t *testing.T) {
	payload, err := os.ReadFile(repoPath("testdata", "governed-action", "d03", "public-incident-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus d03PublicIncidentCorpus
	if err := json.Unmarshal(payload, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != "governed-action.d03-public-incident-corpus/v1" {
		t.Fatalf("unexpected schema %q", corpus.SchemaVersion)
	}
	if corpus.Status != "ACTIVE_CORPUS_EVIDENCE_ONLY" {
		t.Fatalf("unexpected corpus status %q", corpus.Status)
	}
	if corpus.FrozenContract != "candidate-kernel-contract-v1" {
		t.Fatalf("unexpected frozen contract %q", corpus.FrozenContract)
	}
	if corpus.FrozenOracleBlob != "37e2e0a0867fa78df37f9d4243a1c4107d62094b" {
		t.Fatalf("public incident corpus drifted from frozen oracle: %s", corpus.FrozenOracleBlob)
	}
	if corpus.CountsAsD03IndependentValidation {
		t.Fatal("public incident replay must not be counted as D03 independent validation")
	}
	if len(corpus.Incidents) == 0 {
		t.Fatal("public incident corpus must contain at least one incident")
	}

	seen := map[string]bool{}
	foundTortoise := false
	for _, incident := range corpus.Incidents {
		if incident.ID == "" || incident.SourceRepository == "" {
			t.Fatalf("incident identity incomplete: %+v", incident)
		}
		if seen[incident.ID] {
			t.Fatalf("duplicate incident id %s", incident.ID)
		}
		seen[incident.ID] = true
		if strings.HasPrefix(incident.SourceRepository, "achirothmane/") {
			t.Fatalf("public incident source must be externally owned: %s", incident.SourceRepository)
		}
		if incident.HeldOutCohort || incident.IndependentParticipant {
			t.Fatalf("public replay %s must not masquerade as held-out participation", incident.ID)
		}

		if incident.ID != "PIC-0001" {
			continue
		}
		foundTortoise = true
		if incident.SourceRepository != "daniel-ospina/tortoise" ||
			incident.SourceIssue != 3442 ||
			incident.SourceResolutionPR != 5474 ||
			incident.SourceResolutionMerge != "1917852e17ffe741f37ca419c2c433c741112159" {
			t.Fatalf("PIC-0001 source provenance drifted: %+v", incident)
		}
		if !incident.Observed.SameHeadDiffRerunPassed {
			t.Fatal("PIC-0001 must retain the observed fail/rerun-pass signal")
		}
		if incident.CorrectedGroundTruth.Class != "INFRA_TRANSIENT_RUNNER_ACQUISITION_FAILURE" ||
			incident.CorrectedGroundTruth.StepsExecuted != 0 ||
			incident.CorrectedGroundTruth.RunnerID != 0 ||
			!incident.CorrectedGroundTruth.RunnerNameEmpty {
			t.Fatalf("PIC-0001 corrected ground truth drifted: %+v", incident.CorrectedGroundTruth)
		}
		if incident.RetryGateExpectation.Decision != "ALLOW_RERUN_CANDIDATE" ||
			incident.RetryGateExpectation.Precondition != "ZERO_EXECUTION_POSITIVELY_ESTABLISHED" {
			t.Fatalf("PIC-0001 retry rule became broader than the evidence: %+v", incident.RetryGateExpectation)
		}
		if incident.RetryGateExpectation.ForbiddenInference != "RERUN_PASS_IMPLIES_FLAKY_TEST" {
			t.Fatalf("PIC-0001 lost its counterexample: %+v", incident.RetryGateExpectation)
		}
		if incident.SecondaryDefect.Class != "NON_CANONICAL_CHANGED_SET_DERIVATION" ||
			incident.SecondaryDefect.RequiredGateBehavior != "FAIL_CLOSED" {
			t.Fatalf("PIC-0001 secondary defect rule drifted: %+v", incident.SecondaryDefect)
		}
	}
	if !foundTortoise {
		t.Fatal("PIC-0001 tortoise #3442 is missing")
	}
	if corpus.NormativeChange || corpus.RuntimeChange {
		t.Fatalf("public incident corpus must be evidence-only: normative=%v runtime=%v", corpus.NormativeChange, corpus.RuntimeChange)
	}
}
