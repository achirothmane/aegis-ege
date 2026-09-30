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
			SameRepositoryCommitPriorPassThenRerunFailed bool `json:"same_repository_commit_prior_pass_then_rerun_failed"`
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
		Repair struct {
			ProductBehaviorChanged *bool `json:"product_behavior_changed"`
			TTLBeforeMS int `json:"ttl_before_ms"`
			TTLAfterSeconds int `json:"ttl_after_seconds"`
			VerificationConsecutivePasses int `json:"verification_consecutive_passes"`
		} `json:"repair"`
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

	type expectedIncident struct {
		repo string
		issue int
		pr int
		merge string
		class string
		decision string
		precondition string
		forbidden string
	}
	expected := map[string]expectedIncident{
		"PIC-0001": {
			repo: "daniel-ospina/tortoise",
			issue: 3442,
			pr: 5474,
			merge: "1917852e17ffe741f37ca419c2c433c741112159",
			class: "INFRA_TRANSIENT_RUNNER_ACQUISITION_FAILURE",
			decision: "ALLOW_RERUN_CANDIDATE",
			precondition: "ZERO_EXECUTION_POSITIVELY_ESTABLISHED",
			forbidden: "RERUN_PASS_IMPLIES_FLAKY_TEST",
		},
		"PIC-0002": {
			repo: "lidge-jun/opencodex",
			issue: 1563,
			pr: 1575,
			merge: "be3597ff2db1c2941ff15d04f65f1bfc6389c4a3",
			class: "TEST_HARNESS_TIMEOUT_MARGIN",
			decision: "ALLOW_BOUNDED_RERUN_CANDIDATE",
			precondition: "KNOWN_TEST_HARNESS_TIMEOUT_SIGNATURE_WITH_NO_PRODUCT_FAILURE_EVIDENCE",
			forbidden: "RERUN_PASS_ALONE_PROVES_TEST_FLAKE",
		},
		"PIC-0003": {
			repo: "herdrdev/herdr",
			issue: 3451,
			pr: 3453,
			merge: "69585b01d0297b50e302c98f883d705dec92834d",
			class: "TEST_FIXTURE_WALL_CLOCK_RACE",
			decision: "ALLOW_BOUNDED_RERUN_CANDIDATE",
			precondition: "KNOWN_FIXTURE_RACE_SIGNATURE_WITH_NO_PRODUCT_FAILURE_EVIDENCE",
			forbidden: "SAME_COMMIT_RERUN_PASS_IS_SUFFICIENT_CLASSIFICATION",
		},
		"PIC-0004": {
			repo: "frappe/draw",
			issue: 546,
			pr: 547,
			merge: "affaabd607bfec327867d3c170b81bb2f9bfdf3d",
			class: "ENVIRONMENT_DEPENDENCY_DRIFT",
			decision: "HOLD_REQUIRES_INPUT_PROVENANCE",
			precondition: "RECONSTRUCT_OR_PIN_EXTERNAL_EXECUTION_INPUTS_BEFORE_CLASSIFYING",
			forbidden: "SAME_REPOSITORY_COMMIT_IMPLIES_SAME_EXECUTION_INPUTS",
		},
	}
	if len(corpus.Incidents) < len(expected) {
		t.Fatalf("public incident corpus has %d incidents, want at least %d", len(corpus.Incidents), len(expected))
	}

	seenIDs := map[string]bool{}
	seenExpected := map[string]bool{}
	for _, incident := range corpus.Incidents {
		if incident.ID == "" || incident.SourceRepository == "" {
			t.Fatalf("incident identity incomplete: %+v", incident)
		}
		if seenIDs[incident.ID] {
			t.Fatalf("duplicate incident id %s", incident.ID)
		}
		seenIDs[incident.ID] = true
		if strings.HasPrefix(incident.SourceRepository, "achirothmane/") {
			t.Fatalf("public incident source must be externally owned: %s", incident.SourceRepository)
		}
		if incident.HeldOutCohort || incident.IndependentParticipant {
			t.Fatalf("public replay %s must not masquerade as held-out participation", incident.ID)
		}

		want, ok := expected[incident.ID]
		if !ok {
			continue
		}
		seenExpected[incident.ID] = true
		if incident.SourceRepository != want.repo ||
			incident.SourceIssue != want.issue ||
			incident.SourceResolutionPR != want.pr ||
			incident.SourceResolutionMerge != want.merge {
			t.Fatalf("%s source provenance drifted: %+v", incident.ID, incident)
		}
		if incident.CorrectedGroundTruth.Class != want.class {
			t.Fatalf("%s class = %q, want %q", incident.ID, incident.CorrectedGroundTruth.Class, want.class)
		}
		if incident.RetryGateExpectation.Decision != want.decision ||
			incident.RetryGateExpectation.Precondition != want.precondition ||
			incident.RetryGateExpectation.ForbiddenInference != want.forbidden {
			t.Fatalf("%s retry expectation drifted: %+v", incident.ID, incident.RetryGateExpectation)
		}

		switch incident.ID {
		case "PIC-0001":
			if !incident.Observed.SameHeadDiffRerunPassed ||
				incident.CorrectedGroundTruth.StepsExecuted != 0 ||
				incident.CorrectedGroundTruth.RunnerID != 0 ||
				!incident.CorrectedGroundTruth.RunnerNameEmpty {
				t.Fatalf("PIC-0001 zero-execution evidence drifted: %+v", incident)
			}
			if incident.SecondaryDefect.Class != "NON_CANONICAL_CHANGED_SET_DERIVATION" ||
				incident.SecondaryDefect.RequiredGateBehavior != "FAIL_CLOSED" {
				t.Fatalf("PIC-0001 secondary defect rule drifted: %+v", incident.SecondaryDefect)
			}
		case "PIC-0002":
			if !incident.Observed.SameHeadDiffRerunPassed {
				t.Fatal("PIC-0002 must retain the same-commit fail/rerun-pass signal")
			}
			if incident.Repair.ProductBehaviorChanged == nil || *incident.Repair.ProductBehaviorChanged {
				t.Fatal("PIC-0002 must record that product behavior was unchanged")
			}
		case "PIC-0003":
			if !incident.Observed.SameHeadDiffRerunPassed ||
				incident.Repair.TTLBeforeMS != 1 ||
				incident.Repair.TTLAfterSeconds != 60 ||
				incident.Repair.VerificationConsecutivePasses != 100 {
				t.Fatalf("PIC-0003 fixture-race evidence drifted: %+v", incident)
			}
		case "PIC-0004":
			if !incident.Observed.SameRepositoryCommitPriorPassThenRerunFailed {
				t.Fatal("PIC-0004 must retain the same-repository-commit pass-then-fail signal")
			}
		}
	}
	for id := range expected {
		if !seenExpected[id] {
			t.Fatalf("expected public incident %s is missing", id)
		}
	}
	if corpus.NormativeChange || corpus.RuntimeChange {
		t.Fatalf("public incident corpus must be evidence-only: normative=%v runtime=%v", corpus.NormativeChange, corpus.RuntimeChange)
	}
}
