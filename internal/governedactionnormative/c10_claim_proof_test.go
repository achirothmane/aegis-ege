package governedactionnormative

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

type c10EvidenceRef struct {
	Repo  string `json:"repo"`
	PR    int    `json:"pr"`
	Merge string `json:"merge"`
}

type c10Repair struct {
	ID       string           `json:"id"`
	Claim    string           `json:"claim"`
	Evidence []c10EvidenceRef `json:"evidence"`
	Status   string           `json:"status"`
}

type c10BranchControl struct {
	Repo          string `json:"repo"`
	Branch        string `json:"branch"`
	Protected     bool   `json:"protected"`
	RulesetsCount int    `json:"rulesets_count"`
}

type c10OpenPRExclusion struct {
	Repo                    string `json:"repo"`
	PRs                     []int  `json:"prs"`
	CountedAsMainCapability bool   `json:"counted_as_main_capability"`
}

type c10ClaimCorrection struct {
	Target string `json:"target"`
	PR     int    `json:"pr"`
	Head   string `json:"head"`
	Merge  string `json:"merge"`
	Merged *bool  `json:"merged"`
}

type c10ClaimProofRecord struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	Scope         struct {
		CompletedCorrectnessItems []string `json:"completed_correctness_items"`
		NoArchitectureChange      bool     `json:"no_architecture_change"`
		NoRepositorySettingsChange bool    `json:"no_repository_settings_change"`
		NoDistributionClaim       bool     `json:"no_distribution_claim"`
	} `json:"scope"`
	CurrentHeads       map[string]string `json:"current_heads"`
	Repairs            []c10Repair       `json:"repairs"`
	BranchControlAudit struct {
		Repositories []c10BranchControl `json:"repositories"`
		Conclusion   string             `json:"conclusion"`
	} `json:"branch_control_audit"`
	ClaimCorrections []c10ClaimCorrection `json:"claim_corrections"`
	OpenPRExclusions []c10OpenPRExclusion `json:"open_pr_exclusions"`
	CompletionGate   struct {
		AllMaterialClaimsSupportedOrCorrected bool     `json:"all_material_claims_supported_or_corrected"`
		PendingClaimPRs                       []string `json:"pending_claim_prs"`
	} `json:"completion_gate"`
	NormativeChange bool `json:"normative_change"`
	RuntimeChange   bool `json:"runtime_change"`
}

func loadC10ClaimProofRecord(t *testing.T) c10ClaimProofRecord {
	t.Helper()
	payload, err := os.ReadFile(repoPath("testdata", "governed-action", "c10", "claim-proof-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record c10ClaimProofRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestC10ClaimProofMatrixPinsMergedRepairEvidence(t *testing.T) {
	record := loadC10ClaimProofRecord(t)
	if record.SchemaVersion != "governed-action.c10-claim-proof-provenance/v1" {
		t.Fatalf("unexpected C10 schema %q", record.SchemaVersion)
	}
	if record.Status != "COMPLETE" {
		t.Fatalf("C10 status = %q, want COMPLETE after claim-correction PRs merge", record.Status)
	}
	if !record.Scope.NoArchitectureChange || !record.Scope.NoRepositorySettingsChange || !record.Scope.NoDistributionClaim {
		t.Fatalf("C10 scope widened unexpectedly: %+v", record.Scope)
	}

	want := []string{"C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09"}
	got := append([]string(nil), record.Scope.CompletedCorrectnessItems...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("completed correctness items = %v, want %v", got, want)
	}

	seen := map[string]bool{}
	for _, repair := range record.Repairs {
		if repair.ID == "" || seen[repair.ID] {
			t.Fatalf("missing/duplicate repair id %q", repair.ID)
		}
		seen[repair.ID] = true
		if repair.Status != "MERGED_EVIDENCE" {
			t.Fatalf("%s status = %q", repair.ID, repair.Status)
		}
		if strings.TrimSpace(repair.Claim) == "" || len(repair.Evidence) == 0 {
			t.Fatalf("%s lacks claim/evidence", repair.ID)
		}
		for _, evidence := range repair.Evidence {
			if evidence.Repo == "" || evidence.PR <= 0 || len(evidence.Merge) != 40 {
				t.Fatalf("%s has invalid immutable evidence: %+v", repair.ID, evidence)
			}
		}
	}
	for _, id := range want {
		if !seen[id] {
			t.Fatalf("C10 matrix missing repair %s", id)
		}
	}

	for repo, head := range record.CurrentHeads {
		if repo == "" || len(head) != 40 {
			t.Fatalf("invalid current-head evidence %q=%q", repo, head)
		}
	}
}

func TestC10DoesNotRelabelProcessAsEnforcedBranchProtection(t *testing.T) {
	record := loadC10ClaimProofRecord(t)
	if len(record.BranchControlAudit.Repositories) == 0 {
		t.Fatal("branch/ruleset audit is empty")
	}
	for _, item := range record.BranchControlAudit.Repositories {
		if item.Protected {
			t.Fatalf("C10 evidence unexpectedly marks %s:%s protected", item.Repo, item.Branch)
		}
		if item.RulesetsCount != 0 {
			t.Fatalf("C10 evidence unexpectedly records rulesets for %s:%s: %d", item.Repo, item.Branch, item.RulesetsCount)
		}
	}
	if !strings.Contains(record.BranchControlAudit.Conclusion, "No audited branch may be described as protected/mandatory") {
		t.Fatalf("branch audit conclusion lost fail-closed claim boundary: %q", record.BranchControlAudit.Conclusion)
	}
}

func TestC10OpenWorkCannotCountAsMainCapability(t *testing.T) {
	record := loadC10ClaimProofRecord(t)
	for _, excluded := range record.OpenPRExclusions {
		if excluded.CountedAsMainCapability {
			t.Fatalf("open PRs in %s were relabeled as main capability", excluded.Repo)
		}
		if len(excluded.PRs) == 0 {
			t.Fatalf("empty open-PR exclusion for %s", excluded.Repo)
		}
	}

	targetedCorrections := 0
	for _, correction := range record.ClaimCorrections {
		if correction.PR <= 0 {
			continue
		}
		targetedCorrections++
		if correction.Merged == nil || !*correction.Merged {
			t.Fatalf("C10 targeted claim correction remains unmerged: %+v", correction)
		}
		if len(correction.Head) != 40 || len(correction.Merge) != 40 {
			t.Fatalf("merged correction lacks exact PR/head/merge provenance: %+v", correction)
		}
	}
	if targetedCorrections != 3 {
		t.Fatalf("targeted C10 claim corrections = %d, want 3", targetedCorrections)
	}
	if !record.CompletionGate.AllMaterialClaimsSupportedOrCorrected {
		t.Fatal("C10 completion gate must be true after all material corrections merge")
	}
	if len(record.CompletionGate.PendingClaimPRs) != 0 {
		t.Fatalf("pending claim PRs = %v, want none", record.CompletionGate.PendingClaimPRs)
	}
	if record.NormativeChange || record.RuntimeChange {
		t.Fatalf("C10 must be evidence/documentation-only: normative=%v runtime=%v", record.NormativeChange, record.RuntimeChange)
	}
}
