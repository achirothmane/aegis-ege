package governedactionnormative

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

type githubRerunNativeEvidence struct {
	SchemaVersion            string `json:"schema_version"`
	Repository               string `json:"repository"`
	RunID                    int64  `json:"run_id"`
	HeadSHA                  string `json:"head_sha"`
	ActionRef                string `json:"action_ref"`
	EffectID                 string `json:"effect_id"`
	AttemptID                string `json:"attempt_id"`
	InitialAttempt           int    `json:"initial_attempt"`
	ObservedAttempt          int    `json:"observed_attempt"`
	ObservedStatus           string `json:"observed_status"`
	ObservedConclusion       string `json:"observed_conclusion"`
	CustodyRecorded          bool   `json:"custody_recorded"`
	BoundaryRevalidated      bool   `json:"boundary_revalidated"`
	DispatchReceiptAvailable bool   `json:"dispatch_receipt_available"`
	RecoveryMutation         bool   `json:"recovery_mutation"`
	FinalState               string `json:"final_state"`
	ObservationRef           string `json:"observation_ref"`
}

func TestGitHubRerunNativeEvidenceUsesUnchangedK07Evaluator(t *testing.T) {
	path := os.Getenv("GITHUB_RERUN_NATIVE_EVIDENCE")
	if path == "" {
		t.Skip("native GitHub rerun evidence is mandatory in the dedicated proof workflow")
	}
	var evidence githubRerunNativeEvidence
	readJSON(t, path, &evidence)

	if evidence.SchemaVersion != "aegis.github-rerun-native-evidence/v1" {
		t.Fatalf("unexpected native evidence version %q", evidence.SchemaVersion)
	}
	if evidence.Repository == "" || evidence.RunID <= 0 || evidence.HeadSHA == "" {
		t.Fatal("native workflow identity is incomplete")
	}
	if !evidence.CustodyRecorded || !evidence.BoundaryRevalidated {
		t.Fatal("effect reached native boundary without retained custody and revalidation")
	}
	if evidence.DispatchReceiptAvailable {
		t.Fatal("post-effect process-loss proof must not invent a durable dispatch receipt")
	}
	if evidence.RecoveryMutation {
		t.Fatal("takeover/reconciliation process must remain observation-only")
	}
	if evidence.InitialAttempt <= 0 || evidence.ObservedAttempt != evidence.InitialAttempt+1 {
		t.Fatalf("rerun cardinality mismatch: initial=%d observed=%d", evidence.InitialAttempt, evidence.ObservedAttempt)
	}
	if evidence.ObservedStatus != "completed" || evidence.ObservedConclusion != "success" || evidence.FinalState != "CLOSED" {
		t.Fatalf("native postcondition not exactly closed: status=%s conclusion=%s state=%s", evidence.ObservedStatus, evidence.ObservedConclusion, evidence.FinalState)
	}
	if strings.TrimSpace(evidence.ActionRef) == "" || strings.TrimSpace(evidence.EffectID) == "" || strings.TrimSpace(evidence.AttemptID) == "" || strings.TrimSpace(evidence.ObservationRef) == "" {
		t.Fatal("native proof lost action/effect/attempt/observation identity")
	}

	var seed *k07ExecutableCase
	set := loadK07ExecutionSet(t)
	for i := range set.Cases {
		if set.Cases[i].CaseID == "SEED-CI-A1-validated-rerun" {
			seed = &set.Cases[i]
			break
		}
	}
	if seed == nil {
		t.Fatal("frozen CI rerun seed is missing")
	}
	seed.ActionRef = evidence.ActionRef
	seed.EffectID = evidence.EffectID
	seed.AttemptID = evidence.AttemptID
	seed.ObservationRef = "github-run:" + strconv.FormatInt(evidence.RunID, 10) + ":attempt:" + strconv.Itoa(evidence.ObservedAttempt)

	result := evaluateK07(*seed)
	if !result.ValidTrace || result.Disposition != "DISCHARGE_RECOVERY_OBLIGATION" || result.UnauthorizedEffects != 0 || !result.UsefulBehavior {
		t.Fatalf("unchanged K07 rejected native GitHub evidence: %+v", result)
	}
}
