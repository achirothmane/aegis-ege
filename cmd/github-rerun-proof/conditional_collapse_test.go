package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestACPReconcileFixtureProcess(t *testing.T) {
	if os.Getenv("ACP_RECONCILE_PROCESS") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("ACP_RECONCILE_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	runReconcile(args)
	os.Exit(0)
}

// Execute the unchanged real reconciler on API-snapshot fixtures. A provider's
// run_attempt increment does not identify the triggering client or its governed
// authority at provider commitment. These are observation-indistinguishable
// worlds, not claimed live provider executions or an EXACT_EFFECT certificate.
func TestACPGitHubSnapshotsDoNotIdentifyAuthorityOrActualCause(t *testing.T) {
	root := t.TempDir()
	custodyPath := filepath.Join(root, "custody.json")
	custody := custodyRecord{
		SchemaVersion: custodyVersion, Repository: "fixture/repository", RunID: 7,
		HeadSHA: "1111111111111111111111111111111111111111", InitialAttempt: 1,
		ActionRef: "rerun-failed", EffectID: "effect", AttemptID: "claimed",
		Target: "github://fixture/repository/actions/runs/7", Profile: profileID,
		AuthorityUntil: "2099-01-01T00:00:00Z", RecordedAt: "2026-01-01T00:00:00Z",
	}
	if err := writeJSONAtomic(custodyPath, custody); err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(custodyPath)
	if err != nil {
		t.Fatal(err)
	}
	boundaryPath := filepath.Join(root, "boundary.json")
	if err := writeJSONAtomic(boundaryPath, boundaryRecord{boundaryVersion, digest, 7, 1, custody.HeadSHA, "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	observationPath := filepath.Join(root, "observation.json")
	if err := writeJSONAtomic(observationPath, workflowRun{7, custody.HeadSHA, "completed", "success", 2}); err != nil {
		t.Fatal(err)
	}
	var control nativeEvidence
	for i, truth := range []struct {
		name string
		a, c bool
	}{{"owned-authorized", true, true}, {"other-authorized-client", true, false}, {"revoked-governance-live-credential", false, true}} {
		t.Run(truth.name, func(t *testing.T) {
			evidencePath := filepath.Join(root, truth.name+".json")
			args, err := json.Marshal([]string{"--custody", custodyPath, "--boundary", boundaryPath, "--observation", observationPath, "--evidence-out", evidencePath})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestACPReconcileFixtureProcess$")
			cmd.Env = append(os.Environ(), "ACP_RECONCILE_PROCESS=1", "ACP_RECONCILE_ARGS="+string(args))
			if raw, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("actual reconciler failed to consume the common snapshot: %v %s", err, raw)
			}
			var got nativeEvidence
			if err := readACPJSON(evidencePath, &got); err != nil {
				t.Fatal(err)
			}
			got.ObservedAt = "" // Wall-clock transport metadata is not A or C.
			if got.FinalState != "CLOSED" || got.DispatchReceiptAvailable {
				t.Fatalf("legacy observation result changed: %+v", got)
			}
			if i == 0 {
				control = got
			} else if !reflect.DeepEqual(control, got) {
				t.Fatal("indistinguishable API snapshots unexpectedly distinguished the worlds")
			}
			t.Logf("fixture truth A=%t C=%t P=true; legacy CLOSED is a state/observation claim, not exact-attempt proof", truth.a, truth.c)
		})
	}
	// P still changes after a completed exact historical rerun: attempt 3
	// supersedes the profile's currently required exact attempt-2 state.
	if err := writeJSONAtomic(observationPath, workflowRun{7, custody.HeadSHA, "completed", "success", 3}); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(root, "superseded.json")
	args, err := json.Marshal([]string{"--custody", custodyPath, "--boundary", boundaryPath, "--observation", observationPath, "--evidence-out", evidencePath})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestACPReconcileFixtureProcess$")
	cmd.Env = append(os.Environ(), "ACP_RECONCILE_PROCESS=1", "ACP_RECONCILE_ARGS="+string(args))
	if err := cmd.Run(); err == nil {
		t.Fatal("superseded current required postcondition closed from historical commit")
	}
	var got nativeEvidence
	if err := readACPJSON(evidencePath, &got); err != nil || got.FinalState != "UNKNOWN" {
		t.Fatal("current-postcondition negative control did not reach UNKNOWN")
	}
}

func readACPJSON(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// The native workflow supplies one real provider rerun and its three raw
// snapshots. A second observer never dispatches; assigning its attempt name to
// a copied local custody tuple cannot establish that it caused the real effect.
func TestACPGitHubNativeForeignClaim(t *testing.T) {
	root := os.Getenv("ACP_GITHUB_NATIVE_DIR")
	if root == "" {
		if os.Getenv("ACP_GITHUB_REQUIRE") == "1" {
			t.Fatal("native GitHub snapshots required")
		}
		t.Skip("runs after the one sacrificial native rerun in the cross-domain workflow")
	}
	var before, after workflowRun
	var original custodyRecord
	var boundary boundaryRecord
	for path, value := range map[string]any{
		"github-run-before.json": &before, "github-run-after.json": &after,
		"github-rerun-custody.json": &original, "github-rerun-boundary.json": &boundary,
	} {
		if err := readACPJSON(filepath.Join(root, path), value); err != nil {
			t.Fatal(err)
		}
	}
	if original.Repository != os.Getenv("GITHUB_REPOSITORY") || original.HeadSHA != os.Getenv("PROOF_HEAD_SHA") || before.ID != after.ID || before.ID != original.RunID || before.HeadSHA != original.HeadSHA || after.HeadSHA != original.HeadSHA || before.RunAttempt != 1 || after.RunAttempt != 2 || before.Conclusion != "failure" || after.Status != "completed" || after.Conclusion != "success" || boundary.RunAttempt != 1 {
		t.Fatal("native trial lost its actual provider/run/build/cardinality controls")
	}
	controlDigest, err := fileDigest(filepath.Join(root, "github-rerun-custody.json"))
	if err != nil || controlDigest != boundary.CustodyDigest {
		t.Fatal("actual original boundary/custody pair differs")
	}
	foreign := original
	foreign.AttemptID = "read-only-observer-never-dispatched"
	if foreign.AttemptID == original.AttemptID {
		t.Fatal("foreign claim did not change attempt identity")
	}
	trial := t.TempDir()
	custodyPath, boundaryPath, evidencePath := filepath.Join(trial, "custody.json"), filepath.Join(trial, "boundary.json"), filepath.Join(trial, "foreign.json")
	if err := writeJSONAtomic(custodyPath, foreign); err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(custodyPath)
	if err != nil {
		t.Fatal(err)
	}
	boundary.CustodyDigest = digest
	if err := writeJSONAtomic(boundaryPath, boundary); err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal([]string{"--custody", custodyPath, "--boundary", boundaryPath, "--observation", filepath.Join(root, "github-run-after.json"), "--evidence-out", evidencePath})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestACPReconcileFixtureProcess$")
	cmd.Env = append(os.Environ(), "ACP_RECONCILE_PROCESS=1", "ACP_RECONCILE_ARGS="+string(args))
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real provider snapshot could not drive the unchanged reconciler: %v %s", err, raw)
	}
	var result nativeEvidence
	if err := readACPJSON(evidencePath, &result); err != nil || result.FinalState != "CLOSED" || result.AttemptID != foreign.AttemptID || result.DispatchReceiptAvailable {
		t.Fatalf("native projection limitation not reproduced: %v %+v", err, result)
	}
	if err := writeJSONAtomic(filepath.Join(root, "github-acp-native-foreign-claim.json"), struct {
		LegacyResult nativeEvidence `json:"legacy_observation_result"`
		ExactCause   bool           `json:"foreign_attempt_exact_cause"`
		NativeEffect int            `json:"provider_attempt_increment"`
		Scope        string         `json:"scope"`
	}{result, false, after.RunAttempt - before.RunAttempt, "native current state; foreign local claim never dispatched; no exact-effect verifier profile"}); err != nil {
		t.Fatal(err)
	}
}
