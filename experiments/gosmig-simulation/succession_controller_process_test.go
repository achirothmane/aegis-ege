package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/easl/genesis"
)

// Only public, already approved transition input survives the controller.
// Plans, verified pins, store handles and database connections are rebuilt.
type successionControllerInput struct {
	Rotation journal.SignedSuccessorGovernanceRotation `json:"rotation"`
	History  journal.ExternalHead                      `json:"history"`
	Frozen   journal.ExternalHead                      `json:"frozen_authority"`
}

type successionControllerResult struct {
	History   journal.HistorySuccessionResult `json:"history"`
	Authority journal.ExternalHead            `json:"authority"`
}

type successionControllerRun struct {
	Mode        string `json:"mode"`
	PID         int    `json:"pid"`
	ExitCode    int    `json:"exit_code"`
	Transitions int    `json:"durable_policy_transitions"`
}

// A child has no fixture signing-key input and never initializes or resets SQL.
// The SQL administrator/controller remains trusted in this bounded profile.
func TestPostgresCompositeSuccessionProcess(t *testing.T) {
	mode := os.Getenv("COMPOSITE_SUCCESSION_PROCESS")
	if mode == "" {
		return
	}
	if mode != "freeze" && mode != "activate" && mode != "resume" {
		t.Fatal("unknown succession process mode")
	}
	var input successionControllerInput
	loadSuccessionJSON(t, os.Getenv("COMPOSITE_SUCCESSION_INPUT"), &input)
	ctx := context.Background()
	subject, err := genesisbootstrap.CurrentProductionSubject("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	var pins [2]genesisbootstrap.VerifiedGenesisPin
	var portable [2]v.PortableGenesis
	for i, name := range []string{"old", "new"} {
		dir := filepath.Join(os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR"), name)
		loadSuccessionJSON(t, filepath.Join(dir, "portable-genesis.json"), &portable[i])
		_, state, pin, err := genesisbootstrap.BootstrapProductionWithSubjectPin(ctx, filepath.Join(dir, "genesis.json"), filepath.Join(dir, "bundle.json"), uint64(7+i), 3, genesis.ConformanceC3, subject, time.Now().UTC())
		if err != nil || state.State != genesis.StateReady || pin.GenesisEpoch() != uint64(7+i) || pin.ManifestPayloadHash() != v.ContentDigest(portable[i].Payload) {
			t.Fatalf("fresh controller cannot verify exact Genesis: epoch=%d err=%v", pin.GenesisEpoch(), err)
		}
		pins[i] = pin
	}
	oldBinding, err := pins[0].ParseEnrollmentSuccessorGovernanceBinding(portable[0].CapabilityEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	newBinding, err := pins[1].ParseEnrollmentSuccessorGovernanceBinding(portable[1].CapabilityEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.VerifySignedSuccessorGovernanceRotation(input.Rotation, oldBinding, newBinding, time.Now().UTC()); err != nil {
		t.Fatalf("rotation input rejected before native writes: %v", err)
	}
	oldQ, oldH, err := pins[0].ParseHistorySuccessionEpochs(portable[0].CapabilityEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	newQ, newH, err := pins[1].ParseHistorySuccessionEpochs(portable[1].CapabilityEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	quorumPlan, err := journal.NewQuorumRotationPlan(oldQ, newQ)
	if err != nil {
		t.Fatal(err)
	}
	historyPlan, err := journal.NewHistorySuccessionPlan(oldH, newH, quorumPlan)
	if err != nil {
		t.Fatal(err)
	}
	oldQB, err := pins[0].ParseQuorumBinding(portable[0].CapabilityEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	newQB, err := pins[1].ParseQuorumBinding(portable[1].CapabilityEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDB(os.Getenv("GOSMIG_SIM_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	members := map[string]*successionPostgresWitness{}
	for _, id := range []string{"A", "B", "C", "D"} {
		members[id] = &successionPostgresWitness{db: db, id: id, trust: v.ContentDigest([]byte("native-postgres-logical-witness:" + id))}
	}
	list := func(ids []string) []journal.QuorumHeadMember {
		result := []journal.QuorumHeadMember{}
		for _, id := range ids {
			result = append(result, journal.QuorumHeadMember{ID: id, Store: members[id]})
		}
		return result
	}
	oldStore, err := journal.NewGovernedQuorumHeadStore(list([]string{"A", "B", "C"}), oldQB, oldQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := journal.NewGovernedQuorumHeadStore(list([]string{"B", "C", "D"}), newQB, newQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"B", "C"} {
		history, err := members[id].ObserveQuorumRotationHead(ctx, successionHistoryID)
		if err != nil || portableHead(history) != portableHead(input.History) {
			t.Fatalf("fresh controller lost exact retained history at %s: %v", id, err)
		}
		authority, err := members[id].ObserveQuorumRotationHead(ctx, journal.SuccessorGovernanceAuthorityJournalID)
		if err != nil || portableHead(authority) != portableHead(input.Frozen) {
			t.Fatalf("fresh controller lost frozen authority at %s: %v", id, err)
		}
	}
	// The hook runs strictly after the policy/head transaction commits. Exit
	// bypasses defers and withholds the acknowledgement and completion result.
	members["B"].afterTransition = func() error {
		policy, err := members["B"].CurrentQuorumPolicy(ctx)
		if err != nil {
			return err
		}
		if mode == "freeze" && policy.Phase == journal.QuorumPolicyPhaseJoint {
			os.Exit(95)
		}
		if mode == "activate" && policy.Phase == journal.QuorumPolicyPhaseActive && policy.GenesisEpoch == newQ.GenesisEpoch() {
			os.Exit(96)
		}
		return nil
	}
	result, err := journal.ExecuteGovernedHistorySuccession(ctx, historyPlan, oldStore, newStore)
	if err != nil {
		t.Fatal(err)
	}
	if portableHead(result.Head) != portableHead(input.History) {
		t.Fatal("fresh controller changed retained predecessor")
	}
	active, err := journal.ActivateSuccessorGovernanceAuthority(ctx, newStore, input.Rotation, oldBinding, newBinding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if mode != "resume" {
		t.Fatal("requested native crash boundary was not reached")
	}
	if err := json.NewEncoder(os.Stdout).Encode(successionControllerResult{History: result, Authority: active}); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func (s *compositeSuccession) resumeWithFreshControllers(t *testing.T, a *postgresNativeFenceAdapter, head, frozen journal.ExternalHead, evidenceDir string) successionControllerResult {
	t.Helper()
	input := successionControllerInput{Rotation: s.signed, History: head, Frozen: frozen}
	inputPath := filepath.Join(t.TempDir(), "approved-transition.json")
	writeCompositeJSON(t, inputPath, input)
	inputRaw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	runs := []successionControllerRun{}
	seen := map[int]bool{os.Getpid(): true}
	run := func(mode string, expectedExit, expectedTransitions int, rejected bool) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresCompositeSuccessionProcess$")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "COMPOSITE_") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "COMPOSITE_SUCCESSION_PROCESS="+mode, "COMPOSITE_SUCCESSION_INPUT="+inputPath, "COMPOSITE_GENESIS_FIXTURE_DIR="+os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR"))
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("succession controller did not run: %v", err)
			}
			code = exit.ExitCode()
		}
		if code != expectedExit || cmd.Process == nil || seen[cmd.Process.Pid] {
			t.Fatalf("fresh %s controller: expected exit %d, got %d: %s", mode, expectedExit, code, output)
		}
		seen[cmd.Process.Pid] = true
		if (expectedExit == 95 || expectedExit == 96) && len(output) != 0 {
			t.Fatalf("crashed controller returned an acknowledgement: %s", output)
		}
		if rejected && !strings.Contains(string(output), "rotation input rejected before native writes") {
			t.Fatalf("changed approval was not rejected at input verification: %s", output)
		}
		trace, _ := successionObservation(t, a.db, s.members, successionHistoryID, journal.SuccessorGovernanceAuthorityJournalID)
		if len(trace) != expectedTransitions || nativeEffectCount(t, a) != 1 {
			t.Fatalf("controller changed native cardinality: transitions=%d effects=%d", len(trace), nativeEffectCount(t, a))
		}
		runs = append(runs, successionControllerRun{Mode: mode, PID: cmd.Process.Pid, ExitCode: code, Transitions: len(trace)})
		if expectedExit != 0 {
			for _, check := range []struct {
				store   *journal.QuorumHeadStore
				binding journal.GenesisEnrollmentSuccessorGovernanceBinding
			}{{s.oldAdmin, s.oldBinding}, {s.newAdmin, s.newBinding}} {
				if _, err := journal.RequireActiveSuccessorGovernanceAuthority(context.Background(), check.store, journal.SuccessorGovernanceAuthorityJournalID, check.binding); err == nil {
					t.Fatal("crashed/rejected controller made authority current")
				}
			}
			for _, id := range []string{"B", "C"} {
				actual, err := s.members[id].ObserveQuorumRotationHead(context.Background(), head.JournalID)
				if err != nil || portableHead(actual) != portableHead(head) {
					t.Fatal("controller crash/rejection replaced retained history")
				}
				authority, err := s.members[id].ObserveQuorumRotationHead(context.Background(), frozen.JournalID)
				if err != nil || portableHead(authority) != portableHead(frozen) {
					t.Fatal("controller crash/rejection replaced frozen authority")
				}
			}
		}
		return output
	}
	run("freeze", 95, 1, false)
	changed := input
	changed.Rotation.Authorization.RotationID += ":substituted"
	writeCompositeJSON(t, inputPath, changed)
	run("resume", 1, 1, true)
	writeCompositeJSON(t, inputPath, input)
	run("activate", 96, 3, false)
	output := run("resume", 0, 4, false)
	var result successionControllerResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	writeCompositeJSON(t, filepath.Join(evidenceDir, "controller-restarts.json"), map[string]any{"approved_input_digest": v.ContentDigest(inputRaw), "supervisor_pid": os.Getpid(), "runs": runs, "result": result, "scope": "fresh subprocesses; one trusted SQL service; fixture Genesis assurance"})
	t.Logf("fresh controller exits 95 -> rejected changed approval -> 96 -> 0; one native effect; four exact policy transitions")
	return result
}
