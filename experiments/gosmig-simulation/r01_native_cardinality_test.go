package simulation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/governedaction"
)

type r01ShipmentResult struct {
	Worker         string    `json:"worker"`
	EffectID       string    `json:"effect_id"`
	ActionRef      string    `json:"action_ref"`
	AuthorityAt    time.Time `json:"authority_at"`
	BoundaryAt     time.Time `json:"boundary_at"`
	AuthorityValid bool      `json:"authority_valid"`
	BoundaryValid  bool      `json:"boundary_valid"`
	Created        bool      `json:"created"`
}

type r01CardinalityEvidence struct {
	SchemaVersion string              `json:"schema_version"`
	ActionRef     string              `json:"action_ref"`
	EffectID      string              `json:"effect_id"`
	Workers       []r01ShipmentResult `json:"workers"`
	DurableRows   int                 `json:"durable_rows"`
	Winners       int                 `json:"winners"`
	Passed        bool                `json:"passed"`
}

func TestR01ShipmentHelperProcess(t *testing.T) {
	if os.Getenv("R01_HELPER") != "shipment" {
		return
	}
	fail := func(err error) {
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(41)
		}
	}
	db, err := openDB(os.Getenv("R01_DSN"))
	fail(err)
	defer db.Close()

	expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv("R01_EXPIRES_AT"))
	fail(err)
	result := r01ShipmentResult{
		Worker:    os.Getenv("R01_WORKER"),
		EffectID:  os.Getenv("R01_EFFECT_ID"),
		ActionRef: os.Getenv("R01_ACTION_REF"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fail(db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&result.AuthorityAt))
	result.AuthorityValid = governedaction.CheckValidity(expiresAt, result.AuthorityAt) == nil
	if !result.AuthorityValid {
		fail(errors.New("R01_AUTHORITY_INVALID_BEFORE_RACE"))
	}

	ready := os.Getenv("R01_BARRIER") + ".ready"
	release := os.Getenv("R01_BARRIER") + ".release"
	fail(writeJSON(ready, result))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(release); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fail(errors.New("R01_BARRIER_TIMEOUT"))
		}
		time.Sleep(5 * time.Millisecond)
	}

	tx, err := db.BeginTx(ctx, nil)
	fail(err)
	defer tx.Rollback()
	fail(tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&result.BoundaryAt))
	result.BoundaryValid = governedaction.CheckValidity(expiresAt, result.BoundaryAt) == nil
	if !result.BoundaryValid {
		fail(errors.New("R01_AUTHORITY_INVALID_AT_EFFECT_BOUNDARY"))
	}

	var inserted string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO r01_shipments(effect_id, action_ref, worker)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (effect_id) DO NOTHING
		 RETURNING effect_id`,
		result.EffectID, result.ActionRef, result.Worker,
	).Scan(&inserted)
	if err == nil {
		result.Created = inserted == result.EffectID
	} else if !errors.Is(err, sql.ErrNoRows) {
		fail(err)
	}
	fail(tx.Commit())
	fail(writeJSON(os.Getenv("R01_RESULT"), result))
	os.Exit(0)
}

func r01ShipmentCommand(t *testing.T, env map[string]string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	cmd := exec.Command(exe, "-test.run=^TestR01ShipmentHelperProcess$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "R01_") && !strings.HasPrefix(entry, "GS_") && !strings.HasPrefix(entry, "GOSMIG_SIM_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	return cmd
}

func waitR01Barrier(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(base + ".ready"); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("R01 worker did not prove current authority before race")
}

func TestR01NativeDuplicateCallbacksExactlyOneShipment(t *testing.T) {
	if os.Getenv("GOSMIG_SIM_ADMIN_DSN") == "" {
		t.Fatal("this suite requires an isolated real PostgreSQL service")
	}

	root, err := openDB(roleDSN(t, "", "public"))
	must(t, err)
	defer root.Close()
	initRoles(t, root)

	const schema = "gs_r01_cardinality"
	db := initSchema(t, schema)
	_, err = db.Exec(`CREATE TABLE r01_shipments (
		effect_id TEXT PRIMARY KEY,
		action_ref TEXT NOT NULL,
		worker TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
	)`)
	must(t, err)
	_, err = db.Exec(`GRANT SELECT, INSERT ON r01_shipments TO gs_worker`)
	must(t, err)

	var now time.Time
	must(t, db.QueryRow(`SELECT clock_timestamp()`).Scan(&now))
	expiresAt := now.Add(30 * time.Second)
	const effectID = "effect:r01:e3"
	const actionRef = "action:r01:fulfill-order-731"

	type running struct {
		cmd     *exec.Cmd
		barrier string
		result  string
		worker  string
	}
	workers := make([]running, 0, 2)
	for _, worker := range []string{"callback-a", "callback-b"} {
		dir := t.TempDir()
		barrier := filepath.Join(dir, "barrier")
		result := filepath.Join(dir, "result.json")
		cmd := r01ShipmentCommand(t, map[string]string{
			"R01_HELPER":     "shipment",
			"R01_DSN":        roleDSN(t, "gs_worker", schema),
			"R01_WORKER":     worker,
			"R01_EFFECT_ID":  effectID,
			"R01_ACTION_REF": actionRef,
			"R01_EXPIRES_AT": expiresAt.UTC().Format(time.RFC3339Nano),
			"R01_BARRIER":    barrier,
			"R01_RESULT":     result,
		})
		must(t, cmd.Start())
		workers = append(workers, running{cmd: cmd, barrier: barrier, result: result, worker: worker})
	}
	for _, worker := range workers {
		waitR01Barrier(t, worker.barrier)
	}
	for _, worker := range workers {
		must(t, os.WriteFile(worker.barrier+".release", []byte("release\n"), 0600))
	}

	evidence := r01CardinalityEvidence{
		SchemaVersion: "governed-action.r01-native-cardinality/v1",
		ActionRef:     actionRef,
		EffectID:      effectID,
		Workers:       []r01ShipmentResult{},
	}
	for _, worker := range workers {
		if err := worker.cmd.Wait(); err != nil {
			t.Fatalf("%s failed: %v", worker.worker, err)
		}
		data, err := os.ReadFile(worker.result)
		must(t, err)
		var result r01ShipmentResult
		must(t, json.Unmarshal(data, &result))
		evidence.Workers = append(evidence.Workers, result)
		if !result.AuthorityValid || !result.BoundaryValid {
			t.Fatalf("%s did not hold current authority at both checks: %+v", worker.worker, result)
		}
		if result.Created {
			evidence.Winners++
		}
	}
	must(t, db.QueryRow(`SELECT count(*) FROM r01_shipments WHERE effect_id=$1 AND action_ref=$2`, effectID, actionRef).Scan(&evidence.DurableRows))
	evidence.Passed = evidence.Winners == 1 && evidence.DurableRows == 1

	out := os.Getenv("GOSMIG_R01_CARDINALITY_EVIDENCE")
	if out != "" {
		must(t, writeJSON(out, evidence))
	}
	if !evidence.Passed {
		t.Fatalf("R01-04 native cardinality failed: %+v", evidence)
	}
}
