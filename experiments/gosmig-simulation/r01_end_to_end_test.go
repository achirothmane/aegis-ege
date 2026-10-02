package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/governedaction"
)

type r01EndToEndEvidence struct {
	SchemaVersion string `json:"schema_version"`
	ActionRef     string `json:"action_ref"`
	Amount        int64  `json:"amount"`
	E1            struct {
		EffectID        string `json:"effect_id"`
		InitiallyExact  bool   `json:"initially_exact"`
		FinalState      string `json:"final_state"`
	} `json:"e1"`
	E2 struct {
		EffectID                string `json:"effect_id"`
		LostAckWorkerExit       int    `json:"lost_ack_worker_exit"`
		ProviderAcceptanceRows  int    `json:"provider_acceptance_rows"`
		WebhookDeliveries       int    `json:"webhook_deliveries"`
		WebhookValue            string `json:"webhook_value"`
		APIValue                string `json:"api_value"`
		UnrelatedEffectID       string `json:"unrelated_effect_id"`
		AggregateCapturedAmount int64  `json:"aggregate_captured_amount"`
	} `json:"e2"`
	Authority struct {
		OldExpiresAt  time.Time `json:"old_expires_at"`
		OldExpired    bool      `json:"old_expired"`
		CurrentOwner  string    `json:"current_owner"`
		CurrentFence  int64     `json:"current_fence"`
	} `json:"authority"`
	E3 struct {
		EffectID          string `json:"effect_id"`
		StaleAttemptExits []int  `json:"stale_attempt_exits"`
		DurableRows       int    `json:"durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

func TestR01LostAckHelperProcess(t *testing.T) {
	if os.Getenv("R01_E2E_HELPER") != "payment-lost-ack" {
		return
	}
	fail := func(err error) {
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(42)
		}
	}
	db, err := openDB(os.Getenv("R01_E2E_DSN"))
	fail(err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv("R01_E2E_EXPIRES_AT"))
	fail(err)
	var boundaryAt time.Time
	fail(db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&boundaryAt))
	if err := governedaction.CheckValidity(expiresAt, boundaryAt); err != nil {
		fail(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	fail(err)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO provider_a_acceptance(effect_id, action_ref, amount) VALUES ($1,$2,$3)`,
		os.Getenv("R01_E2E_EFFECT_ID"),
		os.Getenv("R01_E2E_ACTION_REF"),
		int64(73100),
	)
	fail(err)
	fail(tx.Commit())

	// Provider accepted durably, but the caller loses the acknowledgement and
	// exits without a receipt. The parent must learn truth by observation.
	os.Exit(93)
}

func r01EndToEndHelperCommand(t *testing.T, env map[string]string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	must(t, err)
	cmd := exec.Command(exe, "-test.run=^TestR01LostAckHelperProcess$")
	for _, entry := range os.Environ() {
		if len(entry) >= 8 && entry[:8] == "R01_E2E_" {
			continue
		}
		if len(entry) >= 3 && entry[:3] == "GS_" {
			continue
		}
		if len(entry) >= 11 && entry[:11] == "GOSMIG_SIM_" {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	return cmd
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func TestR01EndToEndCompoundSchedule(t *testing.T) {
	if os.Getenv("GOSMIG_SIM_ADMIN_DSN") == "" {
		t.Fatal("this suite requires an isolated real PostgreSQL service")
	}

	root, err := openDB(roleDSN(t, "", "public"))
	must(t, err)
	defer root.Close()
	initRoles(t, root)

	const schema = "gs_r01_e2e"
	const actionRef = "action:r01:fulfill-order-731"
	const e1 = "effect:r01:e1"
	const e2 = "effect:r01:e2"
	const e3 = "effect:r01:e3"
	const unrelated = "effect:r01:semantic-aba-unrelated"
	const amount int64 = 73100

	db := initSchema(t, schema)
	for _, q := range []string{
		`CREATE TABLE inventory_reservations (effect_id TEXT PRIMARY KEY, action_ref TEXT NOT NULL, state TEXT NOT NULL)`,
		`CREATE TABLE provider_a_acceptance (effect_id TEXT PRIMARY KEY, action_ref TEXT NOT NULL, amount BIGINT NOT NULL)`,
		`CREATE TABLE provider_a_webhooks (delivery_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, effect_id TEXT NOT NULL, value TEXT NOT NULL)`,
		`CREATE TABLE provider_a_api (effect_id TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE provider_a_settlements (effect_id TEXT PRIMARY KEY, amount BIGINT NOT NULL, state TEXT NOT NULL)`,
		`CREATE TABLE r01_shipments (effect_id TEXT PRIMARY KEY, action_ref TEXT NOT NULL, worker TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`,
		`GRANT SELECT, INSERT ON provider_a_acceptance, r01_shipments TO gs_worker`,
	} {
		_, err := db.Exec(q)
		must(t, err)
	}

	var now time.Time
	must(t, db.QueryRow(`SELECT clock_timestamp()`).Scan(&now))
	oldExpiresAt := now.Add(1200 * time.Millisecond)

	// E1 commits under the original action lineage.
	_, err = db.Exec(`INSERT INTO inventory_reservations(effect_id,action_ref,state) VALUES ($1,$2,'RESERVED')`, e1, actionRef)
	must(t, err)

	// E2 is accepted durably by provider A, but the worker loses the ACK.
	cmd := r01EndToEndHelperCommand(t, map[string]string{
		"R01_E2E_HELPER":     "payment-lost-ack",
		"R01_E2E_DSN":        roleDSN(t, "gs_worker", schema),
		"R01_E2E_EXPIRES_AT": oldExpiresAt.UTC().Format(time.RFC3339Nano),
		"R01_E2E_EFFECT_ID":  e2,
		"R01_E2E_ACTION_REF": actionRef,
	})
	err = cmd.Run()
	lostAckExit := exitCode(err)
	if lostAckExit != 93 {
		t.Fatalf("lost-ack worker exit=%d want=93 err=%v", lostAckExit, err)
	}

	// Original authority expires and takeover advances the destination fence.
	awaitExpired(t, db, permit{ExpiresAt: oldExpiresAt})
	var fence int64
	var owner string
	must(t, db.QueryRow(`UPDATE authority SET fence=fence+1, owner='worker-b' WHERE singleton RETURNING fence,owner`).Scan(&fence, &owner))

	// Provider A is initially unobservable. Later, the same old webhook is
	// delivered twice; neither delivery is authority.
	_, err = db.Exec(`INSERT INTO provider_a_webhooks(delivery_id,event_id,effect_id,value) VALUES
		('delivery-1','evt-old-e2',$1,'CAPTURED'),
		('delivery-2','evt-old-e2',$1,'CAPTURED')`, e2)
	must(t, err)

	// Both stale callbacks try E3 with the expired original authority. They must
	// stop before the destination mutation.
	staleExits := make([]int, 0, 2)
	for _, worker := range []string{"stale-callback-a", "stale-callback-b"} {
		dir := t.TempDir()
		result := filepath.Join(dir, "result.json")
		stale := r01ShipmentCommand(t, map[string]string{
			"R01_HELPER":     "shipment",
			"R01_DSN":        roleDSN(t, "gs_worker", schema),
			"R01_WORKER":     worker,
			"R01_EFFECT_ID":  e3,
			"R01_ACTION_REF": actionRef,
			"R01_EXPIRES_AT": oldExpiresAt.UTC().Format(time.RFC3339Nano),
			"R01_BARRIER":    filepath.Join(dir, "barrier"),
			"R01_RESULT":     result,
		})
		staleExits = append(staleExits, exitCode(stale.Run()))
	}

	// Independent actor reverses E1.
	_, err = db.Exec(`UPDATE inventory_reservations SET state='REVERSED' WHERE effect_id=$1`, e1)
	must(t, err)

	// Semantic ABA: an unrelated same-value payment makes the aggregate look
	// correct even though exact E2 lineage is later contradicted.
	_, err = db.Exec(`INSERT INTO provider_a_settlements(effect_id,amount,state) VALUES ($1,$2,'CAPTURED')`, unrelated, amount)
	must(t, err)
	_, err = db.Exec(`INSERT INTO provider_a_api(effect_id,value) VALUES ($1,'NOT_CAPTURED')`, e2)
	must(t, err)

	var ev r01EndToEndEvidence
	ev.SchemaVersion = "governed-action.r01-end-to-end/v1"
	ev.ActionRef = actionRef
	ev.Amount = amount
	ev.E1.EffectID = e1
	ev.E2.EffectID = e2
	ev.E3.EffectID = e3
	ev.Authority.OldExpiresAt = oldExpiresAt
	ev.Authority.OldExpired = true
	ev.Authority.CurrentFence = fence
	ev.Authority.CurrentOwner = owner
	ev.E2.LostAckWorkerExit = lostAckExit
	ev.E2.UnrelatedEffectID = unrelated
	ev.E3.StaleAttemptExits = staleExits

	var e1Initial int
	must(t, db.QueryRow(`SELECT count(*) FROM inventory_reservations WHERE effect_id=$1 AND action_ref=$2`, e1, actionRef).Scan(&e1Initial))
	ev.E1.InitiallyExact = e1Initial == 1
	must(t, db.QueryRow(`SELECT state FROM inventory_reservations WHERE effect_id=$1`, e1).Scan(&ev.E1.FinalState))
	must(t, db.QueryRow(`SELECT count(*) FROM provider_a_acceptance WHERE effect_id=$1 AND action_ref=$2`, e2, actionRef).Scan(&ev.E2.ProviderAcceptanceRows))
	must(t, db.QueryRow(`SELECT count(*), min(value) FROM provider_a_webhooks WHERE effect_id=$1`, e2).Scan(&ev.E2.WebhookDeliveries, &ev.E2.WebhookValue))
	must(t, db.QueryRow(`SELECT value FROM provider_a_api WHERE effect_id=$1`, e2).Scan(&ev.E2.APIValue))
	must(t, db.QueryRow(`SELECT COALESCE(sum(amount),0) FROM provider_a_settlements WHERE state='CAPTURED'`).Scan(&ev.E2.AggregateCapturedAmount))
	must(t, db.QueryRow(`SELECT count(*) FROM r01_shipments WHERE effect_id=$1`, e3).Scan(&ev.E3.DurableRows))

	ev.ExactPostcondition =
		ev.E1.FinalState == "RESERVED" &&
		ev.E2.APIValue == "CAPTURED" &&
		ev.E3.DurableRows == 1

	if !ev.E1.InitiallyExact ||
		ev.E1.FinalState != "REVERSED" ||
		ev.E2.ProviderAcceptanceRows != 1 ||
		ev.E2.LostAckWorkerExit != 93 ||
		ev.E2.WebhookDeliveries != 2 ||
		ev.E2.WebhookValue != "CAPTURED" ||
		ev.E2.APIValue != "NOT_CAPTURED" ||
		ev.E2.AggregateCapturedAmount != amount ||
		ev.E3.DurableRows != 0 ||
		len(ev.E3.StaleAttemptExits) != 2 ||
		ev.E3.StaleAttemptExits[0] != 41 ||
		ev.E3.StaleAttemptExits[1] != 41 ||
		ev.ExactPostcondition {
		t.Fatalf("R01 end-to-end native facts drifted: %+v", ev)
	}

	out := os.Getenv("GOSMIG_R01_E2E_EVIDENCE")
	if out != "" {
		must(t, writeJSON(out, ev))
	}
}

func readR01EndToEndEvidence(path string) (r01EndToEndEvidence, error) {
	var ev r01EndToEndEvidence
	data, err := os.ReadFile(path)
	if err != nil {
		return ev, err
	}
	err = json.Unmarshal(data, &ev)
	return ev, err
}
