// Package simulation implements only the registered cooperative fixture profile.
// It is not a reusable kernel library or an upstream gosmig modification.
package simulation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/padurean/gosmig"
)

const (
	profile = "gosmig.fixed-transactional-migration/owner-simulation-v1"
	fixtureKey = "fixture-only-not-production-signing-key"
	createMetadata = `CREATE TABLE IF NOT EXISTS gosmig (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`
	selectVersion = "SELECT COALESCE(MAX(version), 0) FROM gosmig"
	insertVersion = "INSERT INTO gosmig (version) VALUES ($1)"
	createTarget = `CREATE TABLE migrated_items (effect_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, action_ref TEXT NOT NULL, payload TEXT NOT NULL CHECK (payload = 'fixture'), created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`
	insertTarget = `INSERT INTO migrated_items (effect_id, attempt_id, action_ref, payload) VALUES ($1, $2, $3, 'fixture')`
)

type permit struct {
	Profile string `json:"profile"`
	Database string `json:"database"`
	Schema string `json:"schema"`
	EffectID string `json:"effect_id"`
	AttemptID string `json:"attempt_id"`
	ActionRef string `json:"action_ref"`
	Owner string `json:"owner"`
	PolicyEpoch int64 `json:"policy_epoch"`
	StateEpoch int64 `json:"state_epoch"`
	Fence int64 `json:"fence"`
	ExpectedVersion int `json:"expected_version"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string `json:"signature"`
}

func (p permit) signature() string {
	p.Signature = ""
	data, _ := json.Marshal(p)
	h := hmac.New(sha256.New, []byte(fixtureKey))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (p permit) validSignature() bool {
	return hmac.Equal([]byte(p.Signature), []byte(p.signature()))
}

func actionRef(p permit, migrationSQL string) string {
	material := struct {
		Profile, Database, Schema string
		Version int
		SQL []string
		Parameters []string
	}{p.Profile, p.Database, p.Schema, 1, []string{migrationSQL, insertTarget}, []string{p.EffectID, p.AttemptID}}
	data, _ := json.Marshal(material)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

type event struct {
	Stage string `json:"stage"`
	Reason string `json:"reason,omitempty"`
	At time.Time `json:"at"`
	Fence int64 `json:"fence,omitempty"`
	Owner string `json:"owner,omitempty"`
	PolicyEpoch int64 `json:"policy_epoch,omitempty"`
	StateEpoch int64 `json:"state_epoch,omitempty"`
}

func appendEvent(e event) error {
	f, err := os.OpenFile(os.Getenv("GS_EVENTS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil { return err }
	defer f.Close()
	if err := json.NewEncoder(f).Encode(e); err != nil { return err }
	return f.Sync()
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return err }
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil { return err }
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil { return err }
	return f.Sync()
}

func barrier(name string) error {
	base := os.Getenv("GS_BARRIER")
	if base == "" { return errors.New("missing barrier path") }
	if err := writeJSON(base+".ready", map[string]string{"stage": name}); err != nil { return err }
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(base+".release"); err == nil { return nil }
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("barrier deadline exceeded")
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil { return nil, err }
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil { _ = db.Close(); return nil, err }
	return db, nil
}

type row struct { value *sql.Row; err error }
func (r *row) Scan(dest ...any) error { if r.err != nil { return r.err }; return r.value.Scan(dest...) }
func (r *row) Err() error { if r.err != nil { return r.err }; return r.value.Err() }

type guardDB struct {
	db *sql.DB
	p permit
	governed bool
	fault string
	migrationSQL string
}

func normalizeSQL(s string) string { return strings.Join(strings.Fields(s), " ") }

func (g *guardDB) QueryRowContext(ctx context.Context, q string, args ...any) *row {
	if q != selectVersion || len(args) != 0 { return &row{err: errors.New("GS_REJECT_UNSUPPORTED_QUERY")} }
	return &row{value: g.db.QueryRowContext(ctx, q)}
}

func (g *guardDB) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	// gosmig's metadata table is provisioned by the isolated harness. The
	// upstream create-if-absent call cannot perform target migration effects.
	if normalizeSQL(q) != normalizeSQL(createMetadata) || len(args) != 0 {
		return nil, errors.New("GS_REJECT_NONTRANSACTIONAL_SQL")
	}
	return g.db.ExecContext(ctx, q)
}

func (g *guardDB) Close() error { return g.db.Close() }

type guardTx struct {
	tx *sql.Tx
	g *guardDB
	ctx context.Context
	mutations int
}

func (g *guardDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*guardTx, error) {
	if g.fault == "pause-before-tx" { if err := barrier("before-tx"); err != nil { return nil, err } }
	tx, err := g.db.BeginTx(ctx, opts)
	if err != nil { return nil, err }
	t := &guardTx{tx: tx, g: g, ctx: ctx}
	if !g.governed { return t, nil }
	if err := t.checkBoundary(true); err != nil { _ = tx.Rollback(); return nil, err }
	data, _ := json.Marshal(g.p)
	// Independent autocommit connection: survives rollback or worker exit.
	var persistedAt time.Time
	err = g.db.QueryRowContext(ctx,
		`INSERT INTO custody (effect_id, attempt_id, permit) VALUES ($1, $2, $3::jsonb) RETURNING created_at`,
		g.p.EffectID, g.p.AttemptID, string(data)).Scan(&persistedAt)
	if err != nil { _ = tx.Rollback(); return nil, fmt.Errorf("GS_REJECT_CUSTODY_INSERT: %w", err) }
	if err := appendEvent(event{Stage:"custody-durable", At:persistedAt}); err != nil {
		_ = tx.Rollback(); return nil, err
	}
	return t, nil
}

func (t *guardTx) checkBoundary(checkVersion bool) error {
	p := t.g.p
	var e event
	e.Stage = "boundary-allowed"
	if err := t.tx.QueryRowContext(t.ctx,
		`SELECT policy_epoch, state_epoch, fence, owner, clock_timestamp() FROM authority WHERE singleton FOR UPDATE`).
		Scan(&e.PolicyEpoch, &e.StateEpoch, &e.Fence, &e.Owner, &e.At); err != nil { return err }
	switch {
	case !e.At.Before(p.ExpiresAt): e.Reason = "EXPIRED"
	case e.PolicyEpoch != p.PolicyEpoch || e.StateEpoch != p.StateEpoch: e.Reason = "STATE"
	case e.Fence != p.Fence || e.Owner != p.Owner: e.Reason = "FENCE"
	}
	if e.Reason == "" && checkVersion {
		var version int
		if err := t.tx.QueryRowContext(t.ctx, selectVersion).Scan(&version); err != nil { return err }
		if version != p.ExpectedVersion { e.Reason = "VERSION" }
	}
	if e.Reason != "" { e.Stage = "boundary-rejected" }
	if err := appendEvent(e); err != nil { return err }
	if e.Reason != "" { return fmt.Errorf("GS_REJECT_%s", e.Reason) }
	return nil
}

func (t *guardTx) QueryRowContext(ctx context.Context, q string, args ...any) *row {
	if q != selectVersion || len(args) != 0 { return &row{err: errors.New("GS_REJECT_UNSUPPORTED_QUERY")} }
	return &row{value: t.tx.QueryRowContext(ctx, q)}
}

func (t *guardTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	p := t.g.p
	expectedSQL := []string{t.g.migrationSQL, insertTarget, insertVersion}
	expectedArgs := [][]any{nil, {p.EffectID, p.AttemptID, p.ActionRef}, {1}}
	if t.mutations >= len(expectedSQL) || q != expectedSQL[t.mutations] || !reflect.DeepEqual(args, expectedArgs[t.mutations]) {
		return nil, errors.New("GS_REJECT_UNSUPPORTED_MUTATION")
	}
	if t.g.governed { if err := t.checkBoundary(false); err != nil { return nil, err } }
	result, err := t.tx.ExecContext(ctx, q, args...)
	if err == nil { t.mutations++ }
	return result, err
}

func (t *guardTx) Rollback() error { return t.tx.Rollback() }

func (t *guardTx) Commit() error {
	if t.mutations != 3 { _ = t.tx.Rollback(); return errors.New("GS_REJECT_INCOMPLETE_MIGRATION") }
	if t.g.fault == "crash-before-commit" { os.Exit(94) }
	if t.g.fault == "pause-before-commit" { if err := barrier("before-commit"); err != nil { _ = t.tx.Rollback(); return err } }
	if t.g.governed { if err := t.checkBoundary(false); err != nil { _ = t.tx.Rollback(); return err } }
	if err := t.tx.Commit(); err != nil { return err }
	// Do not write an accepted receipt on these fault paths. The harness knows
	// the injection schedule, but the recovery observer receives only custody.
	if t.g.fault == "lost-response" { return errors.New("injected commit response loss") }
	if t.g.fault == "crash-after-commit" { os.Exit(93) }
	return appendEvent(event{Stage:"commit-receipt", At:time.Now().UTC()})
}

func runMigration(p permit) error {
	migrationSQL := createTarget
	if os.Getenv("GS_TAMPER_SQL") == "1" { migrationSQL = strings.Replace(createTarget, "migrated_items", "altered_items", 1) }
	governed := os.Getenv("GS_GOVERNED") == "1"
	connect := func(_ string, _ time.Duration) (*guardDB, error) {
		db, err := openDB(os.Getenv("GS_DSN"))
		if err != nil { return nil, err }
		g := &guardDB{db: db, p:p, governed:governed, fault:os.Getenv("GS_FAULT"), migrationSQL:migrationSQL}
		if !governed { return g, nil }
		reject := func(reason string) (*guardDB, error) {
			_ = db.Close()
			if err := appendEvent(event{Stage:"admission-rejected", Reason:reason, At:time.Now().UTC()}); err != nil { return nil, err }
			return nil, fmt.Errorf("GS_REJECT_%s", reason)
		}
		if !p.validSignature() || p.Profile != profile { return reject("SIGNATURE_OR_PROFILE") }
		if p.ActionRef != actionRef(p, migrationSQL) { return reject("REVISION") }
		var database, schema string
		if err := db.QueryRow(`SELECT current_database(), current_schema()`).Scan(&database, &schema); err != nil { _=db.Close(); return nil, err }
		if database != p.Database || schema != p.Schema { return reject("TARGET") }
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM custody WHERE effect_id = $1)`, p.EffectID).Scan(&exists); err != nil { _=db.Close(); return nil, err }
		if exists { return reject("POSSIBLE_EFFECT") }
		return g, nil
	}
	migrations := []gosmig.Migration[*row, sql.Result, *guardTx, *sql.TxOptions, *guardDB]{
		{Version:1, UpDown:&gosmig.UpDown[*row, sql.Result, *guardTx]{
			Up:func(ctx context.Context, tx *guardTx) error {
				if _, err := tx.ExecContext(ctx, migrationSQL); err != nil { return err }
				_, err := tx.ExecContext(ctx, insertTarget, p.EffectID, p.AttemptID, p.ActionRef)
				return err
			},
			Down:func(context.Context, *guardTx) error { return errors.New("down is outside this registered profile") },
		}},
	}
	run, err := gosmig.New(migrations, connect, &gosmig.Config{Timeout:30*time.Second})
	if err != nil { return err }
	// The real upstream CLI parses two arguments; the connector obtains the
	// disposable DSN from the child environment, never from command logs.
	os.Args = []string{filepath.Base(os.Args[0]), "fixture-dsn-from-environment", "up"}
	run()
	return nil
}

type observation struct {
	Knowledge string `json:"knowledge"`
	Disposition string `json:"disposition"`
	EffectID string `json:"effect_id"`
	AttemptID string `json:"attempt_id"`
	ActionRef string `json:"action_ref"`
	DispatchAccepted *bool `json:"dispatch_accepted"`
	PostconditionExact bool `json:"postcondition_exact"`
	CustodyBeforeEffect bool `json:"custody_before_effect"`
	ObserverReadOnly bool `json:"observer_read_only"`
	CustodySHA256 string `json:"custody_sha256"`
	ObservedAt time.Time `json:"observed_at"`
}

func observe(effectID string) (observation, error) {
	o := observation{Knowledge:"UNKNOWN", Disposition:"OPEN", EffectID:effectID}
	db, err := openDB(os.Getenv("GS_DSN"))
	if err != nil { return o, err }
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly:true, Isolation:sql.LevelRepeatableRead})
	if err != nil { return o, err }
	defer tx.Rollback()
	var custody string
	var custodyAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT permit::text, created_at FROM custody WHERE effect_id = $1`, effectID).Scan(&custody, &custodyAt); err != nil { return o, err }
	h := sha256.Sum256([]byte(custody))
	o.CustodySHA256 = hex.EncodeToString(h[:])
	var p permit
	if err := json.Unmarshal([]byte(custody), &p); err != nil { return o, err }
	o.EffectID, o.AttemptID, o.ActionRef = p.EffectID, p.AttemptID, p.ActionRef
	var database, schema, user string
	var canCreate, canCustodyInsert, canCustodyUpdate, canCustodyDelete bool
	if err := tx.QueryRowContext(ctx, `SELECT current_database(), current_schema(), current_user, clock_timestamp(),
		has_schema_privilege(current_schema(), 'CREATE'), has_table_privilege('custody', 'INSERT'),
		has_table_privilege('custody', 'UPDATE'), has_table_privilege('custody', 'DELETE')`).
		Scan(&database, &schema, &user, &o.ObservedAt, &canCreate, &canCustodyInsert, &canCustodyUpdate, &canCustodyDelete); err != nil { return o, err }
	o.ObserverReadOnly = user == "gs_observer" && !canCreate && !canCustodyInsert && !canCustodyUpdate && !canCustodyDelete
	if !o.ObserverReadOnly { return o, errors.New("observer role has mutation authority") }
	if !p.validSignature() || p.Profile != profile || p.Database != database || p.Schema != schema || p.ActionRef != actionRef(p, createTarget) || p.EffectID != effectID { return o, tx.Commit() }
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('migrated_items') IS NOT NULL`).Scan(&exists); err != nil { return o, err }
	if !exists { return o, tx.Commit() }
	var columns int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'migrated_items' AND
		(column_name, data_type, is_nullable) IN (('effect_id','text','NO'),('attempt_id','text','NO'),('action_ref','text','NO'),('payload','text','NO'),('created_at','timestamp with time zone','NO'))`).Scan(&columns); err != nil { return o, err }
	var totalColumns int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'migrated_items'`).Scan(&totalColumns); err != nil { return o, err }
	var effects, matching, versions, maxVersion int
	var effectAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE effect_id=$1 AND attempt_id=$2 AND action_ref=$3 AND payload='fixture'), min(created_at) FROM migrated_items`, p.EffectID, p.AttemptID, p.ActionRef).Scan(&effects, &matching, &effectAt); err != nil { return o, err }
	if err := tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(MAX(version),0) FROM gosmig`).Scan(&versions, &maxVersion); err != nil { return o, err }
	o.CustodyBeforeEffect = effectAt.Valid && !custodyAt.After(effectAt.Time)
	o.PostconditionExact = columns == 5 && totalColumns == 5 && effects == 1 && matching == 1 && versions == 1 && maxVersion == 1 && o.CustodyBeforeEffect
	if o.PostconditionExact { o.Knowledge, o.Disposition = "VERIFIED", "CLOSED" }
	return o, tx.Commit()
}
