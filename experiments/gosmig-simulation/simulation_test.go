package simulation

import (
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	upstreamCommit = "f2cc69c685d654990d01582cb68b2c5b097cb36d"
	upstreamVersion = "v0.0.0-20251102200842-f2cc69c685d6"
	oracleBlob = "37e2e0a0867fa78df37f9d4243a1c4107d62094b"
	registrationCommit = "efdffa811a272128248476b273392feb3d369814"
)

type expected struct {
	WorkerExits []int `json:"worker_exits"`
	Effects int `json:"effects"`
	Versions int `json:"versions"`
	Custody int `json:"custody"`
	Observation string `json:"observation"`
	K07Disposition string `json:"k07_disposition"`
}

type registeredCase struct {
	CaseID string `json:"case_id"`
	Schedule string `json:"schedule"`
	Faults []string `json:"faults"`
	Expected expected `json:"expected"`
}

type registration struct {
	SchemaVersion string `json:"schema_version"`
	ExperimentID string `json:"experiment_id"`
	Classification string `json:"classification"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	Cases []registeredCase `json:"cases"`
}

type snapshot struct {
	Authority json.RawMessage `json:"authority"`
	Custody json.RawMessage `json:"custody"`
	Metadata json.RawMessage `json:"metadata"`
	Target json.RawMessage `json:"target"`
	Effects int `json:"effects"`
	Versions int `json:"versions"`
	CustodyCount int `json:"custody_count"`
}

type workerResult struct {
	Fault string `json:"fault"`
	ExitCode int `json:"exit_code"`
	Output string `json:"output"`
	Events []event `json:"events"`
	Before snapshot `json:"before"`
	After snapshot `json:"after"`
}

type caseResult struct {
	CaseID string `json:"case_id"`
	Schedule string `json:"schedule"`
	OriginalPermit permit `json:"original_permit"`
	RequestedPermit *permit `json:"requested_permit,omitempty"`
	Workers []workerResult `json:"workers"`
	Final snapshot `json:"final"`
	Observations []observation `json:"observations"`
	ObservationLabel string `json:"observation_label"`
	ObservationUnchanged bool `json:"observation_unchanged"`
	ReadOnlyMutationDenied bool `json:"read_only_mutation_denied"`
	Trace map[string]any `json:"trace,omitempty"`
}

type evidence struct {
	SchemaVersion string `json:"schema_version"`
	ExperimentID string `json:"experiment_id"`
	Classification string `json:"classification"`
	SourceHead string `json:"source_head"`
	RegistrationCommit string `json:"registration_commit"`
	RegistrationBlob string `json:"registration_blob"`
	UpstreamCommit string `json:"upstream_commit"`
	UpstreamVersion string `json:"upstream_version"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	PostgreSQLVersion string `json:"postgresql_version"`
	IndependentParticipation bool `json:"independent_participation"`
	D03Pass bool `json:"d03_pass"`
	Passed bool `json:"passed"`
	Cases []caseResult `json:"cases"`
}

// This test binary is the real subprocess executable. os.Exit deliberately
// bypasses defers in crash schedules; the database sees the connection die.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("GS_HELPER")
	if mode == "" { return }
	var err error
	switch mode {
	case "migration":
		var data []byte
		data, err = os.ReadFile(os.Getenv("GS_PERMIT"))
		var p permit
		if err == nil { err = json.Unmarshal(data, &p) }
		if err == nil { err = runMigration(p) }
	case "observe":
		var o observation
		o, err = observe(os.Getenv("GS_EFFECT"))
		if err == nil { err = writeJSON(os.Getenv("GS_OBSERVATION"), o) }
	default:
		err = errors.New("unknown helper mode")
	}
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(40) }
	os.Exit(0)
}

func must(t *testing.T, err error) { t.Helper(); if err != nil { t.Fatal(err) } }

func roleDSN(t *testing.T, role, schema string) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("GOSMIG_SIM_ADMIN_DSN")); must(t, err)
	if role != "" { u.User = url.UserPassword(role, "fixture-only") }
	q := u.Query(); q.Set("search_path", schema); q.Set("connect_timeout", "5"); u.RawQuery = q.Encode()
	return u.String()
}

func initRoles(t *testing.T, db *sql.DB) {
	for _, role := range []string{"gs_worker", "gs_observer"} {
		var exists bool
		must(t, db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists))
		if !exists { _, err := db.Exec(`CREATE ROLE `+role+` LOGIN PASSWORD 'fixture-only'`); must(t, err) }
	}
}

func initSchema(t *testing.T, schema string) *sql.DB {
	t.Helper()
	db, err := openDB(roleDSN(t, "", "public")); must(t, err)
	_, err = db.Exec(`CREATE SCHEMA `+schema); must(t, err)
	_ = db.Close()
	db, err = openDB(roleDSN(t, "", schema)); must(t, err)
	queries := []string{
		`REVOKE ALL ON SCHEMA `+schema+` FROM PUBLIC`,
		`GRANT USAGE, CREATE ON SCHEMA `+schema+` TO gs_worker`,
		`GRANT USAGE ON SCHEMA `+schema+` TO gs_observer`,
		`CREATE TABLE authority (singleton BOOLEAN PRIMARY KEY CHECK (singleton), policy_epoch BIGINT NOT NULL, state_epoch BIGINT NOT NULL, fence BIGINT NOT NULL, owner TEXT NOT NULL)`,
		`INSERT INTO authority VALUES (TRUE,1,1,1,'worker-a')`,
		`CREATE TABLE custody (effect_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE, permit JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`,
		createMetadata,
		`GRANT SELECT, UPDATE ON authority TO gs_worker`,
		`GRANT SELECT, INSERT ON custody, gosmig TO gs_worker`,
		`GRANT SELECT ON authority, custody, gosmig TO gs_observer`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE gs_worker IN SCHEMA `+schema+` GRANT SELECT ON TABLES TO gs_observer`,
	}
	for _, q := range queries { _, err := db.Exec(q); must(t, err) }
	t.Cleanup(func(){ _=db.Close() })
	return db
}

func issue(t *testing.T, db *sql.DB, id, attempt string, ttl time.Duration) permit {
	t.Helper()
	p := permit{Profile:profile, EffectID:"effect."+id, AttemptID:"attempt."+id+"."+attempt}
	var now time.Time
	must(t, db.QueryRow(`SELECT current_database(), current_schema(), policy_epoch, state_epoch, fence, owner, clock_timestamp() FROM authority WHERE singleton`).
		Scan(&p.Database, &p.Schema, &p.PolicyEpoch, &p.StateEpoch, &p.Fence, &p.Owner, &now))
	must(t, db.QueryRow(selectVersion).Scan(&p.ExpectedVersion))
	p.ExpiresAt = now.Add(ttl)
	p.ActionRef = actionRef(p, createTarget)
	p.Signature = p.signature()
	return p
}

func capture(t *testing.T, db *sql.DB) snapshot {
	t.Helper()
	s := snapshot{Target:json.RawMessage("null")}
	var authority, custody, metadata string
	must(t, db.QueryRow(`SELECT to_jsonb(a)::text FROM authority a WHERE singleton`).Scan(&authority))
	must(t, db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY effect_id), '[]'::jsonb)::text FROM custody c`).Scan(&custody))
	must(t, db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY version), '[]'::jsonb)::text FROM gosmig g`).Scan(&metadata))
	s.Authority, s.Custody, s.Metadata = json.RawMessage(authority), json.RawMessage(custody), json.RawMessage(metadata)
	var rows []json.RawMessage
	must(t, json.Unmarshal(s.Custody, &rows)); s.CustodyCount = len(rows)
	must(t, json.Unmarshal(s.Metadata, &rows)); s.Versions = len(rows)
	var exists bool
	must(t, db.QueryRow(`SELECT to_regclass('migrated_items') IS NOT NULL`).Scan(&exists))
	if exists {
		var target string
		must(t, db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY effect_id), '[]'::jsonb)::text FROM migrated_items m`).Scan(&target))
		s.Target = json.RawMessage(target)
		must(t, json.Unmarshal(s.Target, &rows)); s.Effects = len(rows)
	}
	return s
}

type runningWorker struct {
	cmd *exec.Cmd
	output *bytes.Buffer
	eventsPath string
	barrierPath string
	before snapshot
	fault string
}

func childCommand(t *testing.T, env map[string]string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	exe, err := os.Executable(); must(t, err)
	cmd := exec.Command(exe, "-test.run=^TestHelperProcess$")
	cmd.Env = os.Environ()
	for k, v := range env { cmd.Env = append(cmd.Env, k+"="+v) }
	output := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = output, output
	return cmd, output
}

func startWorker(t *testing.T, db *sql.DB, p permit, fault string, governed, tamper bool) *runningWorker {
	t.Helper()
	dir := t.TempDir()
	permitPath := filepath.Join(dir, "permit.json"); must(t, writeJSON(permitPath, p))
	env := map[string]string{
		"GS_HELPER":"migration", "GS_DSN":roleDSN(t,"gs_worker",p.Schema), "GS_PERMIT":permitPath,
		"GS_FAULT":fault, "GS_EVENTS":filepath.Join(dir,"events.jsonl"), "GS_BARRIER":filepath.Join(dir,"barrier"),
		"GS_GOVERNED":"0", "GS_TAMPER_SQL":"0",
	}
	if governed { env["GS_GOVERNED"] = "1" }; if tamper { env["GS_TAMPER_SQL"] = "1" }
	cmd, output := childCommand(t, env)
	w := &runningWorker{cmd:cmd, output:output, eventsPath:env["GS_EVENTS"], barrierPath:env["GS_BARRIER"], before:capture(t,db), fault:fault}
	must(t, cmd.Start())
	t.Cleanup(func(){ if cmd.ProcessState == nil { _=cmd.Process.Kill(); _=cmd.Wait() } })
	return w
}

func waitWorker(t *testing.T, db *sql.DB, w *runningWorker) workerResult {
	t.Helper()
	err := w.cmd.Wait()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) { t.Fatal(err) }
		exitCode = ee.ExitCode()
	}
	r := workerResult{Fault:w.fault, ExitCode:exitCode, Output:w.output.String(), Before:w.before, After:capture(t,db), Events:[]event{}}
	data, err := os.ReadFile(w.eventsPath)
	if err == nil {
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			if len(line) == 0 { continue }
			var e event; must(t, json.Unmarshal(line,&e)); r.Events = append(r.Events,e)
		}
	} else if !errors.Is(err,os.ErrNotExist) { t.Fatal(err) }
	return r
}

func waitReady(t *testing.T, w *runningWorker) {
	t.Helper()
	deadline := time.Now().Add(10*time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(w.barrierPath+".ready"); err == nil { return }
		time.Sleep(10*time.Millisecond)
	}
	t.Fatal("worker did not reach barrier")
}

func release(t *testing.T, w *runningWorker) { t.Helper(); must(t, os.WriteFile(w.barrierPath+".release", []byte("release\n"),0600)) }

func awaitExpired(t *testing.T, db *sql.DB, p permit) {
	t.Helper()
	deadline := time.Now().Add(10*time.Second)
	for time.Now().Before(deadline) {
		var expired bool
		must(t, db.QueryRow(`SELECT clock_timestamp() >= $1`,p.ExpiresAt).Scan(&expired))
		if expired { return }
		time.Sleep(10*time.Millisecond)
	}
	t.Fatal("permit did not expire on database clock")
}

func readonlyProbe(t *testing.T, p permit) bool {
	t.Helper()
	db, err := openDB(roleDSN(t,"gs_observer",p.Schema)); must(t,err); defer db.Close()
	for _, q := range []string{`UPDATE custody SET permit=permit WHERE FALSE`, `UPDATE gosmig SET version=version WHERE FALSE`, `CREATE TABLE observer_should_not_create (id INTEGER)`} {
		_, err := db.Exec(q)
		var pe *pgconn.PgError
		if !errors.As(err,&pe) || pe.Code != "42501" { t.Fatalf("observer mutation not denied by PostgreSQL: %v",err) }
	}
	return true
}

func observeTwice(t *testing.T, db *sql.DB, p permit, r *caseResult) {
	t.Helper()
	before := capture(t,db)
	r.ReadOnlyMutationDenied = readonlyProbe(t,p)
	for i:=0; i<2; i++ {
		dir := t.TempDir(); outputPath:=filepath.Join(dir,"observation.json")
		cmd, output := childCommand(t,map[string]string{"GS_HELPER":"observe","GS_DSN":roleDSN(t,"gs_observer",p.Schema),"GS_EFFECT":p.EffectID,"GS_OBSERVATION":outputPath})
		if err := cmd.Run(); err != nil { t.Fatalf("read-only observer failed: %v: %s",err,output.String()) }
		data, err := os.ReadFile(outputPath); must(t,err)
		var o observation; must(t,json.Unmarshal(data,&o)); r.Observations=append(r.Observations,o)
		if o.EffectID != p.EffectID || o.AttemptID != p.AttemptID || o.ActionRef != p.ActionRef || o.DispatchAccepted != nil || !o.ObserverReadOnly {
			t.Fatalf("observation lost original lineage or claimed a receipt: %+v",o)
		}
	}
	after := capture(t,db)
	r.ObservationUnchanged = reflect.DeepEqual(before,after)
	if !r.ObservationUnchanged { t.Fatal("read-only recovery changed database state, timestamps or original custody") }
	if r.Observations[0].Knowledge != r.Observations[1].Knowledge || r.Observations[0].Disposition != r.Observations[1].Disposition || r.Observations[0].CustodySHA256 != r.Observations[1].CustodySHA256 { t.Fatal("repeated observation changed disposition or custody") }
	r.ObservationLabel = r.Observations[0].Knowledge+"/"+r.Observations[0].Disposition
}

func hasReason(r caseResult, reason string) bool {
	for _, w := range r.Workers { for _, e := range w.Events { if e.Reason == reason { return true } } }
	return false
}

func custodyOrdered(r caseResult) bool {
	if r.Final.Effects == 0 { return true }
	for _, o := range r.Observations { if o.CustodyBeforeEffect { return true } }
	return false
}

// These are mappings from native facts into the existing evaluator input,
// not a second evaluator. The root package evaluates the frozen dispositions.
func nativeTrace(r caseResult) map[string]any {
	possible := r.Final.CustodyCount > 0 && (r.CaseID == "G05" || r.CaseID == "G06" || r.CaseID == "G07" || r.CaseID == "G10" || r.CaseID == "G11")
	verified := (r.CaseID == "G05" || r.CaseID == "G06") && len(r.Observations)>0 && r.Observations[0].PostconditionExact
	emit := r.CaseID == "G01" || r.CaseID == "G08"
	staleWorkerEffects := 0
	if len(r.Workers)>0 { staleWorkerEffects = r.Workers[0].After.Effects }
	input := map[string]any{
		"domain":"gosmig_postgresql_owner_simulation", "profile_trusted":true, "profile_adequate":true,
		"revision_exact":!hasReason(r,"REVISION"), "current_witnesses":!hasReason(r,"EXPIRED"),
		"relevant_state_bound":true, "relevant_state_current":!hasReason(r,"STATE"),
		"required_independence":false, "independence_satisfied":false,
		"enforcement_boundary_declared":true, "complete_mediation":true, "effect_can_survive_process":true,
		"custody_before_dispatch":custodyOrdered(r), "possible_effect_exists":possible,
		"substitution_requested":r.CaseID=="G11", "safe_substitution_proven":false,
		"observation_gap":false, "terminal_unknown_authorized":false, "residual_custody":r.Final.CustodyCount>0,
		"takeover_requested":r.CaseID=="G08", "stale_worker_can_act":r.CaseID=="G08" && staleWorkerEffects>0,
		"destination_fencing_effective":r.CaseID=="G08" && hasReason(r,"FENCE") && staleWorkerEffects==0,
		"takeover_blocked":false, "hard_precondition_required":true, "destination_cas":true,
		"verified_outcome_claim":verified, "postcondition_exact":len(r.Observations)>0 && r.Observations[0].PostconditionExact,
		"already_satisfied":false, "seed_mode":"", "emit_effect":emit && r.Final.Effects==1,
	}
	return map[string]any{"case_id":r.CaseID,"fault_schedule":r.Schedule,"action_ref":r.OriginalPermit.ActionRef,"effect_id":r.OriginalPermit.EffectID,"attempt_id":r.OriginalPermit.AttemptID,"observation_ref":"native-postgresql:"+r.CaseID,"input":input}
}

func checkResult(t *testing.T, c registeredCase, r caseResult) {
	t.Helper()
	var exits []int
	for _, w := range r.Workers { exits=append(exits,w.ExitCode) }
	if !reflect.DeepEqual(exits,c.Expected.WorkerExits) || r.Final.Effects!=c.Expected.Effects || r.Final.Versions!=c.Expected.Versions || r.Final.CustodyCount!=c.Expected.Custody || r.ObservationLabel!=c.Expected.Observation {
		t.Fatalf("fixed registration failed: expected=%+v exits=%v effects=%d versions=%d custody=%d observation=%s workers=%+v",c.Expected,exits,r.Final.Effects,r.Final.Versions,r.Final.CustodyCount,r.ObservationLabel,r.Workers)
	}
	for _, o := range r.Observations {
		if o.PostconditionExact != (c.Expected.Observation=="VERIFIED/CLOSED") { t.Fatal("postcondition contradicted registered disposition") }
	}
	reasons := map[string]string{"G02":"STATE","G03":"EXPIRED","G04":"REVISION","G08":"FENCE","G09":"EXPIRED","G11":"POSSIBLE_EFFECT"}
	if reason := reasons[c.CaseID]; reason!="" && !hasReason(r,reason) { t.Fatalf("expected native rejection reason %s missing",reason) }
	if c.CaseID=="G08" && (r.Workers[0].After.Effects!=0 || r.Workers[0].After.Versions!=0 || r.Workers[0].After.CustodyCount!=0) { t.Fatal("stale worker was not blocked before fresh worker execution") }
	if c.CaseID=="G11" && !reflect.DeepEqual(r.Workers[1].Before,r.Workers[1].After) { t.Fatal("blind replay changed original destination state or custody") }
	if c.CaseID=="G05" || c.CaseID=="G06" || c.CaseID=="G11" {
		for _, e := range r.Workers[0].Events { if e.Stage=="commit-receipt" { t.Fatal("lost receipt path retained a success receipt") } }
	}
}

func TestNativeSimulation(t *testing.T) {
	if os.Getenv("GOSMIG_SIM_ADMIN_DSN")=="" { t.Fatal("this suite requires an isolated real PostgreSQL service") }
	data, err := os.ReadFile("../../testdata/governed-action/gosmig-simulation/registration-v1.json"); must(t,err)
	var reg registration; must(t,json.Unmarshal(data,&reg))
	if reg.FrozenOracleBlob!=oracleBlob || len(reg.Cases)!=13 { t.Fatal("registration changed") }
	h:=sha1.New(); _,_=fmt.Fprintf(h,"blob %d%c",len(data),byte(0)); _,_=h.Write(data)
	report:=evidence{SchemaVersion:"governed-action.gosmig-native-evidence/v1",ExperimentID:reg.ExperimentID,Classification:reg.Classification,SourceHead:os.Getenv("GS_SOURCE_HEAD"),RegistrationCommit:registrationCommit,RegistrationBlob:hex.EncodeToString(h.Sum(nil)),UpstreamCommit:upstreamCommit,UpstreamVersion:upstreamVersion,FrozenOracleBlob:oracleBlob,Cases:[]caseResult{}}
	root,err:=openDB(roleDSN(t,"","public")); must(t,err); defer root.Close()
	initRoles(t,root)
	must(t,root.QueryRow(`SELECT version()`).Scan(&report.PostgreSQLVersion))
	defer func(){ report.Passed=!t.Failed(); out:=os.Getenv("GOSMIG_SIM_EVIDENCE"); if out=="" { out="native-evidence.json" }; if err:=writeJSON(out,report); err!=nil { t.Error(err) } }()
	for _, c:=range reg.Cases {
		t.Run(c.CaseID,func(t *testing.T){
			schema:="gs_"+strings.ToLower(c.CaseID)
			db:=initSchema(t,schema)
			ttl:=30*time.Second
			if c.CaseID=="G03" { ttl=-time.Second }
			if c.CaseID=="G06" || c.CaseID=="G09" { ttl=2*time.Second }
			p:=issue(t,db,c.CaseID,"a",ttl)
			r:=caseResult{CaseID:c.CaseID,Schedule:c.Schedule,OriginalPermit:p,Workers:[]workerResult{},Observations:[]observation{},ObservationLabel:"NOT_RUN"}
			// Preserve partial evidence too; failures do not silently disappear.
			defer func(){ r.Final=capture(t,db); if strings.HasPrefix(c.CaseID,"G") { r.Trace=nativeTrace(r) }; report.Cases=append(report.Cases,r) }()
			if c.CaseID=="N02" || c.CaseID=="G02" { _,err:=db.Exec(`UPDATE authority SET policy_epoch=policy_epoch+1, state_epoch=state_epoch+1 WHERE singleton`); must(t,err) }
			governed:=strings.HasPrefix(c.CaseID,"G")
			w:=startWorker(t,db,p,c.Faults[0],governed,c.CaseID=="G04")
			if c.CaseID=="G08" {
				waitReady(t,w)
				var fence int64
				must(t,db.QueryRow(`UPDATE authority SET fence=fence+1, owner='worker-b' WHERE singleton AND fence=1 RETURNING fence`).Scan(&fence))
				if fence!=2 { t.Fatal("destination fence did not advance") }
				release(t,w); r.Workers=append(r.Workers,waitWorker(t,db,w))
				p=issue(t,db,c.CaseID,"b",30*time.Second); r.OriginalPermit=p
				w=startWorker(t,db,p,"none",true,false)
			}
			if c.CaseID=="G09" {
				waitReady(t,w)
				// A real competing UPDATE must block behind the held destination
				// lock. Cancellation leaves authority unchanged.
				ctx,cancel:=context.WithTimeout(context.Background(),150*time.Millisecond)
				_,err:=db.ExecContext(ctx,`UPDATE authority SET fence=fence+1 WHERE singleton`); cancel()
				if err==nil { t.Fatal("destination lock allowed a concurrent authority change") }
				awaitExpired(t,db,p); release(t,w)
			}
			r.Workers=append(r.Workers,waitWorker(t,db,w))
			if c.CaseID=="G06" { awaitExpired(t,db,p) }
			if c.CaseID=="G10" { _,err:=db.Exec(`UPDATE migrated_items SET action_ref='sha256:unrelated-revision'`); must(t,err) }
			if c.CaseID=="G11" {
				fresh:=issue(t,db,c.CaseID,"b",30*time.Second); r.RequestedPermit=&fresh
				w=startWorker(t,db,fresh,"none",true,false); r.Workers=append(r.Workers,waitWorker(t,db,w))
			}
			if c.Expected.Custody>0 { observeTwice(t,db,p,&r) }
			r.Final=capture(t,db)
			checkResult(t,c,r)
		})
	}
}

func TestAdapterRejectsNontransactionalMutation(t *testing.T) {
	g:=&guardDB{}
	if _,err:=g.ExecContext(context.Background(),`CREATE TABLE bypass (id INT)`); err==nil { t.Fatal("unmediated SQL was accepted") }
}
