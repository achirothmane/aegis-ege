package simulation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// Cycle 5 removes the separate completion/receipt table as well as mutable
// custody. The one physical business-effect row is also the immutable causal
// record. This is representation unification, not erasure of effect identity,
// actual-attempt attribution, retry exclusion, or current-state closure.
func setupUnifiedEffectRecord(t *testing.T) *noCustodyFixture {
	t.Helper()
	f := setupNoCustody(t)
	for _, statement := range []string{
		"DROP TABLE " + nativeFenceTable("effects"),
		"DROP TABLE " + nativeFenceTable("ledger"),
		"CREATE TABLE " + nativeFenceTable("ledger") + " (" +
			"effect_id TEXT PRIMARY KEY, amount BIGINT NOT NULL, attempt_id TEXT NOT NULL, target TEXT NOT NULL, " +
			"owner_id TEXT NOT NULL, owner_kind TEXT NOT NULL, generation BIGINT NOT NULL, " +
			"operation TEXT NOT NULL, from_revision TEXT NOT NULL, to_revision TEXT NOT NULL, " +
			"from_digest TEXT NOT NULL, to_digest TEXT NOT NULL, admission_binding TEXT NOT NULL, " +
			"authority_epoch BIGINT NOT NULL, authority_generation BIGINT NOT NULL, authority_active BOOLEAN NOT NULL, " +
			"created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
	} {
		if _, err := f.a.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	f.policy.CaseID = "unified-effect-record"
	f.policy.AdmissionPolicyHash = v.ContentDigest([]byte("one atomic business-effect row is also the exact causal completion; independent current-state closure"))
	return f
}

func executeUnifiedEffectRecord(ctx context.Context, db *sql.DB, req r.Request, env v.Envelope, policy v.Policy, beforeCommit func() error) error {
	var admission v.Admission
	if err := v.Decode(env.Payload, &admission); err != nil {
		return err
	}
	keyID := policy.RoleKeys["admission"]
	key, keyErr := base64.StdEncoding.DecodeString(policy.PublicKeys[keyID])
	sig, sigErr := base64.StdEncoding.DecodeString(env.Signature)
	var compact bytes.Buffer
	if err := json.Compact(&compact, env.Payload); err != nil {
		return err
	}
	message := append([]byte(v.Schema+"\x00admission\x00"), compact.Bytes()...)
	if env.KeyID != keyID || keyErr != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, sig) {
		return errNativeUntrusted
	}
	binding, err := r.AdmissionBindingDigest(req)
	if err != nil {
		return err
	}
	if !req.Executor.Complete() || req.AttemptID == "" || req.Admission.BindingDigest != binding || admission.RequestBinding != binding || admission.ObservedBefore != noCustodyState(req.Current) || admission.AllowedOperation != req.Transition.Operation || admission.BuildSHA != policy.BuildSHA || admission.CaseID != policy.CaseID || admission.PolicyHash != policy.AdmissionPolicyHash || !admission.AuthorityActive || admission.AuthorityEpoch == 0 || admission.AuthorityGeneration == 0 {
		return errNativeAuthority
	}
	effect, err := r.EffectIdentity(req)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var revision, digest string
	if err := tx.QueryRowContext(ctx, "SELECT revision,digest FROM "+nativeFenceTable("target_state")+" WHERE target=$1 FOR UPDATE", req.Current.Target).Scan(&revision, &digest); err != nil {
		return err
	}
	var active bool
	var epoch, generation uint64
	if err := tx.QueryRowContext(ctx, "SELECT active,epoch,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1 FOR SHARE", binding).Scan(&active, &epoch, &generation); err != nil {
		return err
	}
	if !active || epoch != admission.AuthorityEpoch || generation != admission.AuthorityGeneration {
		return errNativeAuthority
	}
	var completed bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM "+nativeFenceTable("ledger")+" WHERE effect_id=$1)", effect).Scan(&completed); err != nil {
		return err
	}
	if completed {
		return errNativeCompleted
	}
	if revision != req.Current.Revision || digest != req.Current.Digest {
		return errNativeState
	}

	// This INSERT is the business effect itself. There is no second completion
	// write and no separate receipt table: the row carries its own exact cause.
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+nativeFenceTable("ledger")+" (effect_id,amount,attempt_id,target,owner_id,owner_kind,generation,operation,from_revision,to_revision,from_digest,to_digest,admission_binding,authority_epoch,authority_generation,authority_active) VALUES ($1,1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,TRUE)",
		effect, req.AttemptID, req.Current.Target, req.Executor.ID, req.Executor.Kind, req.Transition.Operation, req.Current.Revision, req.Transition.To.Revision, req.Current.Digest, req.Transition.To.Digest, req.Admission.BindingDigest, admission.AuthorityEpoch, admission.AuthorityGeneration); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE "+nativeFenceTable("target_state")+" SET revision=$1,digest=$2 WHERE target=$3", req.Transition.To.Revision, req.Transition.To.Digest, req.Current.Target); err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func observeUnifiedEffectRecord(ctx context.Context, db *sql.DB, req r.Request, withheld bool) (v.Destination, error) {
	d := v.Destination{}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+nativeFenceTable("ledger")).Scan(&d.EffectCount); err != nil {
		return d, err
	}
	if err := db.QueryRowContext(ctx, "SELECT active,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1", req.Admission.BindingDigest).Scan(&d.AuthorityCurrentlyActive, &d.CurrentAuthorityGeneration); err != nil {
		return d, err
	}
	if withheld {
		d.ObservationError = "exact unified effect observation withheld; UNKNOWN grants no execution permission"
		return d, nil
	}
	d.Observed.Target = req.Current.Target
	if err := db.QueryRowContext(ctx, "SELECT revision,digest FROM "+nativeFenceTable("target_state")+" WHERE target=$1", req.Current.Target).Scan(&d.Observed.Revision, &d.Observed.Digest); err != nil {
		return d, err
	}
	effect, err := r.EffectIdentity(req)
	if err != nil {
		return d, err
	}
	var c v.Commit
	var committedAt string
	err = db.QueryRowContext(ctx, "SELECT effect_id,attempt_id,owner_id,owner_kind,generation,admission_binding,authority_epoch,authority_generation,authority_active,operation,target,from_revision,from_digest,to_revision,to_digest,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM "+nativeFenceTable("ledger")+" WHERE effect_id=$1 ORDER BY created_at LIMIT 1", effect).Scan(&c.EffectID, &c.AttemptID, &c.Owner.ID, &c.Owner.Kind, &c.CustodyGeneration, &c.AdmissionBinding, &c.AuthorityEpoch, &c.AuthorityGeneration, &c.AuthorityActive, &c.Operation, &c.Before.Target, &c.Before.Revision, &c.Before.Digest, &c.After.Revision, &c.After.Digest, &committedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("unified native effect observation: %w", err)
	}
	c.After.Target, c.CommittedAt = c.Before.Target, committedAt
	d.Commit = &c
	return d, nil
}

type unifiedEffectProcessInput struct {
	Request   r.Request
	Admission v.Envelope
	Policy    v.Policy
	Withheld  bool
}

func TestPostgresCompositeUnifiedEffectRecordProcess(t *testing.T) {
	mode := os.Getenv("UNIFIED_EFFECT_MODE")
	if mode == "" {
		return
	}
	var input unifiedEffectProcessInput
	if err := json.Unmarshal([]byte(os.Getenv("UNIFIED_EFFECT_INPUT")), &input); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(os.Getenv("UNIFIED_EFFECT_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if mode == "observe" {
		d, err := observeUnifiedEffectRecord(ctx, db, input.Request, input.Withheld)
		if err != nil {
			t.Fatal(err)
		}
		_, mutationErr := db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest=digest")
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			Destination    v.Destination
			MutationDenied bool
			PID            int
		}{d, mutationErr != nil && strings.Contains(mutationErr.Error(), "permission denied"), os.Getpid()}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	barrier := func(name string, code int) {
		fmt.Fprintln(os.Stdout, name)
		var release [1]byte
		if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
			os.Exit(111)
		}
		os.Exit(code)
	}
	var beforeCommit func() error
	switch mode {
	case "pre-commit":
		beforeCommit = func() error {
			barrier("UNIFIED_EFFECT_UNCOMMITTED", 109)
			return nil
		}
	case "post-commit":
	default:
		t.Fatal("unknown unified effect process mode")
	}
	if err := executeUnifiedEffectRecord(ctx, db, input.Request, input.Admission, input.Policy, beforeCommit); err != nil {
		t.Fatal(err)
	}
	barrier("UNIFIED_EFFECT_COMMITTED", 110)
}

func unifiedEffectCommand(t *testing.T, f *noCustodyFixture, mode, dsn string, withheld bool) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresCompositeUnifiedEffectRecordProcess$")
	input := unifiedEffectProcessInput{Request: f.req, Admission: f.seal(t, "admission", f.admission(f.req, 1)), Policy: f.policy, Withheld: withheld}
	raw, err := json.Marshal(input)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "UNIFIED_EFFECT_MODE=" + mode, "UNIFIED_EFFECT_DSN=" + dsn, "UNIFIED_EFFECT_INPUT=" + string(raw)}
	return cmd, cancel
}

func unifiedEffectCrash(t *testing.T, f *noCustodyFixture, preCommit bool) {
	t.Helper()
	mode, marker, code := "post-commit", "UNIFIED_EFFECT_COMMITTED", 110
	if preCommit {
		mode, marker, code = "pre-commit", "UNIFIED_EFFECT_UNCOMMITTED", 109
	}
	cmd, cancel := unifiedEffectCommand(t, f, mode, os.Getenv("GOSMIG_SIM_ADMIN_DSN"), false)
	defer cancel()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != marker {
			t.Fatalf("unified effect barrier failed: %q %s", line, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("unified effect barrier timed out")
	}
	want := uint64(1)
	if preCommit {
		want = 0
	}
	if got := unifiedEffectTally(t, f); got != want {
		t.Fatalf("unified transaction visibility mismatch: got=%d want=%d", got, want)
	}
	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != code {
		t.Fatalf("unified effect process did not die at the required boundary: %v %s", err, stderr.String())
	}
}

func unifiedEffectReadProcess(t *testing.T, f *noCustodyFixture, withheld bool) v.Destination {
	t.Helper()
	cmd, cancel := unifiedEffectCommand(t, f, "observe", compositeReadDSN(t, f.a), withheld)
	defer cancel()
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("fresh unified native observer failed: %v %s", err, raw)
	}
	var result struct {
		Destination    v.Destination
		MutationDenied bool
		PID            int
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.MutationDenied || result.PID == os.Getpid() || result.PID <= 0 {
		t.Fatal("unified native recovery lost process or mutation-authority separation")
	}
	return result.Destination
}

func unifiedEffectTally(t *testing.T, f *noCustodyFixture) uint64 {
	t.Helper()
	var count uint64
	if err := f.a.db.QueryRow("SELECT COUNT(*) FROM " + nativeFenceTable("ledger")).Scan(&count); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"custody", "effects"} {
		var absent bool
		if err := f.a.db.QueryRow("SELECT to_regclass($1) IS NULL", nativeFenceTable(table)).Scan(&absent); err != nil || !absent {
			t.Fatalf("unified path recreated separate %s relation", table)
		}
	}
	return count
}

func TestPostgresCompositeUnifiedEffectRecordCrashRecovery(t *testing.T) {
	for _, name := range []string{"CLOSED", "UNKNOWN", "PRE_COMMIT"} {
		t.Run(name, func(t *testing.T) {
			f := setupUnifiedEffectRecord(t)
			unifiedEffectCrash(t, f, name == "PRE_COMMIT")
			wantEffects := uint64(1)
			if name == "PRE_COMMIT" {
				wantEffects = 0
			}
			next := f.successor(t)
			d := unifiedEffectReadProcess(t, f, name == "UNKNOWN")
			closure, cause := "CLOSED", "EXACT_COMMIT_RECORD"
			if name == "UNKNOWN" {
				closure, cause = "UNKNOWN", "UNPROVEN"
			} else if name == "PRE_COMMIT" {
				closure, cause = "UNKNOWN", "STATE_ONLY"
			}
			f.inspect(t, "unified/"+name+"/original", f.req, 1, d, closure, cause, true)
			if unifiedEffectTally(t, f) != wantEffects {
				t.Fatal("read-only recovery changed the unified effect tally")
			}
			old := f.seal(t, "admission", f.admission(f.req, 1))
			if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, old, f.policy, nil); !errors.Is(err, errNativeAuthority) {
				t.Fatalf("stale authority executed on unified path: %v", err)
			}
			fresh := f.seal(t, "admission", f.admission(next, 2))
			err := executeUnifiedEffectRecord(context.Background(), f.a.db, next, fresh, f.policy, nil)
			if name == "PRE_COMMIT" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errNativeCompleted) {
				t.Fatalf("unified replay exclusion erased: committed_effects=%d successor_error=%v", unifiedEffectTally(t, f), err)
			}
			if unifiedEffectTally(t, f) != 1 {
				t.Fatal("unified effect path allowed a second logical effect")
			}
			actual, err := observeUnifiedEffectRecord(context.Background(), f.a.db, next, false)
			if err != nil {
				t.Fatal(err)
			}
			if name == "PRE_COMMIT" {
				f.inspect(t, "unified/"+name+"/successor", next, 2, actual, "CLOSED", "EXACT_COMMIT_RECORD", true)
			} else {
				f.inspect(t, "unified/"+name+"/foreign-successor", next, 2, actual, "CLOSED", "EXACT_COMMIT_RECORD", false)
			}
		})
	}
}

func TestPostgresCompositeUnifiedEffectRecordReplayExclusion(t *testing.T) {
	f := setupUnifiedEffectRecord(t)
	unifiedEffectCrash(t, f, false)
	next := f.successor(t)
	err := executeUnifiedEffectRecord(context.Background(), f.a.db, next, f.seal(t, "admission", f.admission(next, 2)), f.policy, nil)
	if count := unifiedEffectTally(t, f); count != 1 || !errors.Is(err, errNativeCompleted) {
		t.Fatalf("unified replay exclusion erased: committed_effects=%d successor_error=%v", count, err)
	}
}

func TestPostgresCompositeUnifiedEffectRecordConcurrentSuccessors(t *testing.T) {
	f := setupUnifiedEffectRecord(t)
	first := f.successor(t)
	second := first
	second.Executor.ID, second.AttemptID = "executor:C", "attempt:C"
	requests := []r.Request{first, second}
	envs := []v.Envelope{f.seal(t, "admission", f.admission(first, 2)), f.seal(t, "admission", f.admission(second, 2))}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results <- executeUnifiedEffectRecord(context.Background(), f.a.db, requests[i], envs[i], f.policy, nil)
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	committed, replayed := 0, 0
	for err := range results {
		if err == nil {
			committed++
		} else if errors.Is(err, errNativeCompleted) {
			replayed++
		} else {
			t.Fatal(err)
		}
	}
	if committed != 1 || replayed != 1 || unifiedEffectTally(t, f) != 1 {
		t.Fatal("concurrent unified contenders created ambiguous or duplicate effects")
	}
	d, err := observeUnifiedEffectRecord(context.Background(), f.a.db, first, false)
	if err != nil || d.Commit == nil {
		t.Fatal("unified native winner lacks intrinsic causal metadata")
	}
	winner, loser := first, second
	if d.Commit.AttemptID == second.AttemptID {
		winner, loser = second, first
	}
	f.inspect(t, "unified/concurrent/winner", winner, 2, d, "CLOSED", "EXACT_COMMIT_RECORD", true)
	f.inspect(t, "unified/concurrent/loser", loser, 2, d, "CLOSED", "EXACT_COMMIT_RECORD", false)
}

func TestPostgresCompositeUnifiedEffectRecordHistoricalCauseDoesNotCloseDrift(t *testing.T) {
	f := setupUnifiedEffectRecord(t)
	unifiedEffectCrash(t, f, false)
	before := unifiedEffectReadProcess(t, f, false)
	f.inspect(t, "unified/drift/before", f.req, 1, before, "CLOSED", "EXACT_COMMIT_RECORD", true)
	if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest='later-unified-state'"); err != nil {
		t.Fatal(err)
	}
	after := unifiedEffectReadProcess(t, f, false)
	oldReceipt, err := json.Marshal(before.Commit)
	if err != nil {
		t.Fatal(err)
	}
	currentReceipt, err := json.Marshal(after.Commit)
	if err != nil || string(oldReceipt) != string(currentReceipt) || unifiedEffectTally(t, f) != 1 {
		t.Fatal("later state changed the intrinsic historical cause or effect tally")
	}
	report := f.inspect(t, "unified/drift/after", f.req, 1, after, "CLOSED", "EXACT_COMMIT_RECORD", false)
	if report.Causality != "EXACT_COMMIT_RECORD" {
		t.Fatal("current closure erased the valid intrinsic historical cause")
	}
}
