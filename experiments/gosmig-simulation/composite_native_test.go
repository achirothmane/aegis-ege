package simulation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

// This is a bounded PostgreSQL profile experiment, not a production succession
// orchestrator. The policy identities are fixture trust assumptions inherited
// from the existing native adapter; SQL and process failures are real.

type postgresCompositeHead struct{ db *sql.DB }

func (s postgresCompositeHead) Load(ctx context.Context, id string) (journal.ExternalHead, error) {
	var h journal.ExternalHead
	err := s.db.QueryRowContext(ctx, "SELECT journal_id,sequence,head_hash,key_id FROM "+nativeFenceTable("history_head")+" WHERE journal_id=$1", id).Scan(&h.JournalID, &h.Sequence, &h.HeadHash, &h.KeyID)
	if errors.Is(err, sql.ErrNoRows) {
		err = journal.ErrExternalHeadNotFound
	}
	return h, err
}

func (s postgresCompositeHead) CompareAndAdvance(ctx context.Context, previous, next journal.ExternalHead) (journal.ExternalHead, error) {
	if previous.JournalID != next.JournalID || next.Sequence < previous.Sequence || (previous.KeyID != "" && next.Sequence == previous.Sequence && (next.HeadHash != previous.HeadHash || next.KeyID != previous.KeyID)) {
		return journal.ExternalHead{}, journal.ErrExternalHeadConflict
	}
	var result sql.Result
	var err error
	if previous.Sequence == 0 && previous.HeadHash == "" && previous.KeyID == "" {
		if next.Sequence != 0 {
			return journal.ExternalHead{}, journal.ErrExternalHeadConflict
		}
		result, err = s.db.ExecContext(ctx, "INSERT INTO "+nativeFenceTable("history_head")+" (journal_id,sequence,head_hash,key_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING", next.JournalID, next.Sequence, next.HeadHash, next.KeyID)
	} else {
		result, err = s.db.ExecContext(ctx, "UPDATE "+nativeFenceTable("history_head")+" SET sequence=$1,head_hash=$2,key_id=$3 WHERE journal_id=$4 AND sequence=$5 AND head_hash=$6 AND key_id=$7", next.Sequence, next.HeadHash, next.KeyID, next.JournalID, previous.Sequence, previous.HeadHash, previous.KeyID)
	}
	if err != nil {
		return journal.ExternalHead{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return journal.ExternalHead{}, err
	}
	if n != 1 {
		return journal.ExternalHead{}, journal.ErrExternalHeadConflict
	}
	return next, nil
}

// The native transaction commits; the callback acknowledgement never reaches
// ExecuteReservedFenced. The supervisor changes authority before terminating
// this process. This is callback acknowledgement loss, not packet fault injection.
type interruptAfterNativeCommit struct{ *postgresNativeFenceAdapter }

func (a interruptAfterNativeCommit) ExecuteFenced(ctx context.Context, transition gaRuntime.Transition, custody gaRuntime.FencedCustody) (gaRuntime.Acceptance, error) {
	acceptance, err := a.postgresNativeFenceAdapter.ExecuteFenced(ctx, transition, custody)
	if err != nil {
		return acceptance, err
	}
	fmt.Fprintln(os.Stdout, "NATIVE_COMMITTED")
	var release [1]byte
	if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
		os.Exit(94)
	}
	os.Exit(93)
	panic("unreachable")
}

type observeOnlyComposite struct {
	*postgresNativeFenceAdapter
	withheld       bool
	forbiddenCalls int
}

func (a *observeOnlyComposite) RetainCustody(context.Context, gaRuntime.Custody) error {
	a.forbiddenCalls++
	return errors.New("read-only recovery cannot reserve")
}
func (a *observeOnlyComposite) Execute(context.Context, gaRuntime.Transition, gaRuntime.Custody) (gaRuntime.Acceptance, error) {
	a.forbiddenCalls++
	return gaRuntime.Acceptance{}, errors.New("read-only recovery cannot execute")
}
func (a *observeOnlyComposite) LoadCustody(ctx context.Context, effect, attempt string) (gaRuntime.Custody, error) {
	c, err := a.LoadFencedCustody(ctx, effect, attempt)
	return gaRuntime.Custody{EffectID: c.EffectID, AttemptID: c.AttemptID, Target: c.Target, Owner: c.Owner}, err
}
func (a *observeOnlyComposite) Observe(ctx context.Context, transition gaRuntime.Transition, c gaRuntime.Custody) (gaRuntime.Observation, error) {
	if a.withheld {
		return gaRuntime.Observation{}, errors.New("exact observation intentionally withheld by the experiment")
	}
	fenced, err := a.LoadFencedCustody(ctx, c.EffectID, c.AttemptID)
	if err != nil {
		return gaRuntime.Observation{}, err
	}
	return a.ObserveFenced(ctx, transition, fenced)
}

type compositeRecoveryResult struct {
	Disposition     string                  `json:"disposition"`
	Cause           string                  `json:"cause,omitempty"`
	BoundaryEntered bool                    `json:"boundary_entered"`
	ForbiddenCalls  int                     `json:"forbidden_calls"`
	MutationDenied  bool                    `json:"mutation_denied"`
	Custody         gaRuntime.FencedCustody `json:"custody"`
}

// Helper runs only when launched explicitly by a test supervisor. It never
// counts as one of the corpus cases and cannot silently skip a required run.
func TestPostgresCompositeProcess(t *testing.T) {
	mode := os.Getenv("COMPOSITE_PROCESS_MODE")
	if mode == "" {
		return
	}
	var req gaRuntime.Request
	if err := json.Unmarshal([]byte(os.Getenv("COMPOSITE_REQUEST")), &req); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("GOSMIG_SIM_ADMIN_DSN")
	if mode == "recover" {
		dsn = os.Getenv("COMPOSITE_READ_DSN")
	}
	db, err := openDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &postgresNativeFenceAdapter{db: db, req: req}
	effect, err := gaRuntime.EffectIdentity(req)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := a.LoadFencedCustody(context.Background(), effect, req.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "execute" {
		result := gaRuntime.ExecuteReservedFenced(context.Background(), req, custody, interruptAfterNativeCommit{a})
		t.Fatalf("process unexpectedly returned from execution: %+v", result)
	}
	if mode != "recover" {
		t.Fatal("unknown process mode")
	}
	observer := &observeOnlyComposite{postgresNativeFenceAdapter: a, withheld: os.Getenv("COMPOSITE_WITHHOLD") == "1"}
	c := gaRuntime.Custody{EffectID: custody.EffectID, AttemptID: custody.AttemptID, Target: custody.Target, Owner: custody.Owner}
	recoverer := gaRuntime.Identity{ID: "recovery:read-only", Kind: "observer"}
	result := gaRuntime.Recover(context.Background(), gaRuntime.RecoveryRequest{Original: req, Recoverer: recoverer, RecoveryAuthorization: gaRuntime.Attestation{ID: "recovery:exact-custody", Issuer: nativeTakeoverIssuer, BindingDigest: gaRuntime.RecoveryBindingDigest(c, recoverer)}}, observer)
	_, mutationErr := db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest=digest")
	record := compositeRecoveryResult{Disposition: string(result.Disposition), BoundaryEntered: result.BoundaryEntered, ForbiddenCalls: observer.forbiddenCalls, MutationDenied: mutationErr != nil && strings.Contains(mutationErr.Error(), "permission denied"), Custody: custody}
	if result.Cause != nil {
		record.Cause = result.Cause.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(record); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func writeCompositeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func compositeProcess(t *testing.T, req gaRuntime.Request, mode, readDSN string, withheld bool) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresCompositeProcess$")
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	// Recovery receives no mutation credential. The CLI receives neither DSN.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOSMIG_SIM_ADMIN_DSN=") && !strings.HasPrefix(entry, "COMPOSITE_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "COMPOSITE_PROCESS_MODE="+mode, "COMPOSITE_REQUEST="+string(raw))
	if mode == "execute" {
		cmd.Env = append(cmd.Env, "GOSMIG_SIM_ADMIN_DSN="+os.Getenv("GOSMIG_SIM_ADMIN_DSN"))
	} else {
		cmd.Env = append(cmd.Env, "COMPOSITE_READ_DSN="+readDSN)
	}
	if withheld {
		cmd.Env = append(cmd.Env, "COMPOSITE_WITHHOLD=1")
	}
	return cmd, cancel
}

func compositeReadDSN(t *testing.T, a *postgresNativeFenceAdapter) string {
	t.Helper()
	// A dedicated native reader demonstrates recovery after effect authority is
	// revoked without carrying any destination write permission.
	_, err := a.db.Exec("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='composite_observer') THEN CREATE ROLE composite_observer LOGIN PASSWORD 'fixture-read-only'; END IF; END $$")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("GRANT USAGE ON SCHEMA " + nativeFenceSchema + " TO composite_observer"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("GRANT SELECT ON ALL TABLES IN SCHEMA " + nativeFenceSchema + " TO composite_observer"); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("GOSMIG_SIM_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("composite_observer", "fixture-read-only")
	return u.String()
}

func TestPostgresCompositeLostAcknowledgementAuthorityChangeRecovery(t *testing.T) {
	if os.Getenv("COMPOSITE_BUILD_SHA") == "" || os.Getenv("EVIDENCE_VERIFY_BINARY") == "" {
		if os.Getenv("COMPOSITE_REQUIRE") == "1" {
			t.Fatal("required composite fixture is not configured")
		}
		t.Skip("run the dedicated composite-native-assurance workflow for this fixture")
	}
	for _, withheld := range []bool{false, true} {
		name := "CLOSED"
		if withheld {
			name = "UNKNOWN"
		}
		t.Run(name, func(t *testing.T) { runPostgresComposite(t, name, withheld) })
	}
}

func runPostgresComposite(t *testing.T, caseID string, withheld bool) {
	runPostgresCompositeCase(t, caseID, withheld, false)
}

func runPostgresCompositeCase(t *testing.T, caseID string, withheld, succession bool) {
	a, req := setupPostgresNativeFence(t)
	ctx := context.Background()
	build := os.Getenv("COMPOSITE_BUILD_SHA")
	binary := os.Getenv("EVIDENCE_VERIFY_BINARY")
	if len(build) != 40 || binary == "" {
		t.Fatal("COMPOSITE_BUILD_SHA and EVIDENCE_VERIFY_BINARY are required with native PostgreSQL")
	}
	dir := t.TempDir()
	if root := os.Getenv("COMPOSITE_ARTIFACT_DIR"); root != "" {
		if succession {
			root = filepath.Join(root, "succession")
		}
		dir = filepath.Join(root, caseID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	readDSN := compositeReadDSN(t, a)
	if _, err := a.db.Exec("CREATE TABLE " + nativeFenceTable("history_head") + " (journal_id TEXT PRIMARY KEY,sequence BIGINT NOT NULL,head_hash TEXT NOT NULL,key_id TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PrivateKey{}
	p := v.Policy{Schema: v.Schema, BuildSHA: build, CaseID: caseID, DestinationProfile: "postgresql/native-fence/v1", AdmissionPolicyHash: v.ContentDigest([]byte("native profile: exact subject/state/transition; active authority; exact custody generation")), MaximumGrade: "native", HistoryID: "history:composite:" + caseID, PublicKeys: map[string]string{}, RoleKeys: map[string]string{}}
	for _, role := range []string{"admission", "execution", "destination", "history", "witness"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := role + ":" + caseID
		keys[role] = key
		p.RoleKeys[role] = id
		p.PublicKeys[id] = base64.StdEncoding.EncodeToString(pub)
	}
	var handoff *compositeSuccession
	if succession {
		handoff = prepareCompositeSuccession(t, a, &p, keys)
	}
	seal := func(role string, value any) v.Envelope {
		env, err := v.Seal(role, p.RoleKeys[role], keys[role], value)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	historyRole := "history"
	if succession {
		historyRole = "old_history"
	}
	signer, err := journal.NewEd25519Signer(p.RoleKeys[historyRole], keys[historyRole])
	if err != nil {
		t.Fatal(err)
	}
	keyring := journal.NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	var witness journal.ExternalHeadStore = postgresCompositeHead{a.db}
	if succession {
		witness = handoff.oldHistory
		if err := keyring.Add(p.RoleKeys["history"], keys["history"].Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
	journalPath, anchorPath := filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "history.anchor.json")
	j, err := journal.CreateAnchoredFileJournal(ctx, journalPath, anchorPath, p.HistoryID, signer, keyring, witness)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := gaRuntime.ReserveFenced(ctx, req, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, journal.Event{Type: journal.EventAuthorization, ActionID: prep.Custody.EffectID, AttemptID: req.AttemptID, PayloadDigest: req.Admission.BindingDigest}); err != nil {
		t.Fatal(err)
	}
	initialHead, err := witness.Load(ctx, p.HistoryID)
	if err != nil {
		t.Fatal(err)
	}
	writeCompositeJSON(t, filepath.Join(dir, "before-interruption-head.json"), initialHead)
	cmd, cancel := compositeProcess(t, req, "execute", "", false)
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
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "NATIVE_COMMITTED\n" {
			t.Fatalf("native worker did not commit: %q %s", line, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("native commit barrier timed out")
	}
	if count := nativeEffectCount(t, a); count != 1 {
		t.Fatalf("barrier lacks native commit: %d", count)
	}
	if succession {
		handoff.rotate(t, a, &p, keys, initialHead, anchorPath)
	} else if _, err := a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET active=FALSE,generation=generation+1 WHERE binding_digest=$1", req.Admission.BindingDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 93 {
		t.Fatalf("expected interrupted process 93, got %v %s", err, stderr.String())
	}
	crossing, err := a.LoadFencedCustody(ctx, prep.Custody.EffectID, req.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if crossing.Phase != gaRuntime.CustodyCrossing || crossing.Generation != 1 {
		t.Fatalf("lost callback acknowledgement did not retain crossing: %+v", crossing)
	}
	ownerB := gaRuntime.Identity{ID: "executor:B", Kind: "worker"}
	if _, err := gaRuntime.TakeoverReserved(ctx, nativeTakeoverRequest(t, req, crossing, ownerB), a); !errors.Is(err, gaRuntime.ErrCustodyNotReserved) {
		t.Fatalf("crossing takeover reopened execution: %v", err)
	}
	if replay := gaRuntime.ExecuteReservedFenced(ctx, req, crossing, a); replay.BoundaryEntered || replay.Disposition != gaRuntime.DispositionRejected {
		t.Fatalf("crash reopened runtime dispatch: %+v", replay)
	}
	if _, err := a.ExecuteFenced(ctx, req.Transition, crossing); err == nil {
		t.Fatal("direct native replay unexpectedly committed")
	}
	recoveryCmd, recoveryCancel := compositeProcess(t, req, "recover", readDSN, withheld)
	defer recoveryCancel()
	recoveryRaw, err := recoveryCmd.Output()
	if err != nil {
		t.Fatalf("read-only recovery failed: %v", err)
	}
	var recovery compositeRecoveryResult
	if err := json.Unmarshal(recoveryRaw, &recovery); err != nil {
		t.Fatal(err)
	}
	if recovery.Disposition != caseID || recovery.BoundaryEntered || recovery.ForbiddenCalls != 0 || !recovery.MutationDenied || !recovery.Custody.Equal(crossing) {
		t.Fatalf("unsafe recovery: %+v", recovery)
	}
	writeCompositeJSON(t, filepath.Join(dir, "recovery.json"), recovery)
	unknown := crossing
	unknown.Phase = gaRuntime.CustodyUnknown
	if err := a.TransitionFencedCustodyCAS(ctx, crossing, unknown); err != nil {
		t.Fatal(err)
	}
	final := unknown
	if !withheld {
		final.Phase = gaRuntime.CustodyClosed
		if err := a.TransitionFencedCustodyCAS(ctx, unknown, final); err != nil {
			t.Fatal(err)
		}
	}
	if count := nativeEffectCount(t, a); count != 1 {
		t.Fatalf("recovery/replay duplicated the native effect: %d", count)
	}
	// Record the exact native commit, including authority values captured under
	// transaction locks. Current inactive authority does not rewrite that fact.
	var commit v.Commit
	var committedAt time.Time
	err = a.db.QueryRow("SELECT effect_id,attempt_id,owner_id,owner_kind,generation,admission_binding,authority_epoch,authority_generation,authority_active,operation,target,from_revision,from_digest,to_revision,to_digest,created_at FROM "+nativeFenceTable("effects")).Scan(&commit.EffectID, &commit.AttemptID, &commit.Owner.ID, &commit.Owner.Kind, &commit.CustodyGeneration, &commit.AdmissionBinding, &commit.AuthorityEpoch, &commit.AuthorityGeneration, &commit.AuthorityActive, &commit.Operation, &commit.Before.Target, &commit.Before.Revision, &commit.Before.Digest, &commit.After.Revision, &commit.After.Digest, &committedAt)
	if err != nil {
		t.Fatal(err)
	}
	commit.After.Target = commit.Before.Target
	commit.CommittedAt = committedAt.UTC().Format(time.RFC3339Nano)
	state, err := a.CurrentState(ctx, req.Current.Target)
	if err != nil {
		t.Fatal(err)
	}
	var active bool
	var currentGeneration uint64
	if err := a.db.QueryRow("SELECT active,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1", req.Admission.BindingDigest).Scan(&active, &currentGeneration); err != nil {
		t.Fatal(err)
	}
	convertState := func(s gaRuntime.State) v.State {
		return v.State{Target: s.Target, Revision: s.Revision, Digest: s.Digest}
	}
	request := v.Request{Subject: v.Identity{ID: req.Subject.ID, Kind: req.Subject.Kind}, Executor: v.Identity{ID: req.Executor.ID, Kind: req.Executor.Kind}, Before: convertState(req.Current), After: convertState(req.Transition.To), Operation: req.Transition.Operation, AttemptID: req.AttemptID, AdmissionBinding: req.Admission.BindingDigest}
	e := v.Execution{BuildSHA: build, CaseID: caseID, Grade: "native", ClaimType: "EXACT_EFFECT", IntentID: "intent:composite:" + caseID, Request: request, EffectID: prep.Custody.EffectID, CustodyGeneration: prep.Custody.Generation, AuthorityEpoch: 1, AuthorityGeneration: 1, Admitted: true, AcknowledgementLost: true, RecoveredBy: v.Identity{ID: "recovery:read-only", Kind: "observer"}, ClaimedClosure: caseID, ClaimedCausality: "EXACT_COMMIT_RECORD", ClaimedHistory: "TRUSTED_HISTORY"}
	d := v.Destination{BuildSHA: build, CaseID: caseID, Profile: p.DestinationProfile, Observed: convertState(state), EffectCount: uint64(nativeEffectCount(t, a)), Commit: &commit, AuthorityCurrentlyActive: active, CurrentAuthorityGeneration: currentGeneration}
	admission := v.Admission{BuildSHA: build, CaseID: caseID, PolicyHash: p.AdmissionPolicyHash, RequestBinding: req.Admission.BindingDigest, ObservedBefore: request.Before, AllowedOperation: req.Transition.Operation, AuthorityEpoch: 1, AuthorityGeneration: 1, AuthorityActive: true}
	if succession {
		e.Grade = "simulation"
		e.EvidenceGrades = &p.Succession.Grades
		e.AuthorityEpoch = handoff.oldPin.GenesisEpoch()
		admission.AuthorityEpoch = e.AuthorityEpoch
	}
	// Native raw evidence retains the commit even when the evaluated evidence
	// set intentionally withholds it. UNKNOWN must survive that loss.
	writeCompositeJSON(t, filepath.Join(dir, "native-observation.json"), struct {
		Destination v.Destination           `json:"destination"`
		Custody     gaRuntime.FencedCustody `json:"custody"`
		ProcessExit int                     `json:"process_exit"`
	}{d, final, exit.ExitCode()})
	if withheld {
		d.Observed = v.State{}
		d.Commit = nil
		d.ObservationError = recovery.Cause
		e.ClaimedCausality = "UNPROVEN"
	}
	dest := seal("destination", d)
	b := v.Bundle{Schema: v.Schema, Admission: seal("admission", admission), Execution: seal("execution", e), Destination: &dest}
	if succession {
		b.Succession = &handoff.proof
		witness = handoff.newHistory
		signer, err = journal.NewEd25519Signer(p.RoleKeys["history"], keys["history"])
		if err != nil {
			t.Fatal(err)
		}
	}
	// Restart opens existing identity/head. It never creates a replacement.
	j, err = journal.OpenAnchoredFileJournal(ctx, journalPath, anchorPath, p.HistoryID, signer, keyring, witness)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, journal.Event{Type: journal.EventOutcome, ActionID: e.EffectID, AttemptID: req.AttemptID, OutcomeVerdict: caseID, PayloadDigest: v.BundleHistoryBinding(b)}); err != nil {
		t.Fatal(err)
	}
	head, err := witness.Load(ctx, p.HistoryID)
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != initialHead.Sequence+1 {
		t.Fatal("recovery lost history continuity")
	}
	p.Checkpoint = &v.Head{JournalID: head.JournalID, Sequence: head.Sequence, HeadHash: head.HeadHash, KeyID: head.KeyID}
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	h := &v.History{Anchor: anchor, Witness: seal("witness", v.Witness{BuildSHA: build, CaseID: caseID, Head: *p.Checkpoint})}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		h.Entries = append(h.Entries, append(json.RawMessage(nil), line...))
	}
	b.History = h
	if succession {
		trace, current := successionObservation(t, a.db, handoff.members, p.HistoryID, journal.SuccessorGovernanceAuthorityJournalID)
		handoff.observation.Transitions, handoff.observation.Current = trace, current
		handoff.observation.BuildSHA, handoff.observation.CaseID = build, caseID
		handoff.observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		p.Succession.EvaluationTime = time.Now().UTC().Format(time.RFC3339Nano)
		handoff.proof.Witness = seal("succession_witness", handoff.observation)
		writeCompositeJSON(t, filepath.Join(dir, "succession-native-observation.json"), handoff.observation)
	}
	bundlePath, policyPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "fixture-policy.json")
	writeCompositeJSON(t, bundlePath, b)
	writeCompositeJSON(t, policyPath, p)
	// Separate process imports only bundle + independently supplied policy.
	// Fixture roots do not constitute independent operator reproduction.
	durations := []int64{}
	for i := 0; i < 2; i++ {
		started := time.Now()
		inspect := exec.Command(binary, "--bundle", bundlePath, "--policy", policyPath, "--format", "json")
		inspect.Env = []string{"PATH=/usr/bin:/bin"}
		output, err := inspect.Output()
		durations = append(durations, time.Since(started).Milliseconds())
		if err != nil {
			t.Fatalf("independent executable rejected native result: %v %s", err, output)
		}
		var report v.Report
		if err := json.Unmarshal(output, &report); err != nil {
			t.Fatal(err)
		}
		if !report.ClaimsSupported || report.Closure != caseID || report.HistoricalTrust != "TRUSTED_HISTORY" || report.Grade != e.Grade || report.Causality != e.ClaimedCausality {
			t.Fatalf("separate verifier changed native judgment: %+v", report)
		}
		if succession && (report.SuccessionValidity != "VALID" || report.CustodianAuthority != "AUTHORIZED_AT_CHECKPOINT" || report.CurrentCustodian == nil || *report.CurrentCustodian != p.Succession.NewCustodian) {
			t.Fatalf("new custodian lacks independently verified continuation: %+v", report)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("report-%d.json", i+1)), output, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if succession {
		falsifySuccessionBundle(t, dir, b, p, keys)
	}
	writeCompositeJSON(t, filepath.Join(dir, "first-use.json"), map[string]any{"scope": "automated fixture; no human usability claim", "first_report_ms": durations[0], "second_report_ms": durations[1], "permissions": []string{"read bundle", "read independently provisioned policy"}, "configuration_steps": 2, "mutation_credentials": 0, "support_required": "not measured with a human", "points_of_confusion": []string{"where independently trusted policy comes from", "supported UNKNOWN exit code is not effect success"}, "decision": caseID, "independent_operator_reproduction": false})
	// Losing local history cannot authorize reenrollment of the same identity.
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.OpenAnchoredFileJournal(ctx, journalPath, anchorPath, p.HistoryID, signer, keyring, witness); !errors.Is(err, journal.ErrJournalHistoryUnavailable) {
		t.Fatalf("missing history reopened: %v", err)
	}
	if _, err := journal.CreateAnchoredFileJournal(ctx, journalPath, anchorPath, p.HistoryID, signer, keyring, witness); !errors.Is(err, journal.ErrJournalAlreadyExists) {
		t.Fatalf("replacement reset history: %v", err)
	}
	after, err := witness.Load(ctx, p.HistoryID)
	if err != nil || after.Sequence != head.Sequence || after.HeadHash != head.HeadHash {
		t.Fatal("local history loss reset external continuity")
	}
}

func TestPostgresCompositeAuthorityGenerationSwitchDoesNotReviveOldAdmission(t *testing.T) {
	a, req := setupPostgresNativeFence(t)
	// Add columns also against the pre-change adapter for an executable baseline.
	if _, err := a.db.Exec("ALTER TABLE " + nativeFenceTable("authority") + " ADD COLUMN IF NOT EXISTS epoch BIGINT NOT NULL DEFAULT 1, ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 1"); err != nil {
		t.Fatal(err)
	}
	prep, err := gaRuntime.ReserveFenced(context.Background(), req, a)
	if err != nil {
		t.Fatal(err)
	}
	a.afterPolicyVerify = func(n int) {
		if n == 4 {
			if _, err := a.db.Exec("UPDATE " + nativeFenceTable("authority") + " SET generation=generation+1,active=TRUE"); err != nil {
				panic(err)
			}
		}
	}
	result := gaRuntime.ExecuteReservedFenced(context.Background(), req, prep.Custody, a)
	if result.Disposition != gaRuntime.DispositionUnknown || !errors.Is(result.EffectError, errNativeAuthority) || nativeEffectCount(t, a) != 0 {
		t.Fatalf("old admission crossed a new authority generation: disposition=%s effects=%d error=%v", result.Disposition, nativeEffectCount(t, a), result.EffectError)
	}
}

func TestPostgresCompositeMatchingStateAndForeignEffectDoNotProveCausality(t *testing.T) {
	a, req := setupPostgresNativeFence(t)
	ctx := context.Background()
	prep, err := gaRuntime.ReserveFenced(ctx, req, a)
	if err != nil {
		t.Fatal(err)
	}
	crossing := prep.Custody
	crossing.Phase = gaRuntime.CustodyCrossing
	if err := a.TransitionFencedCustodyCAS(ctx, prep.Custody, crossing); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExecuteFenced(ctx, req.Transition, crossing); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("UPDATE "+nativeFenceTable("effects")+" SET owner_kind='foreign-kind',operation='unrelated' WHERE effect_id=$1", crossing.EffectID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ObserveFenced(ctx, req.Transition, crossing); !errors.Is(err, errNativeObservation) {
		t.Fatalf("matching state was substituted for exact cause: %v", err)
	}
	if nativeEffectCount(t, a) != 1 {
		t.Fatal("negative observation unexpectedly mutated effects")
	}
}
