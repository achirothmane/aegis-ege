package simulation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

type noCustodyFixture struct {
	a      *postgresNativeFenceAdapter
	req    r.Request
	policy v.Policy
	keys   map[string]ed25519.PrivateKey
	epoch  uint64
}

func setupNoCustody(t *testing.T) *noCustodyFixture {
	t.Helper()
	if len(os.Getenv("COMPOSITE_BUILD_SHA")) != 40 || os.Getenv("EVIDENCE_VERIFY_BINARY") == "" {
		if os.Getenv("COMPOSITE_REQUIRE") == "1" {
			t.Fatal("native custody trial requires the build SHA and separate evidence consumer")
		}
		t.Skip("native custody trial runs in the composite assurance profile")
	}
	a, req := setupPostgresNativeFence(t)
	if _, err := a.db.Exec("DROP TABLE " + nativeFenceTable("custody")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("CREATE TABLE " + nativeFenceTable("ledger") + " (id BIGSERIAL PRIMARY KEY,amount BIGINT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	// An append can be non-idempotent without changing the proposal's state.
	// Matching that state therefore cannot mask a second ledger mutation.
	req.Transition.Operation = "append-native-ledger"
	req.Transition.To = req.Current
	binding, err := r.AdmissionBindingDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET binding_digest=$1 WHERE binding_digest=$2", binding, req.Admission.BindingDigest); err != nil {
		t.Fatal(err)
	}
	req.Admission.BindingDigest = binding
	a.req = req
	f := &noCustodyFixture{a: a, req: req, epoch: 1, keys: map[string]ed25519.PrivateKey{}, policy: v.Policy{Schema: v.Schema, BuildSHA: os.Getenv("COMPOSITE_BUILD_SHA"), CaseID: "no-custody", DestinationProfile: "postgresql/native-fence/v1", AdmissionPolicyHash: v.ContentDigest([]byte("one append; stable exact effect key; transactional receipt retention; current admission authority fence")), RequiredClaimType: "EXACT_EFFECT", MaximumGrade: "native", PublicKeys: map[string]string{}, RoleKeys: map[string]string{}}}
	for _, role := range []string{"admission", "execution", "destination"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := role + ":no-custody"
		f.keys[role], f.policy.RoleKeys[role], f.policy.PublicKeys[id] = key, id, base64.StdEncoding.EncodeToString(pub)
	}
	return f
}

func (f *noCustodyFixture) admission(req r.Request, generation uint64) v.Admission {
	return v.Admission{BuildSHA: f.policy.BuildSHA, CaseID: f.policy.CaseID, PolicyHash: f.policy.AdmissionPolicyHash, RequestBinding: req.Admission.BindingDigest, ObservedBefore: noCustodyState(req.Current), AllowedOperation: req.Transition.Operation, AuthorityEpoch: f.epoch, AuthorityGeneration: generation, AuthorityActive: true}
}

func (f *noCustodyFixture) seal(t *testing.T, role string, value any) v.Envelope {
	t.Helper()
	env, err := v.Seal(role, f.policy.RoleKeys[role], f.keys[role], value)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (f *noCustodyFixture) tally(t *testing.T) uint64 {
	t.Helper()
	var count uint64
	if err := f.a.db.QueryRow("SELECT COUNT(*) FROM " + nativeFenceTable("ledger")).Scan(&count); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err := f.a.db.QueryRow("SELECT to_regclass($1) IS NULL", nativeFenceTable("custody")).Scan(&absent); err != nil || !absent {
		t.Fatal("alternate path recreated independent custody")
	}
	return count
}

func (f *noCustodyFixture) successor(t *testing.T) r.Request {
	t.Helper()
	if _, err := f.a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET generation=2 WHERE binding_digest=$1", f.req.Admission.BindingDigest); err != nil {
		t.Fatal(err)
	}
	q := f.req
	q.Executor.ID, q.AttemptID = "executor:B", "attempt:B"
	original, err := r.EffectIdentity(f.req)
	if err != nil {
		t.Fatal(err)
	}
	next, err := r.EffectIdentity(q)
	if err != nil || original != next {
		t.Fatal("successor changed the logical effect identity")
	}
	return q
}

func (f *noCustodyFixture) inspect(t *testing.T, name string, req r.Request, generation uint64, d v.Destination, closure, causality string, supported bool) v.Report {
	t.Helper()
	b, _ := f.bundle(t, req, generation, d, closure, causality)
	return f.consume(t, name, b, closure, causality, supported)
}

func (f *noCustodyFixture) bundle(t *testing.T, req r.Request, generation uint64, d v.Destination, closure, causality string) (v.Bundle, v.Execution) {
	t.Helper()
	effect, err := r.EffectIdentity(req)
	if err != nil {
		t.Fatal(err)
	}
	d.BuildSHA, d.CaseID, d.Profile = f.policy.BuildSHA, f.policy.CaseID, f.policy.DestinationProfile
	q := v.Request{Subject: v.Identity{ID: req.Subject.ID, Kind: req.Subject.Kind}, Executor: v.Identity{ID: req.Executor.ID, Kind: req.Executor.Kind}, Before: noCustodyState(req.Current), After: noCustodyState(req.Transition.To), Operation: req.Transition.Operation, AttemptID: req.AttemptID, AdmissionBinding: req.Admission.BindingDigest}
	e := v.Execution{BuildSHA: f.policy.BuildSHA, CaseID: f.policy.CaseID, Grade: f.policy.MaximumGrade, ClaimType: "EXACT_EFFECT", IntentID: "intent:no-custody", Request: q, EffectID: effect, CustodyGeneration: 1, AuthorityEpoch: f.epoch, AuthorityGeneration: generation, Admitted: true, ClaimedClosure: closure, ClaimedCausality: causality, ClaimedHistory: "UNTRUSTED_HISTORY"}
	if f.policy.Succession != nil {
		e.EvidenceGrades = &f.policy.Succession.Grades
	}
	dest := f.seal(t, "destination", d)
	b := v.Bundle{Schema: v.Schema, Admission: f.seal(t, "admission", f.admission(req, generation)), Execution: f.seal(t, "execution", e), Destination: &dest}
	return b, e
}

func (f *noCustodyFixture) consume(t *testing.T, name string, b v.Bundle, closure, causality string, supported bool) v.Report {
	t.Helper()
	dir := t.TempDir()
	if root := os.Getenv("COMPOSITE_ARTIFACT_DIR"); root != "" {
		dir = filepath.Join(root, "custody-elimination", name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeCompositeJSON(t, filepath.Join(dir, "bundle.json"), b)
	writeCompositeJSON(t, filepath.Join(dir, "fixture-policy.json"), f.policy)
	cmd := exec.Command(os.Getenv("EVIDENCE_VERIFY_BINARY"), "--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "fixture-policy.json"), "--format", "json")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	raw, err := cmd.Output()
	var exit *exec.ExitError
	if (err == nil) != supported || err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		t.Fatalf("native no-custody consumer changed acceptance: %v %s", err, raw)
	}
	var report v.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.ClaimsSupported != supported || report.RequiredClaimType != "EXACT_EFFECT" || report.Signatures != "VALID" || report.TrustRoots != "VALID" || !report.Admitted {
		t.Fatalf("native no-custody consumer lost the independent contract: %+v", report)
	}
	if supported && (report.Closure != closure || report.Causality != causality) {
		t.Fatalf("native no-custody consumer changed the exact answer: %+v", report)
	}
	if !supported && report.Closure != "UNKNOWN" {
		t.Fatalf("foreign attempt inherited native closure: %+v", report)
	}
	writeCompositeJSON(t, filepath.Join(dir, "report.json"), report)
	return report
}

func TestPostgresCompositeNoCustodyCrashRecovery(t *testing.T) {
	for _, name := range []string{"CLOSED", "UNKNOWN", "PRE_COMMIT"} {
		t.Run(name, func(t *testing.T) {
			f := setupNoCustody(t)
			noCustodyCrash(t, f, name == "PRE_COMMIT")
			wantEffects := uint64(1)
			if name == "PRE_COMMIT" {
				wantEffects = 0
			}
			if f.tally(t) != wantEffects {
				t.Fatal("native crash escaped the atomic effect/receipt boundary")
			}
			next := f.successor(t)
			d := noCustodyReadProcess(t, f, name == "UNKNOWN")
			closure, cause := "CLOSED", "EXACT_COMMIT_RECORD"
			if name == "UNKNOWN" {
				closure, cause = "UNKNOWN", "UNPROVEN"
			} else if name == "PRE_COMMIT" {
				closure, cause = "UNKNOWN", "STATE_ONLY"
			}
			f.inspect(t, name+"/original", f.req, 1, d, closure, cause, true)
			// Observation has no mutation credential and grants no retry.
			if f.tally(t) != wantEffects {
				t.Fatal("UNKNOWN recovery dispatched an effect")
			}
			old := f.seal(t, "admission", f.admission(f.req, 1))
			if err := executeWithoutCustody(context.Background(), f.a.db, f.req, old, f.policy, nil); !errors.Is(err, errNativeAuthority) {
				t.Fatalf("stale authority executed without current custody: %v", err)
			}
			fresh := f.seal(t, "admission", f.admission(next, 2))
			err := executeWithoutCustody(context.Background(), f.a.db, next, fresh, f.policy, nil)
			if name == "PRE_COMMIT" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errNativeCompleted) {
				t.Fatalf("native retention erased: committed_effects=%d successor_error=%v", f.tally(t), err)
			}
			if f.tally(t) != 1 {
				t.Fatal("native destination allowed a second logical effect")
			}
			actual, err := observeWithoutCustody(context.Background(), f.a.db, next, false)
			if err != nil {
				t.Fatal(err)
			}
			if name == "PRE_COMMIT" {
				f.inspect(t, name+"/successor", next, 2, actual, "CLOSED", "EXACT_COMMIT_RECORD", true)
			} else {
				f.inspect(t, name+"/foreign-successor", next, 2, actual, "CLOSED", "EXACT_COMMIT_RECORD", false)
			}
		})
	}
}

func TestPostgresCompositeNoCustodyReplayRetention(t *testing.T) {
	f := setupNoCustody(t)
	noCustodyCrash(t, f, false)
	if f.tally(t) != 1 {
		t.Fatal("lost acknowledgement case lacks one genuine native effect")
	}
	next := f.successor(t)
	err := executeWithoutCustody(context.Background(), f.a.db, next, f.seal(t, "admission", f.admission(next, 2)), f.policy, nil)
	if count := f.tally(t); count != 1 || !errors.Is(err, errNativeCompleted) {
		t.Fatalf("native retention erased: committed_effects=%d successor_error=%v", count, err)
	}
}

func TestPostgresCompositeNoCustodyConcurrentSuccessors(t *testing.T) {
	f := setupNoCustody(t)
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
			results <- executeWithoutCustody(context.Background(), f.a.db, requests[i], envs[i], f.policy, nil)
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
	if committed != 1 || replayed != 1 || f.tally(t) != 1 {
		t.Fatal("concurrent native contenders created ambiguous or duplicate effects")
	}
	d, err := observeWithoutCustody(context.Background(), f.a.db, first, false)
	if err != nil || d.Commit == nil {
		t.Fatal("native winner lacks an immutable causal receipt")
	}
	winner, loser := first, second
	if d.Commit.AttemptID == second.AttemptID {
		winner, loser = second, first
	}
	f.inspect(t, "concurrent/winner", winner, 2, d, "CLOSED", "EXACT_COMMIT_RECORD", true)
	f.inspect(t, "concurrent/loser", loser, 2, d, "CLOSED", "EXACT_COMMIT_RECORD", false)
}

func TestPostgresCompositeNoCustodyHistoricalCompletionDoesNotCloseDrift(t *testing.T) {
	f := setupNoCustody(t)
	noCustodyCrash(t, f, false)
	before := noCustodyReadProcess(t, f, false)
	f.inspect(t, "drift/before", f.req, 1, before, "CLOSED", "EXACT_COMMIT_RECORD", true)
	if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest='later-native-state'"); err != nil {
		t.Fatal(err)
	}
	after := noCustodyReadProcess(t, f, false)
	oldReceipt, err := json.Marshal(before.Commit)
	if err != nil {
		t.Fatal(err)
	}
	currentReceipt, err := json.Marshal(after.Commit)
	if err != nil || string(oldReceipt) != string(currentReceipt) || f.tally(t) != 1 {
		t.Fatal("later state changed the retained historical cause or effect tally")
	}
	report := f.inspect(t, "drift/after", f.req, 1, after, "CLOSED", "EXACT_COMMIT_RECORD", false)
	if report.Causality != "EXACT_COMMIT_RECORD" {
		t.Fatal("current closure erased the valid historical cause")
	}
}
