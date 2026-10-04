package simulation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

// Reuse the actual constitutional Genesis/history/succession substrate, while
// the effect executor itself has no mutable custody register. Immutable history
// retains authorization and outcome facts; it never selects a current effect
// owner, grants execution on UNKNOWN, or manufactures a causal receipt.
func TestPostgresCompositeNoCustodyGenesisHistorySuccession(t *testing.T) {
	if os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR") == "" {
		if os.Getenv("COMPOSITE_SUCCESSION_REQUIRE") == "1" {
			t.Fatal("required no-custody Genesis succession fixture missing")
		}
		t.Skip("run composite-native-assurance for verified Genesis succession")
	}
	for _, name := range []string{"CLOSED", "UNKNOWN"} {
		t.Run(name, func(t *testing.T) { noCustodyHistorySuccession(t, name) })
	}
}

func noCustodyHistorySuccession(t *testing.T, name string) {
	f := setupNoCustody(t)
	// Preserve the constitutional helper's UNKNOWN-specific promotion witness.
	// The independent policy, exact request and artifact directory distinguish
	// this alternate profile from the existing custody-backed history corpus.
	f.policy.CaseID = name
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.keys["witness"], f.policy.RoleKeys["witness"] = key, "witness:no-custody"
	f.policy.PublicKeys["witness:no-custody"] = base64.StdEncoding.EncodeToString(pub)
	handoff := prepareCompositeSuccession(t, f.a, &f.policy, f.keys)
	f.epoch = handoff.oldPin.GenesisEpoch()
	ctx := context.Background()
	signer, err := journal.NewEd25519Signer(f.policy.RoleKeys["old_history"], f.keys["old_history"])
	if err != nil {
		t.Fatal(err)
	}
	keyring := journal.NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(f.policy.RoleKeys["history"], f.keys["history"].Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if root := os.Getenv("COMPOSITE_ARTIFACT_DIR"); root != "" {
		dir = filepath.Join(root, "custody-elimination", "succession", name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	journalPath, anchorPath := filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "history.anchor.json")
	j, err := journal.CreateAnchoredFileJournal(ctx, journalPath, anchorPath, f.policy.HistoryID, signer, keyring, handoff.oldHistory)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := handoff.oldHistory.Load(ctx, f.policy.HistoryID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.oldWriter.ConvergeAuthorizedTransition(ctx, []journal.ExternalHead{{JournalID: f.policy.HistoryID}, seed}, seed); err != nil {
		t.Fatal(err)
	}
	effect, err := r.EffectIdentity(f.req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, journal.Event{Type: journal.EventAuthorization, ActionID: effect, AttemptID: f.req.AttemptID, PayloadDigest: f.req.Admission.BindingDigest}); err != nil {
		t.Fatal(err)
	}
	initial, err := handoff.oldHistory.Load(ctx, f.policy.HistoryID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.oldWriter.ConvergeAuthorizedTransition(ctx, []journal.ExternalHead{seed, initial}, initial); err != nil {
		t.Fatal(err)
	}
	noCustodyCrash(t, f, false)
	if f.tally(t) != 1 {
		t.Fatal("custody-less executor did not commit one native effect before succession")
	}
	// This invokes the same real native rotation, two abruptly dying controllers,
	// fresh reconstruction, stale authority denial and custodian SQL fence as #235.
	handoff.rotate(t, f.a, &f.policy, f.keys, initial, anchorPath)
	old := f.seal(t, "admission", f.admission(f.req, 1))
	if err := executeWithoutCustody(ctx, f.a.db, f.req, old, f.policy, nil); !errors.Is(err, errNativeAuthority) {
		t.Fatalf("succession revived stale effect authority: %v", err)
	}
	d := noCustodyReadProcess(t, f, name == "UNKNOWN")
	cause := "EXACT_COMMIT_RECORD"
	if name == "UNKNOWN" {
		cause = "UNPROVEN"
	}
	b, e := f.bundle(t, f.req, 1, d, name, cause)
	e.ClaimedHistory = "TRUSTED_HISTORY"
	e.AcknowledgementLost = true
	e.RecoveredBy = v.Identity{ID: "recovery:read-only", Kind: "observer"}
	b.Execution = f.seal(t, "execution", e)
	b.Succession = &handoff.proof
	signer, err = journal.NewEd25519Signer(f.policy.RoleKeys["history"], f.keys["history"])
	if err != nil {
		t.Fatal(err)
	}
	j, err = journal.OpenAnchoredFileJournal(ctx, journalPath, anchorPath, f.policy.HistoryID, signer, keyring, handoff.newHistory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, journal.Event{Type: journal.EventOutcome, ActionID: effect, AttemptID: f.req.AttemptID, OutcomeVerdict: name, PayloadDigest: v.BundleHistoryBinding(b)}); err != nil {
		t.Fatal(err)
	}
	head, err := handoff.newHistory.Load(ctx, f.policy.HistoryID)
	if err != nil || head.Sequence != initial.Sequence+1 || head.JournalID != initial.JournalID {
		t.Fatal("custody elimination broke history identity or predecessor continuity")
	}
	checkpoint := portableHead(head)
	f.policy.Checkpoint = &checkpoint
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	b.History = &v.History{Anchor: anchor, Witness: f.seal(t, "witness", v.Witness{BuildSHA: f.policy.BuildSHA, CaseID: f.policy.CaseID, Head: checkpoint})}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		b.History.Entries = append(b.History.Entries, append(json.RawMessage(nil), line...))
	}
	trace, current := successionObservation(t, f.a.db, handoff.members, f.policy.HistoryID, journal.SuccessorGovernanceAuthorityJournalID)
	handoff.observation.Transitions, handoff.observation.Current = trace, current
	handoff.observation.BuildSHA, handoff.observation.CaseID = f.policy.BuildSHA, f.policy.CaseID
	handoff.observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	f.policy.Succession.EvaluationTime = time.Now().UTC().Format(time.RFC3339Nano)
	handoff.proof.Witness = f.seal(t, "succession_witness", handoff.observation)
	report := f.consume(t, "succession/"+name, b, name, cause, true)
	if report.HistoricalTrust != "TRUSTED_HISTORY" || report.SuccessionValidity != "VALID" || report.CustodianAuthority != "AUTHORIZED_AT_CHECKPOINT" || report.CurrentCustodian == nil || *report.CurrentCustodian != f.policy.Succession.NewCustodian || report.Grade != "simulation" {
		t.Fatalf("custody-less effect lost independently verified succession: %+v", report)
	}
	falsifySuccessionBundle(t, dir, b, f.policy, f.keys)
	if f.tally(t) != 1 {
		t.Fatal("native succession/recovery changed the effect tally or recreated custody")
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.OpenAnchoredFileJournal(ctx, journalPath, anchorPath, f.policy.HistoryID, signer, keyring, handoff.newHistory); !errors.Is(err, journal.ErrJournalHistoryUnavailable) {
		t.Fatalf("custody-less missing history reopened: %v", err)
	}
	if _, err := journal.CreateAnchoredFileJournal(ctx, journalPath, anchorPath, f.policy.HistoryID, signer, keyring, handoff.newHistory); !errors.Is(err, journal.ErrJournalAlreadyExists) {
		t.Fatalf("custody-less replacement reset history: %v", err)
	}
	after, err := handoff.newHistory.Load(ctx, f.policy.HistoryID)
	if err != nil || portableHead(after) != checkpoint {
		t.Fatal("custody-less local history loss reset the durable checkpoint")
	}
}
