package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnchoredJournalCannotRebootstrapAfterLocalHistoryLoss(t *testing.T) {
	ctx := context.Background()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("history-signer", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	external := NewMemoryHeadStore()
	dir := t.TempDir()
	path, anchorPath := filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "history.anchor.json")
	const historyID = "governed-operation-history"
	first, err := CreateAnchoredFileJournal(ctx, path, anchorPath, historyID, signer, keyring, external)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := first.Append(ctx, testEvent("closed-operation", "CLOSED"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenAnchoredFileJournal(ctx, path, anchorPath, historyID, signer, keyring, external); !errors.Is(err, ErrJournalHistoryUnavailable) {
		t.Fatalf("lost local history must not reopen: %v", err)
	}
	if _, err := CreateAnchoredFileJournal(ctx, path, anchorPath, historyID, signer, keyring, external); !errors.Is(err, ErrJournalAlreadyExists) {
		t.Fatalf("retained witness must forbid rebootstrap: %v", err)
	}
	for _, p := range []string{path, anchorPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused recovery created local history %s: %v", p, err)
		}
	}
	head, err := external.Load(ctx, historyID)
	if err != nil || head.Sequence != entry.Sequence || head.HeadHash != entry.EntryHash || len(external.heads) != 1 {
		t.Fatalf("history loss changed the retained truth: head=%+v err=%v heads=%d", head, err, len(external.heads))
	}
}

type historyFixture struct {
	path, anchorPath, id string
	signer               *Ed25519Signer
	keyring              *Ed25519Keyring
}

func newHistoryFixture(t *testing.T) historyFixture {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("fixture-history-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return historyFixture{filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "anchor.json"), "fixture-history", signer, keyring}
}

func (f historyFixture) create(ctx context.Context, store ExternalHeadStore) (*FileJournal, error) {
	return CreateAnchoredFileJournal(ctx, f.path, f.anchorPath, f.id, f.signer, f.keyring, store)
}

func (f historyFixture) open(ctx context.Context, store ExternalHeadStore) (*FileJournal, error) {
	return OpenAnchoredFileJournal(ctx, f.path, f.anchorPath, f.id, f.signer, f.keyring, store)
}

func TestUnpinnedJournalCannotClaimExternalContinuity(t *testing.T) {
	f := newHistoryFixture(t)
	store := NewMemoryHeadStore()
	if _, err := NewFileJournalWithSecurity(f.path, f.anchorPath, f.signer, f.keyring, store); !errors.Is(err, ErrJournalIdentityRequired) {
		t.Fatalf("legacy unpinned constructor must fail before provisioning: %v", err)
	}
	if len(store.heads) != 0 {
		t.Fatal("unpinned constructor enrolled a witness head")
	}
	for _, p := range []string{f.path, f.anchorPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unpinned constructor wrote %s: %v", p, err)
		}
	}
}

func TestAnchoredOpenNeverBootstrapsAbsentHistory(t *testing.T) {
	f := newHistoryFixture(t)
	store := NewMemoryHeadStore()
	if _, err := f.open(context.Background(), store); !errors.Is(err, ErrJournalHistoryUnavailable) {
		t.Fatalf("open manufactured absent history: %v", err)
	}
	if len(store.heads) != 0 {
		t.Fatal("open enrolled a witness")
	}
	for _, p := range []string{f.path, f.anchorPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("open wrote %s: %v", p, err)
		}
	}
}

type interruptedHeadStore struct {
	*MemoryHeadStore
	loadErr           error
	advanceErr        error
	commitBeforeError bool
	foreignIdentity   bool
	loads             []string
}

func (s *interruptedHeadStore) Load(ctx context.Context, id string) (ExternalHead, error) {
	s.loads = append(s.loads, id)
	if s.loadErr != nil {
		return ExternalHead{}, s.loadErr
	}
	head, err := s.MemoryHeadStore.Load(ctx, id)
	if s.foreignIdentity && err == nil {
		head.JournalID = "foreign-history"
	}
	return head, err
}

func (s *interruptedHeadStore) CompareAndAdvance(ctx context.Context, previous, next ExternalHead) (ExternalHead, error) {
	if s.advanceErr != nil && !s.commitBeforeError {
		return ExternalHead{}, s.advanceErr
	}
	head, err := s.MemoryHeadStore.CompareAndAdvance(ctx, previous, next)
	if err == nil && s.advanceErr != nil {
		return ExternalHead{}, s.advanceErr
	}
	return head, err
}

func TestAnchoredJournalRejectsSignedForeignHistoryBeforeWitnessLookup(t *testing.T) {
	ctx := context.Background()
	f := newHistoryFixture(t)
	store := &interruptedHeadStore{MemoryHeadStore: NewMemoryHeadStore()}
	original, err := f.create(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Append(ctx, testEvent("original", "CLOSED")); err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.id = "foreign-history"
	dir := t.TempDir()
	foreign.path, foreign.anchorPath = filepath.Join(dir, "foreign.jsonl"), filepath.Join(dir, "foreign.anchor.json")
	replacement, err := foreign.create(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Append(ctx, testEvent("replacement", "CLOSED")); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{foreign.path, f.path}, {foreign.anchorPath, f.anchorPath}} {
		payload, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pair[1], payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Both histories are authentic under the same signer. That does not give
	// the foreign history the right to replace the relying context's history.
	local, err := NewFileJournalWithSecurity(f.path, f.anchorPath, f.signer, f.keyring, nil)
	if err != nil || !local.Verify(ctx).Valid {
		t.Fatalf("foreign fixture must be cryptographically valid: %v", err)
	}
	store.loads = nil
	verification := original.Verify(ctx)
	if verification.Valid || verification.HistoricalTrust != HistoryUntrusted || !strings.Contains(verification.Error, "journal identity mismatch") {
		t.Fatalf("signed foreign history inherited trust: %+v", verification)
	}
	if _, err := f.open(ctx, store); !errors.Is(err, ErrJournalHistoryUnavailable) {
		t.Fatalf("foreign history reopened: %v", err)
	}
	if len(store.loads) != 0 {
		t.Fatalf("foreign anchor selected a witness namespace before pin verification: %v", store.loads)
	}
}

func TestAnchoredJournalChecksWitnessReturnedIdentity(t *testing.T) {
	ctx := context.Background()
	f := newHistoryFixture(t)
	store := &interruptedHeadStore{MemoryHeadStore: NewMemoryHeadStore()}
	j, err := f.create(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	store.foreignIdentity = true
	got := j.Verify(ctx)
	if got.Valid || got.HistoricalTrust != HistoryUntrusted {
		t.Fatalf("matching coordinates from another witness namespace gained trust: %+v", got)
	}
}

func TestHistoricalTrustIsIndependentOfOperationalOutcome(t *testing.T) {
	for _, disposition := range []string{"CLOSED", "UNKNOWN"} {
		t.Run(disposition, func(t *testing.T) {
			ctx := context.Background()
			f := newHistoryFixture(t)
			store := &interruptedHeadStore{MemoryHeadStore: NewMemoryHeadStore()}
			j, err := f.create(ctx, store)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := j.Append(ctx, testEvent("operation", disposition))
			if err != nil {
				t.Fatal(err)
			}
			if got := j.Verify(ctx); !got.Valid || got.HistoricalTrust != HistoryTrusted {
				t.Fatalf("retained claim lacks continuity: %+v", got)
			}
			before, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			store.loadErr = errors.New("independent witness unavailable")
			got := j.Verify(ctx)
			if got.Valid || got.HistoricalTrust != HistoryUntrusted {
				t.Fatalf("witness outage retained historical trust: %+v", got)
			}
			if _, err := j.Append(ctx, testEvent("later", "CLOSED")); err == nil {
				t.Fatal("append continued without continuity proof")
			}
			after, err := os.ReadFile(f.path)
			if err != nil || string(before) != string(after) {
				t.Fatalf("continuity loss rewrote operational history: %v", err)
			}
			var retained Entry
			if err := json.Unmarshal(after, &retained); err != nil {
				t.Fatal(err)
			}
			if retained.Event.Decision != disposition || retained.EntryHash != entry.EntryHash {
				t.Fatalf("historical distrust changed the operation's recorded reality: %+v", retained)
			}
			store.loadErr = nil
			if got := j.Verify(ctx); !got.Valid || got.HistoricalTrust != HistoryTrusted {
				t.Fatalf("exact restored witness did not restore point-in-time trust: %+v", got)
			}
		})
	}
}

func TestLocalIntegrityDoesNotEarnHistoricalTrust(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)
	for _, got := range []Verification{j.Verify(context.Background()), VerifyFiles(path, anchorPath, j.PublicKey())} {
		if !got.Valid || got.HistoricalTrust != HistoryUnverified {
			t.Fatalf("local integrity was promoted to historical continuity: %+v", got)
		}
	}
}

func TestAnchoredCreationInterruptionNeverInventsRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before_external_commit"
		if committed {
			name = "external_commit_with_lost_reply"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newHistoryFixture(t)
			interruption := errors.New("creation interrupted")
			store := &interruptedHeadStore{MemoryHeadStore: NewMemoryHeadStore(), advanceErr: interruption, commitBeforeError: committed}
			if _, err := f.create(ctx, store); !errors.Is(err, interruption) {
				t.Fatalf("expected interrupted creation, got %v", err)
			}
			store.advanceErr = nil
			if _, err := f.create(ctx, store); !errors.Is(err, ErrJournalAlreadyExists) {
				t.Fatalf("partial state silently reenrolled: %v", err)
			}
			reopened, err := f.open(ctx, store)
			if !committed {
				if !errors.Is(err, ErrJournalHistoryUnavailable) || len(store.heads) != 0 {
					t.Fatalf("missing external commitment became recovery permission: %v heads=%d", err, len(store.heads))
				}
				return
			}
			if err != nil || reopened.Verify(ctx).HistoricalTrust != HistoryTrusted || len(store.heads) != 1 {
				t.Fatalf("exact committed history failed lost-reply recovery: %v heads=%d", err, len(store.heads))
			}
		})
	}
}

func TestAnchoredJournalRelocationPreservesExactHistory(t *testing.T) {
	ctx := context.Background()
	f := newHistoryFixture(t)
	store := NewMemoryHeadStore()
	j, err := f.create(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := j.Append(ctx, testEvent("operation", "CLOSED"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	relocated := f
	relocated.path, relocated.anchorPath = filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "history.anchor.json")
	for _, pair := range [][2]string{{f.path, relocated.path}, {f.anchorPath, relocated.anchorPath}} {
		payload, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pair[1], payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(pair[0]); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := relocated.open(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Verify(ctx); !got.Valid || got.HistoricalTrust != HistoryTrusted || got.HeadHash != entry.EntryHash || got.EntryCount != entry.Sequence {
		t.Fatalf("relocation failed exact continuity: %+v", got)
	}
	if len(store.heads) != 1 {
		t.Fatal("relocation enrolled another history identity")
	}
}

func TestAnchoredJournalNeverEnrollsAroundWitnessLoss(t *testing.T) {
	ctx := context.Background()
	f := newHistoryFixture(t)
	store := NewMemoryHeadStore()
	j, err := f.create(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(ctx, testEvent("operation", "CLOSED")); err != nil {
		t.Fatal(err)
	}
	delete(store.heads, f.id)
	if _, err := f.open(ctx, store); !errors.Is(err, ErrJournalHistoryUnavailable) {
		t.Fatalf("signed local pair was allowed to reenroll lost witness: %v", err)
	}
	if len(store.heads) != 0 {
		t.Fatal("open recreated a lost witness head")
	}
	if got := j.Verify(ctx); got.Valid || got.HistoricalTrust != HistoryUntrusted {
		t.Fatalf("lost witness retained historical trust: %+v", got)
	}
}

func TestAnchoredCreationRequiresWitnessAvailabilityBeforeWriting(t *testing.T) {
	f := newHistoryFixture(t)
	outage := errors.New("witness offline")
	store := &interruptedHeadStore{MemoryHeadStore: NewMemoryHeadStore(), loadErr: outage}
	if _, err := f.create(context.Background(), store); !errors.Is(err, outage) {
		t.Fatalf("outage was treated as absence: %v", err)
	}
	for _, p := range []string{f.path, f.anchorPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("creation wrote %s without witness knowledge: %v", p, err)
		}
	}
}

type concurrentCreationStore struct {
	*MemoryHeadStore
	loads   atomic.Uint32
	ready   chan struct{}
	proceed chan struct{}
}

func (s *concurrentCreationStore) Load(ctx context.Context, id string) (ExternalHead, error) {
	if s.loads.Add(1) <= 2 {
		s.ready <- struct{}{}
		select {
		case <-s.proceed:
			// Both creators saw the same absent head before either commit.
			return ExternalHead{}, ErrExternalHeadNotFound
		case <-ctx.Done():
			return ExternalHead{}, ctx.Err()
		}
	}
	return s.MemoryHeadStore.Load(ctx, id)
}

func TestAnchoredConcurrentCreationLinearizesAtWitnessCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f := newHistoryFixture(t)
	other := f
	dir := t.TempDir()
	other.path, other.anchorPath = filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "anchor.json")
	store := &concurrentCreationStore{MemoryHeadStore: NewMemoryHeadStore(), ready: make(chan struct{}, 2), proceed: make(chan struct{})}
	results := make(chan error, 2)
	for _, fixture := range []historyFixture{f, other} {
		go func() {
			_, err := fixture.create(ctx, store)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-store.ready:
		case <-ctx.Done():
			t.Fatal("creators did not reach concurrent absence checks")
		}
	}
	close(store.proceed)
	var successes, conflicts int
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			} else if errors.Is(err, ErrExternalHeadConflict) {
				conflicts++
			} else {
				t.Fatalf("unexpected creation result: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("creators did not complete")
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent provisioning did not linearize: success=%d conflict=%d", successes, conflicts)
	}
}
