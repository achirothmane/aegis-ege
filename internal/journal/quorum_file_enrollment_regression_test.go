package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
)

// Native composite execution exposed a previously untested real composition:
// FileJournal supplies an identity-only nonexistent predecessor for enrollment,
// whereas QuorumHeadStore had treated it as an existing sequence-zero head.
func TestQuorumFileJournalEnrollmentPreservesRetainedIdentity(t *testing.T) {
	ctx := context.Background()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("enrollment-key", key)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewEd25519Keyring()
	if err := ring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	store := quorumStoreForTest(t, newQuorumTestStore(nil), newQuorumTestStore(nil), newQuorumTestStore(nil))
	path := filepath.Join(t.TempDir(), "history.jsonl")
	anchor := path + ".anchor"
	j, err := CreateAnchoredFileJournal(ctx, path, anchor, "enrolled-history", signer, ring, store)
	if err != nil {
		t.Fatalf("anchored journal cannot enroll through existing quorum relation: %v", err)
	}
	initial, err := store.Load(ctx, "enrolled-history")
	if err != nil {
		t.Fatal(err)
	}
	changed := initial
	changed.KeyID = "replacement-key"
	changed.StoreVersion = ""
	if _, err := store.CompareAndAdvance(ctx, ExternalHead{JournalID: initial.JournalID}, changed); !errors.Is(err, ErrExternalHeadConflict) {
		t.Fatalf("identity-only expectation replaced a retained empty journal: %v", err)
	}
	if _, err := j.Append(ctx, testEvent("after-enrollment", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAnchoredFileJournal(ctx, path, anchor, "enrolled-history", signer, ring, store); err != nil {
		t.Fatalf("enrolled history did not reopen: %v", err)
	}
}

func TestQuorumRejectsMalformedNonexistentPredecessor(t *testing.T) {
	for _, previous := range []ExternalHead{{Sequence: 1}, {HeadHash: "invented"}, {KeyID: "invented"}, {StoreVersion: "invented"}} {
		store := quorumStoreForTest(t, newQuorumTestStore(nil), newQuorumTestStore(nil), newQuorumTestStore(nil))
		if _, err := store.CompareAndAdvance(context.Background(), previous, ExternalHead{JournalID: "new-history", KeyID: "new-key"}); !errors.Is(err, ErrExternalHeadConflict) {
			t.Fatalf("nonzero nonexistent predecessor accepted: %+v err=%v", previous, err)
		}
	}
}

func TestQuorumAbsenceCannotRepairMissingHistoryPrefix(t *testing.T) {
	store := quorumStoreForTest(t, newQuorumTestStore(nil), newQuorumTestStore(nil), newQuorumTestStore(nil))
	target := ExternalHead{JournalID: "lost-history", Sequence: 1, HeadHash: "retained-hash", KeyID: "retained-key"}
	if _, err := store.ConvergeAuthorizedTransition(context.Background(), []ExternalHead{{JournalID: target.JournalID}, target}, target); !errors.Is(err, ErrExternalHeadConflict) {
		t.Fatalf("absence was silently promoted to missing-prefix repair: %v", err)
	}
}
