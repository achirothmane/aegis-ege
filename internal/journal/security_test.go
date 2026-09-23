package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalHeadDetectsFullLocalSnapshotRollback(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("key-v1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyring := NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	external := NewMemoryHeadStore()

	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	anchorPath := filepath.Join(dir, "journal.anchor.json")
	j, err := NewFileJournalWithSecurity(path, anchorPath, signer, keyring, external)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := j.Append(context.Background(), testEvent("one", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(context.Background(), testEvent("two", "ALLOW")); err != nil {
		t.Fatal(err)
	}

	oldJournal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := j.Append(context.Background(), testEvent("three", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	if got := j.Verify(context.Background()); !got.Valid || got.EntryCount != 3 {
		t.Fatalf("expected three-entry secured journal, got %+v", got)
	}

	if err := os.WriteFile(path, oldJournal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorPath, oldAnchor, 0o600); err != nil {
		t.Fatal(err)
	}

	// The old journal + matching old local anchor is internally valid.
	localOnly := VerifyFiles(path, anchorPath, signer.PublicKey())
	if !localOnly.Valid || localOnly.EntryCount != 2 {
		t.Fatalf("local-only verification should accept restored valid pair, got %+v", localOnly)
	}

	// M10 compares that valid old pair with the independently retained latest
	// external head and detects the rollback.
	secured := j.Verify(context.Background())
	if secured.Valid || !strings.Contains(secured.Error, "external journal head mismatch") {
		t.Fatalf("full local rollback must fail external verification, got %+v", secured)
	}
}

func TestSignerRotationPreservesHistoricalVerification(t *testing.T) {
	_, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, _ := NewEd25519Signer("key-2026-a", oldPrivate)

	_, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, _ := NewEd25519Signer("key-2026-b", newPrivate)

	keyring := NewEd25519Keyring()
	if err := keyring.Add(oldSigner.KeyID(), oldSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(newSigner.KeyID(), newSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	external := NewMemoryHeadStore()
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	anchorPath := filepath.Join(dir, "journal.anchor.json")

	first, err := NewFileJournalWithSecurity(path, anchorPath, oldSigner, keyring, external)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Append(context.Background(), testEvent("old-key-entry", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := readAnchor(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if oldAnchor.KeyID != oldSigner.KeyID() {
		t.Fatalf("expected old key id, got %+v", oldAnchor)
	}
	if err := verifyAnchor(context.Background(), oldAnchor, keyring); err != nil {
		t.Fatalf("historical anchor did not verify before rotation: %v", err)
	}

	rotated, err := NewFileJournalWithSecurity(path, anchorPath, newSigner, keyring, external)
	if err != nil {
		t.Fatalf("open with rotated signer: %v", err)
	}
	if _, err := rotated.Append(context.Background(), testEvent("new-key-entry", "ALLOW")); err != nil {
		t.Fatal(err)
	}
	newAnchor, err := readAnchor(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if newAnchor.KeyID != newSigner.KeyID() {
		t.Fatalf("expected rotated key id, got %+v", newAnchor)
	}
	if err := verifyAnchor(context.Background(), oldAnchor, keyring); err != nil {
		t.Fatalf("old historical anchor no longer verifies: %v", err)
	}
	if err := verifyAnchor(context.Background(), newAnchor, keyring); err != nil {
		t.Fatalf("new anchor does not verify: %v", err)
	}
	if got := rotated.Verify(context.Background()); !got.Valid || got.EntryCount != 2 {
		t.Fatalf("rotated journal verification failed: %+v", got)
	}
}

func TestRotationFailsClosedWithoutHistoricalKey(t *testing.T) {
	_, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	oldSigner, _ := NewEd25519Signer("old", oldPrivate)
	oldRing := NewEd25519Keyring()
	_ = oldRing.Add(oldSigner.KeyID(), oldSigner.PublicKey())

	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	anchorPath := filepath.Join(dir, "journal.anchor.json")
	j, err := NewFileJournalWithSecurity(path, anchorPath, oldSigner, oldRing, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(context.Background(), testEvent("one", "ALLOW")); err != nil {
		t.Fatal(err)
	}

	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newSigner, _ := NewEd25519Signer("new", newPrivate)
	newOnlyRing := NewEd25519Keyring()
	_ = newOnlyRing.Add(newSigner.KeyID(), newSigner.PublicKey())

	if _, err := NewFileJournalWithSecurity(path, anchorPath, newSigner, newOnlyRing, nil); err == nil {
		t.Fatal("rotation without the historical verification key must fail closed")
	}
}
