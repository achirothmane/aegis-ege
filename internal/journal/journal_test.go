package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileJournalVerifiesIntactChain(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	got := j.Verify(context.Background())
	if !got.Valid || got.EntryCount != 3 || got.HeadHash == "" {
		t.Fatalf("expected valid three-entry chain, got %+v", got)
	}

	external := VerifyFiles(path, anchorPath, j.PublicKey())
	if !external.Valid || external.EntryCount != 3 {
		t.Fatalf("external verification failed: %+v", external)
	}
}

func TestFileJournalDetectsMiddleEntryModification(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	lines := readLines(t, path)
	var entry Entry
	if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
		t.Fatal(err)
	}
	entry.Event.Decision = "BLOCK"
	tampered, _ := json.Marshal(entry)
	lines[1] = string(tampered)
	writeLines(t, path, lines)

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "hash mismatch")
}

func TestFileJournalDetectsReordering(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	lines := readLines(t, path)
	lines[0], lines[1] = lines[1], lines[0]
	writeLines(t, path, lines)

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "sequence mismatch")
}

func TestFileJournalDetectsMiddleDeletion(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	lines := readLines(t, path)
	lines = append(lines[:1], lines[2:]...)
	writeLines(t, path, lines)

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "sequence mismatch")
}

func TestSignedAnchorDetectsTailTruncation(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	lines := readLines(t, path)
	writeLines(t, path, lines[:2])

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "anchor sequence")
}

func TestSignedAnchorDetectsAnchorTampering(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	data, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	var anchor Anchor
	if err := json.Unmarshal(data, &anchor); err != nil {
		t.Fatal(err)
	}
	anchor.HeadHash = "sha256:deadbeef"
	tampered, _ := json.Marshal(anchor)
	if err := os.WriteFile(anchorPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "anchor verification")
}

func TestMissingAnchorFailsClosed(t *testing.T) {
	j, path, anchorPath := newTestJournal(t)
	appendThree(t, j)

	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	got := VerifyFiles(path, anchorPath, j.PublicKey())
	if got.Valid {
		t.Fatalf("missing anchor must fail verification: %+v", got)
	}
}

func TestAppendRefusesTamperedJournal(t *testing.T) {
	j, path, _ := newTestJournal(t)
	appendThree(t, j)

	lines := readLines(t, path)
	lines[0] = strings.Replace(lines[0], "ALLOW", "BLOCK", 1)
	writeLines(t, path, lines)

	if _, err := j.Append(context.Background(), testEvent("four", "ALLOW")); err == nil {
		t.Fatal("append must refuse an unverifiable journal")
	}
}

func TestDigestPayloadStableForSameValue(t *testing.T) {
	value := struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}{Action: "drain", Count: 2}

	a, err := DigestPayload(value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DigestPayload(value)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("expected stable SHA-256 payload digest, a=%q b=%q", a, b)
	}
}

func newTestJournal(t *testing.T) (*FileJournal, string, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	anchorPath := filepath.Join(dir, "journal.anchor.json")
	j, err := NewFileJournal(path, anchorPath, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return j, path, anchorPath
}

func appendThree(t *testing.T, j *FileJournal) {
	t.Helper()
	ctx := context.Background()
	for _, event := range []Event{
		testEvent("one", "ALLOW"),
		testEvent("two", "ALLOW"),
		testEvent("three", "ALLOW"),
	} {
		if _, err := j.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
}

func testEvent(actionID, decisionValue string) Event {
	return Event{
		Type:           EventDecision,
		ActionID:       actionID,
		Target:         "node/node-7",
		Decision:       decisionValue,
		EvidenceDigest: "sha256:evidence",
		PlanDigest:     "sha256:plan",
		OccurredAt:     time.Date(2026, 9, 23, 19, 40, 0, 0, time.UTC),
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertInvalid(t *testing.T, got Verification, contains string) {
	t.Helper()
	if got.Valid {
		t.Fatalf("expected verification failure, got %+v", got)
	}
	if contains != "" && !strings.Contains(got.Error, contains) {
		t.Fatalf("expected error containing %q, got %+v", contains, got)
	}
}
