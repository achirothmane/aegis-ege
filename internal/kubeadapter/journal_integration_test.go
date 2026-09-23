//go:build integration

package kubeadapter

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

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/journal"
)

func TestKindM6JournalBindsAuthorizationExecutionAndOutcome(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m6-journal")
	policy := integrationExecutionPolicy()

	preparation, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		env.adapter,
		"m6-journal-action",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Allow ||
		preparation.Authorization == nil ||
		preparation.Plan == nil {
		t.Fatalf(
			"expected successful guarded execution, decision=%s reasons=%v",
			report.Decision,
			report.ReasonCodes,
		)
	}

	outcomeRecord, err := env.adapter.ObserveDrainOutcome(
		context.Background(),
		*preparation.Authorization,
		*preparation.Plan,
		nil,
	)
	if err != nil {
		t.Fatalf("ObserveDrainOutcome: %v", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "execution.jsonl")
	anchorPath := filepath.Join(dir, "execution.anchor.json")
	j, err := journal.NewFileJournal(journalPath, anchorPath, privateKey)
	if err != nil {
		t.Fatalf("NewFileJournal: %v", err)
	}

	now := time.Now().UTC()
	authEvent := JournalAuthorizationEvent(*preparation.Authorization, now)
	executionEvent, err := JournalExecutionEvent(
		*preparation.Authorization,
		report,
		now.Add(time.Millisecond),
	)
	if err != nil {
		t.Fatalf("JournalExecutionEvent: %v", err)
	}
	outcomeEvent, err := JournalOutcomeEvent(outcomeRecord)
	if err != nil {
		t.Fatalf("JournalOutcomeEvent: %v", err)
	}

	for _, event := range []journal.Event{authEvent, executionEvent, outcomeEvent} {
		if _, err := j.Append(context.Background(), event); err != nil {
			t.Fatalf("append %s event: %v", event.Type, err)
		}
	}

	verification := j.Verify(context.Background())
	if !verification.Valid || verification.EntryCount != 3 {
		t.Fatalf("expected intact three-entry journal, got %+v", verification)
	}

	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three journal lines, got %d", len(lines))
	}

	entries := make([]journal.Entry, 0, 3)
	for _, line := range lines {
		var entry journal.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode journal line: %v", err)
		}
		entries = append(entries, entry)
	}

	for i, entry := range entries {
		if entry.Sequence != uint64(i+1) {
			t.Fatalf("unexpected sequence at entry %d: %+v", i, entry)
		}
		if entry.Event.ActionID != preparation.Authorization.ActionID {
			t.Fatalf("action binding lost at entry %d: %+v", i, entry.Event)
		}
		if entry.Event.EvidenceDigest != preparation.Authorization.EvidenceDigest {
			t.Fatalf("evidence binding lost at entry %d: %+v", i, entry.Event)
		}
		if entry.Event.PlanDigest != preparation.Authorization.PlanDigest {
			t.Fatalf("plan binding lost at entry %d: %+v", i, entry.Event)
		}
	}

	// Tamper with the execution event while keeping its stored entry hash.
	// Verification must fail instead of accepting a rewritten audit record.
	entries[1].Event.Decision = string(decision.Block)
	tamperedMiddle, err := json.Marshal(entries[1])
	if err != nil {
		t.Fatalf("marshal tampered entry: %v", err)
	}
	lines[1] = string(tamperedMiddle)
	if err := os.WriteFile(
		journalPath,
		[]byte(strings.Join(lines, "\n")+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write tampered journal: %v", err)
	}

	tampered := journal.VerifyFiles(journalPath, anchorPath, j.PublicKey())
	if tampered.Valid {
		t.Fatalf("tampered live execution journal unexpectedly verified: %+v", tampered)
	}
	if !strings.Contains(tampered.Error, "hash mismatch") {
		t.Fatalf("expected hash mismatch after tamper, got %+v", tampered)
	}
}
