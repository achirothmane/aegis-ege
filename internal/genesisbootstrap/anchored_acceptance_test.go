package genesisbootstrap

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestAnchoredLedgerBindsRecordIndexToMonotonicCounter(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	anchor := &memoryMonotonicAnchor{id: "anchor-A"}
	ledger := mustAnchoredAcceptanceLedger(t, path, anchor)
	now := time.Date(2026, 9, 28, 15, 30, 0, 0, time.UTC)
	candidate := mustAcceptanceCandidate(
		t,
		acceptanceTestManifest(7, 0, "", 3, digestString("doctrine"), 7),
		acceptanceTestRevocations(1),
		now,
	)

	session, _, err := ledger.Begin(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if anchor.value != 1 {
		t.Fatalf("anchor value = %d, want 1", anchor.value)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := readAcceptanceRecords(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].MonotonicAnchorID != "anchor-A" || records[0].MonotonicAnchorValue != 1 {
		t.Fatalf("unexpected anchor binding: %+v", records[0])
	}
}

func TestAnchoredLedgerDetectsWholeDiskRollbackAgainstTPM(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	anchor := &memoryMonotonicAnchor{id: "anchor-A"}
	now := time.Date(2026, 9, 28, 15, 30, 0, 0, time.UTC)

	firstManifest := acceptanceTestManifest(7, 0, "", 3, digestString("doctrine"), 7)
	first := mustAcceptanceCandidate(t, firstManifest, acceptanceTestRevocations(1), now)
	acceptAnchoredCandidate(t, path, anchor, first)

	oldSnapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	secondManifest := acceptanceTestManifest(7, 1, first.ManifestHash, 3, digestString("doctrine"), 7)
	secondManifest.Authenticity.Signature = "second"
	second := mustAcceptanceCandidate(t, secondManifest, acceptanceTestRevocations(2), now.Add(time.Minute))
	acceptAnchoredCandidate(t, path, anchor, second)
	if anchor.value != 2 {
		t.Fatalf("anchor value = %d, want 2", anchor.value)
	}

	if err := os.WriteFile(path, oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := mustAnchoredAcceptanceLedger(t, path, anchor)
	if _, _, err := ledger.Begin(context.Background(), second); !errors.Is(err, ErrAcceptanceRollback) {
		t.Fatalf("rolled-back disk error = %v, want %v", err, ErrAcceptanceRollback)
	}
}

func TestAnchoredLedgerDetectsAnchorIdentityReplacement(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	anchor := &memoryMonotonicAnchor{id: "anchor-A"}
	now := time.Date(2026, 9, 28, 15, 30, 0, 0, time.UTC)
	candidate := mustAcceptanceCandidate(
		t,
		acceptanceTestManifest(7, 0, "", 3, digestString("doctrine"), 7),
		acceptanceTestRevocations(1),
		now,
	)
	acceptAnchoredCandidate(t, path, anchor, candidate)

	anchor.id = "anchor-B"
	if _, _, err := mustAnchoredAcceptanceLedger(t, path, anchor).Begin(context.Background(), candidate); !errors.Is(err, ErrAcceptanceContinuity) {
		t.Fatalf("anchor replacement error = %v, want %v", err, ErrAcceptanceContinuity)
	}
}

func TestAnchoredLedgerFailsClosedWhenAnchorAdvancesButDiskCommitFails(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	anchor := &memoryMonotonicAnchor{id: "anchor-A"}
	now := time.Date(2026, 9, 28, 15, 30, 0, 0, time.UTC)

	firstManifest := acceptanceTestManifest(7, 0, "", 3, digestString("doctrine"), 7)
	first := mustAcceptanceCandidate(t, firstManifest, acceptanceTestRevocations(1), now)
	acceptAnchoredCandidate(t, path, anchor, first)

	secondManifest := acceptanceTestManifest(7, 1, first.ManifestHash, 3, digestString("doctrine"), 7)
	secondManifest.Authenticity.Signature = "second"
	second := mustAcceptanceCandidate(t, secondManifest, acceptanceTestRevocations(2), now.Add(time.Minute))

	ledger := mustAnchoredAcceptanceLedger(t, path, anchor)
	session, _, err := ledger.Begin(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(); err == nil {
		t.Fatal("expected disk commit failure after anchor advance")
	}
	if anchor.value != 2 {
		t.Fatalf("anchor value = %d, want 2 after advance-before-disk failure", anchor.value)
	}

	if _, _, err := mustAnchoredAcceptanceLedger(t, path, anchor).Begin(context.Background(), second); !errors.Is(err, ErrAcceptanceRollback) {
		t.Fatalf("post-failure restart error = %v, want %v", err, ErrAcceptanceRollback)
	}
}

func TestAnchoredLedgerDoesNotAppendWhenAnchorAdvanceFails(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	anchor := &memoryMonotonicAnchor{
		id:         "anchor-A",
		advanceErr: errors.New("hardware unavailable"),
	}
	now := time.Date(2026, 9, 28, 15, 30, 0, 0, time.UTC)
	candidate := mustAcceptanceCandidate(
		t,
		acceptanceTestManifest(7, 0, "", 3, digestString("doctrine"), 7),
		acceptanceTestRevocations(1),
		now,
	)

	session, _, err := mustAnchoredAcceptanceLedger(t, path, anchor).Begin(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(); err == nil {
		t.Fatal("expected monotonic anchor advance failure")
	}
	_ = session.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("ledger size = %d, want 0 after anchor failure", info.Size())
	}
}

func acceptAnchoredCandidate(t *testing.T, path string, anchor MonotonicAnchor, candidate AcceptanceCandidate) {
	t.Helper()
	ledger := mustAnchoredAcceptanceLedger(t, path, anchor)
	session, _, err := ledger.Begin(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}
