//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMNVHistoryAnchorRejectsWholeVolumeRollbackToValidSignedHead(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A151),
		StatePath: filepath.Join(dir, "history-anchor.json"),
		IndexAuth: []byte("aegis-history-anchor-test"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := kernelfabric.TaintRecoveryHistoryStore{
		Dir: filepath.Join(dir, "recovery-history"),
	}
	base := time.Date(2026, 10, 3, 2, 10, 0, 0, time.UTC)

	first := tpmHistoryAnchorReceipt("h1", "", 1, base)
	signedFirst, err := kernelfabric.SignTaintRecoveryHistoryReceipt(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := store.AppendAnchored(
		context.Background(),
		signedFirst,
		publicKey,
		anchor,
	)
	if err != nil {
		t.Fatal(err)
	}

	headAtH1, err := os.ReadFile(filepath.Join(store.Dir, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	anchorAtH1, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	stateAtH1, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read H1 anchor state: ok=%t err=%v", ok, err)
	}

	second := tpmHistoryAnchorReceipt(
		"h2",
		firstDigest,
		2,
		base.Add(time.Minute),
	)
	signedSecond, err := kernelfabric.SignTaintRecoveryHistoryReceipt(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := store.AppendAnchored(
		context.Background(),
		signedSecond,
		publicKey,
		anchor,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondDigest == firstDigest {
		t.Fatal("distinct recovery receipts produced the same digest")
	}
	stateAtH2, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read H2 anchor state: ok=%t err=%v", ok, err)
	}
	if stateAtH2.Generation != stateAtH1.Generation+1 {
		t.Fatalf(
			"TPM history generation did not advance exactly once: H1=%d H2=%d",
			stateAtH1.Generation,
			stateAtH2.Generation,
		)
	}
	counterAtH2, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAtH2 != stateAtH2.Generation {
		t.Fatalf(
			"TPM counter/state mismatch before rollback scenario: counter=%d state=%d",
			counterAtH2,
			stateAtH2.Generation,
		)
	}
	if _, digest, exists, err := store.CurrentAnchored(
		context.Background(),
		publicKey,
		anchor,
	); err != nil || !exists || digest != secondDigest {
		t.Fatalf(
			"H2 did not verify before rollback scenario: exists=%t digest=%s err=%v",
			exists,
			digest,
			err,
		)
	}

	// Simulate restoring the writable volume to the exact H1 snapshot while the
	// TPM NV counter remains at H2. Both the history head and the anchor's
	// companion state are old but individually valid.
	if err := os.WriteFile(filepath.Join(store.Dir, "head.json"), headAtH1, 0o600); err != nil {
		t.Fatal(err)
	}
	h2ReceiptPath := filepath.Join(
		store.Dir,
		"receipts",
		strings.TrimPrefix(secondDigest, "sha256:")+".json",
	)
	if err := os.Remove(h2ReceiptPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, anchorAtH1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.StatePath + ".pending"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	unanchored, unanchoredDigest, exists, err := store.Current(publicKey)
	if err != nil {
		t.Fatalf("restored H1 signature should still verify locally: %v", err)
	}
	if !exists || unanchoredDigest != firstDigest || unanchored.Receipt.ReceiptID != "h1" {
		t.Fatalf(
			"restored local history is not exact H1: exists=%t digest=%s receipt=%+v",
			exists,
			unanchoredDigest,
			unanchored.Receipt,
		)
	}

	restoredState, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read restored H1 anchor state: ok=%t err=%v", ok, err)
	}
	if restoredState.Generation != stateAtH1.Generation {
		t.Fatalf(
			"companion state was not restored to H1: got=%d want=%d",
			restoredState.Generation,
			stateAtH1.Generation,
		)
	}
	counterAfterRestore, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfterRestore != counterAtH2 {
		t.Fatalf(
			"TPM counter unexpectedly rolled back with writable volume: got=%d want=%d",
			counterAfterRestore,
			counterAtH2,
		)
	}

	if _, err := anchor.Current(context.Background()); !errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("TPM did not detect restored companion state: %v", err)
	}
	if _, _, _, err := store.CurrentAnchored(
		context.Background(),
		publicKey,
		anchor,
	); err == nil ||
		!errors.Is(err, kernelfabric.ErrTaintRecoveryHistoryRollback) ||
		!errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("restored signed history was not rejected fail-closed: %v", err)
	}
}

func TestTPMNVHistoryAnchorRecoversCommittedPendingAfterInterruption(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A152),
		StatePath: filepath.Join(dir, "history-anchor.json"),
		IndexAuth: []byte("aegis-history-anchor-crash-test"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	current, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read initial history anchor: ok=%t err=%v", ok, err)
	}
	nextDigest := "sha256:" + strings.Repeat("a", 64)
	next := current
	next.PreviousGeneration = current.Generation
	next.Generation = current.Generation + 1
	next.PreviousHeadDigest = current.HeadDigest
	next.HeadDigest = nextDigest
	next.Digest = ""
	if err := writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath+".pending", next); err != nil {
		t.Fatal(err)
	}
	counter, err := anchor.helper.incrementCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counter != next.Generation {
		t.Fatalf("counter did not reach pending generation: got=%d want=%d", counter, next.Generation)
	}

	restarted, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	head, err := restarted.Current(context.Background())
	if err != nil {
		t.Fatalf("post-increment pending state did not recover: %v", err)
	}
	if head != nextDigest {
		t.Fatalf("pending head was not promoted: got=%s want=%s", head, nextDigest)
	}
	if _, err := os.Stat(cfg.StatePath + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("pending state was not consumed: %v", err)
	}
}

func tpmHistoryAnchorReceipt(
	id,
	previous string,
	epoch uint64,
	recordedAt time.Time,
) kernelfabric.TaintRecoveryHistoryReceipt {
	boot := sha256.Sum256([]byte("tpm-history-boot-" + id))
	plan := sha256.Sum256([]byte("tpm-history-plan-" + id))
	return kernelfabric.TaintRecoveryHistoryReceipt{
		Version:               kernelfabric.TaintRecoveryHistoryReceiptVersion,
		ReceiptID:             id,
		Event:                 kernelfabric.TaintRecoveryHistoryEventRecoveryCommitted,
		BootIDHash:            fmt.Sprintf("sha256:%x", boot[:]),
		PlanDigest:            fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:              77,
		EnrollmentEpoch:       epoch,
		DirtyGeneration:       epoch,
		CleanGeneration:       epoch,
		CleanEffectAllowed:    true,
		TaintedEffectDenied:   true,
		PreviousReceiptDigest: previous,
		RecordedAt:            recordedAt,
	}
}
