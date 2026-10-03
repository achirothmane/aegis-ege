//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memoryRecoveryHistoryAnchor struct {
	head     string
	failOnce bool
}

func (a *memoryRecoveryHistoryAnchor) Advance(
	_ context.Context,
	previousDigest,
	nextDigest string,
) error {
	if a.failOnce {
		a.failOnce = false
		return errors.New("synthetic anchor interruption")
	}
	if a.head == nextDigest {
		return nil
	}
	if a.head != previousDigest {
		return fmt.Errorf("anchor predecessor mismatch: got=%s want=%s", a.head, previousDigest)
	}
	a.head = nextDigest
	return nil
}

func (a *memoryRecoveryHistoryAnchor) Current(context.Context) (string, error) {
	return a.head, nil
}

func TestAnchoredRecoveryHistoryRejectsRestoredSignedHead(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := TaintRecoveryHistoryStore{Dir: filepath.Join(t.TempDir(), "history")}
	anchor := &memoryRecoveryHistoryAnchor{}
	base := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)

	first := recoveryHistoryAnchorTestReceipt(t, "h1", "", 1, base)
	signedFirst, err := SignTaintRecoveryHistoryReceipt(first, privateKey)
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
	headAtFirst, err := os.ReadFile(filepath.Join(store.Dir, "head.json"))
	if err != nil {
		t.Fatal(err)
	}

	second := recoveryHistoryAnchorTestReceipt(
		t,
		"h2",
		firstDigest,
		2,
		base.Add(time.Minute),
	)
	signedSecond, err := SignTaintRecoveryHistoryReceipt(second, privateKey)
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
	if anchor.head != secondDigest {
		t.Fatalf("anchor did not advance: got=%s want=%s", anchor.head, secondDigest)
	}

	if err := os.WriteFile(filepath.Join(store.Dir, "head.json"), headAtFirst, 0o600); err != nil {
		t.Fatal(err)
	}

	unanchored, unanchoredDigest, exists, err := store.Current(publicKey)
	if err != nil {
		t.Fatalf("old signed head should remain cryptographically valid: %v", err)
	}
	if !exists || unanchoredDigest != firstDigest || unanchored.Receipt.ReceiptID != "h1" {
		t.Fatalf(
			"unexpected restored local head: exists=%t digest=%s receipt=%+v",
			exists,
			unanchoredDigest,
			unanchored.Receipt,
		)
	}

	if _, _, _, err := store.CurrentAnchored(
		context.Background(),
		publicKey,
		anchor,
	); !errors.Is(err, ErrTaintRecoveryHistoryRollback) {
		t.Fatalf("restored signed head was not rejected by monotonic anchor: %v", err)
	}
}

func TestAnchoredAppendRetryRepairsAnchorAfterInterruptedAdvance(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := TaintRecoveryHistoryStore{Dir: filepath.Join(t.TempDir(), "history")}
	anchor := &memoryRecoveryHistoryAnchor{failOnce: true}
	receipt := recoveryHistoryAnchorTestReceipt(
		t,
		"retry",
		"",
		1,
		time.Date(2026, 10, 3, 2, 5, 0, 0, time.UTC),
	)
	signed, err := SignTaintRecoveryHistoryReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := TaintRecoveryHistoryReceiptDigest(signed)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.AppendAnchored(
		context.Background(),
		signed,
		publicKey,
		anchor,
	); !errors.Is(err, ErrTaintRecoveryHistoryRollback) {
		t.Fatalf("interrupted anchor advance did not fail closed: %v", err)
	}

	if _, _, _, err := store.CurrentAnchored(
		context.Background(),
		publicKey,
		anchor,
	); !errors.Is(err, ErrTaintRecoveryHistoryRollback) {
		t.Fatalf("unanchored durable head did not fail closed: %v", err)
	}

	got, err := store.AppendAnchored(
		context.Background(),
		signed,
		publicKey,
		anchor,
	)
	if err != nil {
		t.Fatalf("idempotent retry did not repair anchor: %v", err)
	}
	if got != expectedDigest || anchor.head != expectedDigest {
		t.Fatalf("retry mismatch: digest=%s anchor=%s want=%s", got, anchor.head, expectedDigest)
	}
	if _, digest, exists, err := store.CurrentAnchored(
		context.Background(),
		publicKey,
		anchor,
	); err != nil || !exists || digest != expectedDigest {
		t.Fatalf("repaired anchored history unavailable: exists=%t digest=%s err=%v", exists, digest, err)
	}
}

func recoveryHistoryAnchorTestReceipt(
	t *testing.T,
	id,
	previous string,
	epoch uint64,
	recordedAt time.Time,
) TaintRecoveryHistoryReceipt {
	t.Helper()
	boot := sha256.Sum256([]byte("boot-" + id))
	plan := sha256.Sum256([]byte("plan-" + id))
	return TaintRecoveryHistoryReceipt{
		Version:               TaintRecoveryHistoryReceiptVersion,
		ReceiptID:             id,
		Event:                 TaintRecoveryHistoryEventRecoveryCommitted,
		BootIDHash:            fmt.Sprintf("sha256:%x", boot[:]),
		PlanDigest:            fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:              42,
		EnrollmentEpoch:       epoch,
		DirtyGeneration:       epoch,
		CleanGeneration:       epoch,
		CleanEffectAllowed:    true,
		TaintedEffectDenied:   true,
		PreviousReceiptDigest: previous,
		RecordedAt:            recordedAt,
	}
}
