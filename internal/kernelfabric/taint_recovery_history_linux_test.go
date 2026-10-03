//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaintRecoveryHistoryStorePersistsSignedChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot := sha256.Sum256([]byte("boot-b"))
	plan := sha256.Sum256([]byte("plan-b"))
	base := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	store := TaintRecoveryHistoryStore{Dir: filepath.Join(t.TempDir(), "history")}

	first := TaintRecoveryHistoryReceipt{
		Version:             TaintRecoveryHistoryReceiptVersion,
		ReceiptID:           "r1",
		Event:               TaintRecoveryHistoryEventReenrolled,
		BootIDHash:          fmt.Sprintf("sha256:%x", boot[:]),
		PlanDigest:          fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:            42,
		EnrollmentEpoch:     1,
		DirtyGeneration:     0,
		CleanGeneration:     0,
		CleanEffectAllowed:  true,
		TaintedEffectDenied: true,
		RecordedAt:          base,
	}
	signedFirst, err := SignTaintRecoveryHistoryReceipt(first, priv)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := store.Append(signedFirst, pub)
	if err != nil {
		t.Fatal(err)
	}

	second := first
	second.ReceiptID = "r2"
	second.Event = TaintRecoveryHistoryEventRecoveryCommitted
	second.EnrollmentEpoch = 2
	second.DirtyGeneration = 3
	second.CleanGeneration = 3
	second.PreviousReceiptDigest = firstDigest
	second.RecordedAt = base.Add(time.Minute)
	signedSecond, err := SignTaintRecoveryHistoryReceipt(second, priv)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := store.Append(signedSecond, pub)
	if err != nil {
		t.Fatal(err)
	}

	// A brand-new store object simulates a restarted controller.
	restarted := TaintRecoveryHistoryStore{Dir: store.Dir}
	current, digest, exists, err := restarted.Current(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || digest != secondDigest || current.Receipt.ReceiptID != "r2" {
		t.Fatalf("durable history mismatch: exists=%v digest=%s receipt=%+v", exists, digest, current.Receipt)
	}

	// Re-appending the exact current receipt is idempotent.
	replayed, err := restarted.Append(signedSecond, pub)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != secondDigest {
		t.Fatalf("idempotent append changed digest: got=%s want=%s", replayed, secondDigest)
	}
}

func TestTaintRecoveryHistoryRejectsForkAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot := sha256.Sum256([]byte("boot"))
	plan := sha256.Sum256([]byte("plan"))
	now := time.Now().UTC()
	store := TaintRecoveryHistoryStore{Dir: filepath.Join(t.TempDir(), "history")}

	base := TaintRecoveryHistoryReceipt{
		Version:             TaintRecoveryHistoryReceiptVersion,
		ReceiptID:           "base",
		Event:               TaintRecoveryHistoryEventRecoveryCommitted,
		BootIDHash:          fmt.Sprintf("sha256:%x", boot[:]),
		PlanDigest:          fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:            7,
		EnrollmentEpoch:     2,
		DirtyGeneration:     1,
		CleanGeneration:     1,
		CleanEffectAllowed:  true,
		TaintedEffectDenied: true,
		RecordedAt:          now,
	}
	signed, err := SignTaintRecoveryHistoryReceipt(base, priv)
	if err != nil {
		t.Fatal(err)
	}
	head, err := store.Append(signed, pub)
	if err != nil {
		t.Fatal(err)
	}

	fork := base
	fork.ReceiptID = "fork"
	fork.EnrollmentEpoch = 3
	fork.RecordedAt = now.Add(time.Second)
	fork.PreviousReceiptDigest = "sha256:" + strings.Repeat("f", 64)
	signedFork, err := SignTaintRecoveryHistoryReceipt(fork, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(signedFork, pub); err == nil {
		t.Fatal("history fork unexpectedly accepted")
	}

	receiptPath := filepath.Join(store.Dir, "receipts", strings.TrimPrefix(head, "sha256:")+".json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(receiptPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Current(pub); err == nil {
		t.Fatal("tampered durable history unexpectedly verified")
	}
}
