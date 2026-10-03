//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testTaintRecoveryHistoryAnchor struct {
	mu    sync.Mutex
	state TaintRecoveryHistoryAnchorState
}

func (a *testTaintRecoveryHistoryAnchor) Current(context.Context) (TaintRecoveryHistoryAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *testTaintRecoveryHistoryAnchor) CompareAndAdvance(
	_ context.Context,
	expected TaintRecoveryHistoryAnchorState,
	next TaintRecoveryHistoryAnchorState,
) (TaintRecoveryHistoryAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != expected {
		return TaintRecoveryHistoryAnchorState{}, errors.New("anchor changed concurrently")
	}
	if next.Sequence != expected.Sequence+1 {
		return TaintRecoveryHistoryAnchorState{}, errors.New("anchor sequence did not advance exactly once")
	}
	if _, err := ParseSHA256Digest(next.HeadDigest); err != nil {
		return TaintRecoveryHistoryAnchorState{}, fmt.Errorf("anchor head digest: %w", err)
	}
	a.state = next
	return a.state, nil
}

func TestAnchoredRecoveryHistoryDetectsWholeVolumeRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boot := sha256.Sum256([]byte("same-boot-history-rollback"))
	plan := sha256.Sum256([]byte("same-boot-plan"))
	base := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)

	root := t.TempDir()
	liveDir := filepath.Join(root, "live-history")
	snapshotDir := filepath.Join(root, "snapshot-r1")
	raw := TaintRecoveryHistoryStore{Dir: liveDir}
	anchor := &testTaintRecoveryHistoryAnchor{}
	anchored := AnchoredTaintRecoveryHistoryStore{Store: raw, Anchor: anchor}

	r1 := TaintRecoveryHistoryReceipt{
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
	s1, err := SignTaintRecoveryHistoryReceipt(r1, priv)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := anchored.Append(context.Background(), s1, pub)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.state.Sequence != 1 || anchor.state.HeadDigest != d1 {
		t.Fatalf("anchor after R1 = %+v, want sequence=1 head=%s", anchor.state, d1)
	}
	if err := copyRecoveryHistoryTree(liveDir, snapshotDir); err != nil {
		t.Fatalf("snapshot R1 history volume: %v", err)
	}

	r2 := r1
	r2.ReceiptID = "r2"
	r2.Event = TaintRecoveryHistoryEventRecoveryCommitted
	r2.EnrollmentEpoch = 2
	r2.DirtyGeneration = 1
	r2.CleanGeneration = 1
	r2.PreviousReceiptDigest = d1
	r2.RecordedAt = base.Add(time.Minute)
	s2, err := SignTaintRecoveryHistoryReceipt(r2, priv)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := anchored.Append(context.Background(), s2, pub)
	if err != nil {
		t.Fatal(err)
	}
	if d2 == d1 {
		t.Fatal("R2 did not advance history digest")
	}
	if anchor.state.Sequence != 2 || anchor.state.HeadDigest != d2 {
		t.Fatalf("anchor after R2 = %+v, want sequence=2 head=%s", anchor.state, d2)
	}

	current, digest, exists, err := anchored.Current(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || digest != d2 || current.Receipt.ReceiptID != "r2" {
		t.Fatalf("anchored R2 current mismatch: exists=%v digest=%s receipt=%+v", exists, digest, current.Receipt)
	}

	// Restore the entire writable history volume to its earlier R1 snapshot.
	// The independent anchor is deliberately not rolled back.
	if err := os.RemoveAll(liveDir); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveryHistoryTree(snapshotDir, liveDir); err != nil {
		t.Fatalf("restore R1 volume snapshot: %v", err)
	}

	// Cryptography alone cannot identify this as stale: R1 is intact, signed,
	// and internally consistent, so the unanchored store accepts it.
	rawCurrent, rawDigest, rawExists, err := raw.Current(pub)
	if err != nil {
		t.Fatalf("raw cryptographic history rejected valid R1 snapshot: %v", err)
	}
	if !rawExists || rawDigest != d1 || rawCurrent.Receipt.ReceiptID != "r1" {
		t.Fatalf("raw rollback state mismatch: exists=%v digest=%s receipt=%+v", rawExists, rawDigest, rawCurrent.Receipt)
	}

	// The independent exact-head commitment makes the same R1 snapshot stale.
	_, _, _, err = anchored.Current(context.Background(), pub)
	if !errors.Is(err, ErrTaintRecoveryHistoryRollback) {
		t.Fatalf("whole-volume rollback error=%v, want %v", err, ErrTaintRecoveryHistoryRollback)
	}
	if anchor.state.Sequence != 2 || anchor.state.HeadDigest != d2 {
		t.Fatalf("rollback mutated independent anchor: %+v", anchor.state)
	}

	// A new append cannot build authority on top of the rolled-back R1 volume.
	r3 := r1
	r3.ReceiptID = "r3-from-rolled-back-r1"
	r3.EnrollmentEpoch = 3
	r3.DirtyGeneration = 2
	r3.CleanGeneration = 2
	r3.PreviousReceiptDigest = d1
	r3.RecordedAt = base.Add(2 * time.Minute)
	s3, err := SignTaintRecoveryHistoryReceipt(r3, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchored.Append(context.Background(), s3, pub); !errors.Is(err, ErrTaintRecoveryHistoryRollback) {
		t.Fatalf("append on rolled-back history error=%v, want rollback denial", err)
	}
}

func copyRecoveryHistoryTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source %s is not a directory", src)
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.IsDir() {
			if err := copyRecoveryHistoryTree(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if !entryInfo.Mode().IsRegular() {
			continue
		}
		in, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, entryInfo.Mode().Perm())
		if err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		syncErr := out.Sync()
		closeOutErr := out.Close()
		closeInErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeOutErr != nil {
			return closeOutErr
		}
		if closeInErr != nil {
			return closeInErr
		}
	}
	dir, err := os.Open(dst)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
