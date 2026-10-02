package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

type testCapabilityMonotonicAnchor struct {
	mu       sync.Mutex
	identity string
	value    uint64
}

func (a *testCapabilityMonotonicAnchor) Identity(context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == "" {
		return "", errors.New("anchor identity is empty")
	}
	return a.identity, nil
}

func (a *testCapabilityMonotonicAnchor) Read(context.Context) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.value, nil
}

func (a *testCapabilityMonotonicAnchor) Advance(_ context.Context, expected uint64) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.value != expected {
		return 0, errors.New("anchor changed concurrently")
	}
	a.value++
	return a.value, nil
}

func anchoredCapabilityScope() CapabilityFenceScope {
	return CapabilityFenceScope{
		IntentID: "intent-cap-root-1",
		Kind:     "kubernetes.node_drain",
		Target: egeproto.Target{
			Type: "kubernetes.node",
			Name: "node-7",
		},
	}
}

func anchoredCapabilitySnapshot(decisionEpoch uint64) egeproto.CapabilityAuthoritySnapshot {
	return egeproto.CapabilityAuthoritySnapshot{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   decisionEpoch,
		RevocationEpoch: 4,
	}
}

func TestAnchoredCapabilityRootPersistsHighWaterAndRejectsRegression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityMonotonicAnchor{identity: "test-anchor"}
	root, err := NewAnchoredFileCapabilityMonotonicRoot(path, anchor)
	if err != nil {
		t.Fatal(err)
	}

	scope := anchoredCapabilityScope()
	t1 := anchoredCapabilitySnapshot(31)
	t2 := anchoredCapabilitySnapshot(32)

	got, err := root.Advance(context.Background(), scope, t1)
	if err != nil {
		t.Fatal(err)
	}
	if got != t1 {
		t.Fatalf("advance T1 = %+v, want %+v", got, t1)
	}
	got, err = root.Advance(context.Background(), scope, t2)
	if err != nil {
		t.Fatal(err)
	}
	if got != t2 {
		t.Fatalf("advance T2 = %+v, want %+v", got, t2)
	}
	if anchor.value != 2 {
		t.Fatalf("anchor value = %d, want 2", anchor.value)
	}

	reopened, err := NewAnchoredFileCapabilityMonotonicRoot(path, anchor)
	if err != nil {
		t.Fatal(err)
	}
	current, err := reopened.Current(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if current != t2 {
		t.Fatalf("reopened current = %+v, want %+v", current, t2)
	}

	got, err = reopened.Advance(context.Background(), scope, t1)
	if err != nil {
		t.Fatal(err)
	}
	if got != t2 {
		t.Fatalf("regression returned %+v, want preserved %+v", got, t2)
	}
	if anchor.value != 2 {
		t.Fatalf("regression advanced anchor to %d, want 2", anchor.value)
	}
}

func TestAnchoredCapabilityRootDetectsDiskRollbackAfterAnchorAdvance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityMonotonicAnchor{identity: "test-anchor"}
	root, err := NewAnchoredFileCapabilityMonotonicRoot(path, anchor)
	if err != nil {
		t.Fatal(err)
	}

	scope := anchoredCapabilityScope()
	t1 := anchoredCapabilitySnapshot(31)
	t2 := anchoredCapabilitySnapshot(32)

	if _, err := root.Advance(context.Background(), scope, t1); err != nil {
		t.Fatal(err)
	}
	t1Ledger, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Advance(context.Background(), scope, t2); err != nil {
		t.Fatal(err)
	}
	if anchor.value != 2 {
		t.Fatalf("anchor value = %d, want 2", anchor.value)
	}

	if err := os.WriteFile(path, t1Ledger, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = root.Current(context.Background(), scope)
	if !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("rolled-back ledger error = %v, want %v", err, ErrCapabilityRootRollback)
	}
}

func TestIndependentAuthorityFailsClosedWhenMutableAndLedgerRollbackTogether(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityMonotonicAnchor{identity: "test-anchor"}
	root, err := NewAnchoredFileCapabilityMonotonicRoot(path, anchor)
	if err != nil {
		t.Fatal(err)
	}

	scope := anchoredCapabilityScope()
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authority.Issue(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	t1Ledger, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t2Issue := t1Issue
	t2Issue.DecisionEpoch++
	t2 := capabilityAuthoritySnapshotFromIssue(t2Issue)
	mutable.issue = t2Issue
	mutable.coordination = t2
	mutable.witness = t2
	if _, err := authority.Issue(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if anchor.value != 2 {
		t.Fatalf("anchor value = %d, want 2", anchor.value)
	}

	// Restore every mutable authority view and the disk-backed root ledger to T1.
	// The monotonic anchor deliberately remains at T2.
	mutable.issue = t1Issue
	mutable.coordination = t1
	mutable.witness = t1
	if err := os.WriteFile(path, t1Ledger, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authority.Current(context.Background(), scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("coordinated rollback error = %v, want %v", err, ErrCapabilityRootRollback)
	}
	if _, err := authority.Issue(context.Background(), scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("coordinated rollback reissue error = %v, want %v", err, ErrCapabilityRootRollback)
	}
}
