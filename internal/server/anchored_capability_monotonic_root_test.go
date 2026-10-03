package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

type testCapabilityRootAnchor struct {
	mu       sync.Mutex
	identity string
	state    CapabilityRootAnchorState
}

func (a *testCapabilityRootAnchor) Identity(context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == "" {
		return "", errors.New("anchor identity is empty")
	}
	return a.identity, nil
}

func (a *testCapabilityRootAnchor) Current(context.Context) (CapabilityRootAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *testCapabilityRootAnchor) Advance(
	_ context.Context,
	expected CapabilityRootAnchorState,
	next CapabilityRootAnchorState,
) (CapabilityRootAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != expected {
		return CapabilityRootAnchorState{}, errors.New("anchor changed concurrently")
	}
	if next.Sequence != expected.Sequence+1 {
		return CapabilityRootAnchorState{}, errors.New("anchor sequence did not advance by one")
	}
	if !isCapabilityRootDigest(next.Commitment) {
		return CapabilityRootAnchorState{}, errors.New("anchor commitment is not a sha256 digest")
	}
	a.state = next
	return a.state, nil
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
	anchor := &testCapabilityRootAnchor{identity: "test-anchor"}
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
	if anchor.state.Sequence != 2 {
		t.Fatalf("anchor sequence = %d, want 2", anchor.state.Sequence)
	}
	if !isCapabilityRootDigest(anchor.state.Commitment) {
		t.Fatalf("anchor commitment = %q, want sha256 digest", anchor.state.Commitment)
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
	if anchor.state.Sequence != 2 {
		t.Fatalf("regression advanced anchor to %d, want 2", anchor.state.Sequence)
	}
}

func TestAnchoredCapabilityRootDetectsDiskRollbackAfterAnchorAdvance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityRootAnchor{identity: "test-anchor"}
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
	if anchor.state.Sequence != 2 {
		t.Fatalf("anchor sequence = %d, want 2", anchor.state.Sequence)
	}

	if err := os.WriteFile(path, t1Ledger, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = root.Current(context.Background(), scope)
	if !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("rolled-back ledger error = %v, want %v", err, ErrCapabilityRootRollback)
	}
}

func TestAnchoredCapabilityRootRejectsSameLengthRewrittenLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityRootAnchor{identity: "test-anchor"}
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
	if _, err := root.Advance(context.Background(), scope, t2); err != nil {
		t.Fatal(err)
	}
	originalCommitment := anchor.state.Commitment

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) != 2 {
		t.Fatalf("ledger lines = %d, want 2", len(lines))
	}
	var records [2]capabilityRootRecord
	for i := range lines {
		if err := json.Unmarshal([]byte(lines[i]), &records[i]); err != nil {
			t.Fatal(err)
		}
	}

	// Keep exactly two records and a locally valid hash chain, but move the
	// second record to another scope. The original scope now appears to have
	// stopped at T1 even though the external anchor still commits to the real T2
	// ledger head.
	otherScope := scope
	otherScope.IntentID = "intent-cap-root-other"
	records[1].ScopeDigest, err = capabilityRootScopeDigest(otherScope)
	if err != nil {
		t.Fatal(err)
	}
	records[1].RecordHash, err = capabilityRootRecordHash(records[1])
	if err != nil {
		t.Fatal(err)
	}
	if records[1].RecordHash == originalCommitment {
		t.Fatal("rewritten ledger unexpectedly preserved external head commitment")
	}

	var rewritten strings.Builder
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		rewritten.Write(line)
		rewritten.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(rewritten.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = root.Current(context.Background(), scope)
	if !errors.Is(err, ErrCapabilityRootAnchorMismatch) {
		t.Fatalf(
			"same-length rewritten ledger error = %v, want %v",
			err,
			ErrCapabilityRootAnchorMismatch,
		)
	}
}

func TestIndependentAuthorityFailsClosedWhenMutableAndLedgerRollbackTogether(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability-root.log")
	anchor := &testCapabilityRootAnchor{identity: "test-anchor"}
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
	if anchor.state.Sequence != 2 {
		t.Fatalf("anchor sequence = %d, want 2", anchor.state.Sequence)
	}

	// Restore every mutable authority view and the local root ledger to T1.
	// The independently protected anchor deliberately remains committed to T2.
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
