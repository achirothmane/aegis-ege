//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

type switchableHeadStore struct {
	store    journal.ExternalHeadStore
	failLoad bool
}

func (s *switchableHeadStore) Load(
	ctx context.Context,
	journalID string,
) (journal.ExternalHead, error) {
	if s.failLoad {
		return journal.ExternalHead{}, errors.New("synthetic witness unavailable")
	}
	return s.store.Load(ctx, journalID)
}

func (s *switchableHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous,
	next journal.ExternalHead,
) (journal.ExternalHead, error) {
	if s.failLoad {
		return journal.ExternalHead{}, errors.New("synthetic witness unavailable")
	}
	return s.store.CompareAndAdvance(ctx, previous, next)
}

func TestTPMAndQuorumHistoryAnchorRejectsReplacementTPMReset(t *testing.T) {
	ctx := context.Background()

	w1 := &switchableHeadStore{store: journal.NewMemoryHeadStore()}
	w2 := &switchableHeadStore{store: journal.NewMemoryHeadStore()}
	w3 := &switchableHeadStore{store: journal.NewMemoryHeadStore()}
	quorum, err := journal.NewQuorumHeadStore([]journal.QuorumHeadMember{
		{ID: "witness-a", Store: w1},
		{ID: "witness-b", Store: w2},
		{ID: "witness-c", Store: w3},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := NewExternalHeadTaintRecoveryHistoryAnchor(
		quorum,
		"taint-recovery/main",
	)
	if err != nil {
		t.Fatal(err)
	}

	simA, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)

	dir := t.TempDir()
	cfgA := TPMNVHistoryAnchorConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A160),
		StatePath: filepath.Join(dir, "tpm-a-history-anchor.json"),
		IndexAuth: []byte("history-quorum-a"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceA, cfgA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		undefineTPMHistoryAnchorNV(t, deviceA, cfgA)
		_ = simA.Close()
	})
	localA, err := NewTPMNVHistoryAnchor(deviceA, cfgA)
	if err != nil {
		t.Fatal(err)
	}
	anchorA, err := NewConjunctiveTaintRecoveryHistoryAnchor(localA, witness)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawStore := kernelfabric.TaintRecoveryHistoryStore{
		Dir: filepath.Join(dir, "recovery-history"),
	}
	storeA := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: anchorA,
	}

	base := time.Date(2026, 10, 3, 2, 30, 0, 0, time.UTC)
	h1 := tpmHistoryAnchorReceipt("quorum-h1", "", 1, base)
	signedH1, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h1Digest, err := storeA.Append(ctx, signedH1, publicKey)
	if err != nil {
		t.Fatalf("append H1: %v", err)
	}

	h2 := tpmHistoryAnchorReceipt(
		"quorum-h2",
		h1Digest,
		2,
		base.Add(time.Minute),
	)
	signedH2, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h2, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h2Digest, err := storeA.Append(ctx, signedH2, publicKey)
	if err != nil {
		t.Fatalf("append H2: %v", err)
	}

	committed, err := anchorA.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Sequence != 2 || committed.HeadDigest != h2Digest {
		t.Fatalf("unexpected committed anchor state: %+v", committed)
	}

	waitForWitnessReplication(t, ctx, "taint-recovery/main", h2Digest, w1, w2, w3)

	// After all three replicas have converged, any one witness can disappear
	// without erasing the 2-of-3 quorum truth.
	w1.failLoad = true
	quorumState, err := witness.Current(ctx)
	if err != nil {
		t.Fatalf("2-of-3 witness quorum did not survive one unavailable member: %v", err)
	}
	if quorumState != committed {
		t.Fatalf("quorum changed after one witness outage: got=%+v want=%+v", quorumState, committed)
	}

	// Replace/reinitialize the local TPM root. The new local anchor legitimately
	// starts at sequence zero, but the independent witness quorum still commits
	// to H2. The pair must not accept the reset as a fresh history.
	simB, err := simulator.Get()
	if err != nil {
		t.Skipf("replacement TPM simulator unavailable: %v", err)
	}
	deviceB := transport.FromReadWriter(simB)
	cfgB := TPMNVHistoryAnchorConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath: filepath.Join(dir, "tpm-b-history-anchor.json"),
		IndexAuth: []byte("history-quorum-b"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		undefineTPMHistoryAnchorNV(t, deviceB, cfgB)
		_ = simB.Close()
	})
	localB, err := NewTPMNVHistoryAnchor(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	replacementAnchor, err := NewConjunctiveTaintRecoveryHistoryAnchor(localB, witness)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := replacementAnchor.Current(ctx); !errors.Is(err, ErrTaintRecoveryHistoryWitnessMismatch) {
		t.Fatalf("replacement TPM reset was not rejected by independent witness quorum: %v", err)
	}

	storeB := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: replacementAnchor,
	}
	if _, _, _, err := storeB.Current(ctx, publicKey); !errors.Is(err, ErrTaintRecoveryHistoryWitnessMismatch) {
		t.Fatalf("history remained readable after unapproved TPM replacement: %v", err)
	}
}

func waitForWitnessReplication(
	t *testing.T,
	ctx context.Context,
	historyID string,
	headDigest string,
	stores ...*switchableHeadStore,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		all := true
		for _, store := range stores {
			head, err := store.store.Load(ctx, historyID)
			if err != nil ||
				head.Sequence != 2 ||
				head.HeadHash != headDigest ||
				head.KeyID != taintRecoveryHistoryExternalHeadKeyID {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			for i, store := range stores {
				head, err := store.store.Load(ctx, historyID)
				t.Logf("witness[%d] head=%+v err=%v", i, head, err)
			}
			t.Fatal("external witness replicas did not converge before outage proof")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConjunctiveHistoryAnchorFailsClosedAfterOneSidedWitnessCommit(t *testing.T) {
	expected := kernelfabric.TaintRecoveryHistoryAnchorState{}
	next := kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   1,
		HeadDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	local := &failingRecoveryHistoryAnchor{
		state:       expected,
		failAdvance: true,
	}
	witness := &failingRecoveryHistoryAnchor{state: expected}
	anchor, err := NewConjunctiveTaintRecoveryHistoryAnchor(local, witness)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := anchor.CompareAndAdvance(context.Background(), expected, next); !errors.Is(
		err,
		ErrTaintRecoveryHistoryWitnessMismatch,
	) {
		t.Fatalf("one-sided witness commit did not fail closed: %v", err)
	}
	if witness.state != next {
		t.Fatalf("witness did not commit next state: %+v", witness.state)
	}
	if local.state != expected {
		t.Fatalf("local anchor unexpectedly advanced: %+v", local.state)
	}
	if _, err := anchor.Current(context.Background()); !errors.Is(
		err,
		ErrTaintRecoveryHistoryWitnessMismatch,
	) {
		t.Fatalf("divergent anchors were accepted after partial commit: %v", err)
	}
}

type failingRecoveryHistoryAnchor struct {
	state       kernelfabric.TaintRecoveryHistoryAnchorState
	failAdvance bool
}

func (a *failingRecoveryHistoryAnchor) Current(
	context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	return a.state, nil
}

func (a *failingRecoveryHistoryAnchor) CompareAndAdvance(
	_ context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a.state != expected {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("synthetic compare mismatch")
	}
	if a.failAdvance {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("synthetic local anchor interruption")
	}
	a.state = next
	return next, nil
}
