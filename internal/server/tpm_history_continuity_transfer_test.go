//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

type sequenceGateHeadStore struct {
	mu             sync.Mutex
	store          journal.ExternalHeadStore
	failAtSequence uint64
}

func (s *sequenceGateHeadStore) Load(
	ctx context.Context,
	journalID string,
) (journal.ExternalHead, error) {
	return s.store.Load(ctx, journalID)
}

func (s *sequenceGateHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous,
	next journal.ExternalHead,
) (journal.ExternalHead, error) {
	s.mu.Lock()
	fail := s.failAtSequence != 0 && next.Sequence == s.failAtSequence
	s.mu.Unlock()
	if fail {
		return journal.ExternalHead{}, errors.New("synthetic ownership witness write interruption")
	}
	return s.store.CompareAndAdvance(ctx, previous, next)
}

func (s *sequenceGateHeadStore) setFailure(sequence uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAtSequence = sequence
}

func TestAuthorizedTPMHistoryContinuityTransferPreservesHeadAndRetiresSource(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 3, 30, 0, 0, time.UTC)

	historyQuorum := newHistoryTransferQuorum(t,
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
	)
	historyWitness, err := NewExternalHeadTaintRecoveryHistoryAnchor(
		historyQuorum,
		"taint-recovery/main",
	)
	if err != nil {
		t.Fatal(err)
	}

	ownershipQuorum := newHistoryTransferQuorum(t,
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
	)
	ownership, err := NewTaintRecoveryHistoryOwnershipWitness(
		ownershipQuorum,
		"taint-recovery/main/active-device",
	)
	if err != nil {
		t.Fatal(err)
	}

	simA, err := simulator.GetWithFixedSeedInsecure(701)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-a.json"),
		IndexAuth:     []byte("history-transfer-a"),
		HeadIndexAuth: []byte("history-transfer-head-a"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceA, cfgA); err != nil {
		t.Fatal(err)
	}
	localA, err := NewTPMNVHistoryAnchor(deviceA, cfgA)
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentity, err := localA.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownership.Initialize(ctx, sourceIdentity); err != nil {
		t.Fatal(err)
	}
	ownedA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localA, historyWitness, ownership)
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
		Anchor: ownedA,
	}

	h1 := tpmHistoryAnchorReceipt("transfer-h1", "", 1, now)
	signedH1, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h1Digest, err := storeA.Append(ctx, signedH1, publicKey)
	if err != nil {
		t.Fatalf("append H1 under TPM-A: %v", err)
	}

	h2 := tpmHistoryAnchorReceipt("transfer-h2", h1Digest, 2, now.Add(time.Minute))
	signedH2, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h2, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h2Digest, err := storeA.Append(ctx, signedH2, publicKey)
	if err != nil {
		t.Fatalf("append H2 under TPM-A: %v", err)
	}

	sourceState, ok, err := readTPMNVHistoryAnchorState(cfgA.StatePath)
	if err != nil || !ok {
		t.Fatalf("read source history anchor state: ok=%t err=%v", ok, err)
	}
	if sourceState.Sequence != 2 || sourceState.HeadDigest != h2Digest {
		t.Fatalf("unexpected source history state: %+v", sourceState)
	}
	if err := simA.Close(); err != nil {
		t.Fatalf("close TPM-A before replacement: %v", err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(702)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)
	cfgB := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-b.json"),
		IndexAuth:     []byte("history-transfer-b"),
		HeadIndexAuth: []byte("history-transfer-head-b"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	localB, err := NewTPMNVHistoryAnchor(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	destinationState, ok, err := readTPMNVHistoryAnchorState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read destination history anchor state: ok=%t err=%v", ok, err)
	}
	destinationIdentity, err := localB.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destinationBoot, err := localB.MeasuredBootIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}

	transferPub, transferPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := TPMHistoryContinuityTransferAuthorization{
		Version:                    TPMHistoryContinuityTransferAuthorizationVersion,
		TransferID:                 "history-a-to-b-1",
		HistoryWitnessID:           "taint-recovery/main",
		OwnershipWitnessID:         "taint-recovery/main/active-device",
		SourceDeviceIdentity:       sourceState.DeviceIdentity,
		SourceMeasuredBootIdentity: sourceState.MeasuredBootIdentity,
		SourceStateDigest:          sourceState.Digest,
		SourceGeneration:           sourceState.Generation,
		SourceSequence:             sourceState.Sequence,
		SourceHeadDigest:           sourceState.HeadDigest,
		SourceOwnershipEpoch:       0,
		DestinationDeviceIdentity:       destinationIdentity,
		DestinationMeasuredBootIdentity: destinationBoot,
		DestinationStateDigest:          destinationState.Digest,
		DestinationGeneration:           destinationState.Generation,
		DestinationNVIndex:              uint32(cfgB.NVIndex),
		DestinationHeadNVIndex:          uint32(cfgB.HeadNVIndex),
		NotBefore:                  now.Add(-time.Minute),
		ExpiresAt:                  now.Add(5 * time.Minute),
	}
	signedTransfer, err := SignTPMHistoryContinuityTransferAuthorization(auth, transferPriv)
	if err != nil {
		t.Fatal(err)
	}

	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitness,
		ownership,
		signedTransfer,
		transferPub,
		now,
	); err != nil {
		t.Fatalf("authorized continuity transfer failed: %v", err)
	}

	commitment, err := TPMHistoryContinuityTransferAuthorizationDigest(signedTransfer)
	if err != nil {
		t.Fatal(err)
	}
	ownerState, err := ownership.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ownerState.Epoch != 2 ||
		ownerState.ActiveDeviceIdentity != destinationIdentity ||
		ownerState.AuthorizationDigest != commitment {
		t.Fatalf("unexpected final ownership witness: %+v", ownerState)
	}

	ownedB, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localB, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}
	currentB, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatalf("destination did not inherit exact history head: %v", err)
	}
	if currentB.Sequence != 2 || currentB.HeadDigest != h2Digest {
		t.Fatalf("destination continuity mismatch: %+v", currentB)
	}

	staleSource := &staticDeviceHistoryAnchor{
		identity: sourceState.DeviceIdentity,
		state: kernelfabric.TaintRecoveryHistoryAnchorState{
			Sequence:   2,
			HeadDigest: h2Digest,
		},
	}
	retiredA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(staleSource, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retiredA.Current(ctx); !errors.Is(err, ErrTaintRecoveryHistoryOwnershipMismatch) {
		t.Fatalf("source identity remained active after ownership transfer: %v", err)
	}

	h3 := tpmHistoryAnchorReceipt("transfer-h3", h2Digest, 3, now.Add(2*time.Minute))
	signedH3, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h3, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	retiredStoreA := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: retiredA,
	}
	if _, err := retiredStoreA.Append(ctx, signedH3, publicKey); !errors.Is(err, ErrTaintRecoveryHistoryOwnershipMismatch) {
		t.Fatalf("retired source identity appended a new history receipt: %v", err)
	}

	storeB := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: ownedB,
	}
	h3Digest, err := storeB.Append(ctx, signedH3, publicKey)
	if err != nil {
		t.Fatalf("destination could not continue history: %v", err)
	}
	currentB, err = ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if currentB.Sequence != 3 || currentB.HeadDigest != h3Digest {
		t.Fatalf("destination did not continue from transferred head: %+v", currentB)
	}

	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitness,
		ownership,
		signedTransfer,
		transferPub,
		now,
	); !errors.Is(err, ErrTPMHistoryContinuityReplay) {
		t.Fatalf("completed transfer replay was not rejected: %v", err)
	}
}

func TestTPMHistoryContinuityTransferResumesAfterQuiescedWitnessInterruption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)

	historyQuorum := newHistoryTransferQuorum(t,
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
	)
	historyWitness, err := NewExternalHeadTaintRecoveryHistoryAnchor(historyQuorum, "taint-recovery/resume")
	if err != nil {
		t.Fatal(err)
	}

	g1 := &sequenceGateHeadStore{store: journal.NewMemoryHeadStore()}
	g2 := &sequenceGateHeadStore{store: journal.NewMemoryHeadStore()}
	g3 := &sequenceGateHeadStore{store: journal.NewMemoryHeadStore()}
	ownershipQuorum := newHistoryTransferQuorum(t, g1, g2, g3)
	ownership, err := NewTaintRecoveryHistoryOwnershipWitness(
		ownershipQuorum,
		"taint-recovery/resume/active-device",
	)
	if err != nil {
		t.Fatal(err)
	}

	simA, err := simulator.GetWithFixedSeedInsecure(711)
	if err != nil {
		t.Fatal(err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "resume-a.json"),
		IndexAuth:     []byte("history-resume-a"),
		HeadIndexAuth: []byte("history-resume-head-a"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceA, cfgA); err != nil {
		t.Fatal(err)
	}
	localA, err := NewTPMNVHistoryAnchor(deviceA, cfgA)
	if err != nil {
		t.Fatal(err)
	}
	identityA, err := localA.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownership.Initialize(ctx, identityA); err != nil {
		t.Fatal(err)
	}
	ownedA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localA, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}

	receiptPub, receiptPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawStore := kernelfabric.TaintRecoveryHistoryStore{Dir: filepath.Join(dir, "resume-history")}
	storeA := kernelfabric.AnchoredTaintRecoveryHistoryStore{Store: rawStore, Anchor: ownedA}
	h1 := tpmHistoryAnchorReceipt("resume-h1", "", 1, now)
	signedH1, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h1, receiptPriv)
	if err != nil {
		t.Fatal(err)
	}
	h1Digest, err := storeA.Append(ctx, signedH1, receiptPub)
	if err != nil {
		t.Fatal(err)
	}
	sourceState, ok, err := readTPMNVHistoryAnchorState(cfgA.StatePath)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if err := simA.Close(); err != nil {
		t.Fatalf("close TPM-A before replacement: %v", err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(712)
	if err != nil {
		t.Fatal(err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)
	cfgB := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "resume-b.json"),
		IndexAuth:     []byte("history-resume-b"),
		HeadIndexAuth: []byte("history-resume-head-b"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	localB, err := NewTPMNVHistoryAnchor(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	destState, ok, err := readTPMNVHistoryAnchorState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatal(err)
	}
	destIdentity, err := localB.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destBoot, err := localB.MeasuredBootIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}

	transferPub, transferPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := TPMHistoryContinuityTransferAuthorization{
		Version:                    TPMHistoryContinuityTransferAuthorizationVersion,
		TransferID:                 "history-resume-a-to-b",
		HistoryWitnessID:           "taint-recovery/resume",
		OwnershipWitnessID:         "taint-recovery/resume/active-device",
		SourceDeviceIdentity:       sourceState.DeviceIdentity,
		SourceMeasuredBootIdentity: sourceState.MeasuredBootIdentity,
		SourceStateDigest:          sourceState.Digest,
		SourceGeneration:           sourceState.Generation,
		SourceSequence:             sourceState.Sequence,
		SourceHeadDigest:           h1Digest,
		SourceOwnershipEpoch:       0,
		DestinationDeviceIdentity:       destIdentity,
		DestinationMeasuredBootIdentity: destBoot,
		DestinationStateDigest:          destState.Digest,
		DestinationGeneration:           destState.Generation,
		DestinationNVIndex:              uint32(cfgB.NVIndex),
		DestinationHeadNVIndex:          uint32(cfgB.HeadNVIndex),
		NotBefore:                  now.Add(-time.Minute),
		ExpiresAt:                  now.Add(5 * time.Minute),
	}
	signedTransfer, err := SignTPMHistoryContinuityTransferAuthorization(auth, transferPriv)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := TPMHistoryContinuityTransferAuthorizationDigest(signedTransfer)
	if err != nil {
		t.Fatal(err)
	}

	// Sequence 1 is the quiesced ownership state; sequence 2 is final ownership.
	// Let the quiesce commit, then make a strict majority reject the final step.
	g1.setFailure(2)
	g2.setFailure(2)
	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitness,
		ownership,
		signedTransfer,
		transferPub,
		now,
	); err == nil {
		t.Fatal("ownership finalization interruption unexpectedly succeeded")
	}

	quiesced, err := ownership.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if quiesced.Epoch != 1 ||
		quiesced.ActiveDeviceIdentity != quiescedRecoveryHistoryOwnershipIdentity(commitment) {
		t.Fatalf("ownership did not remain quiesced after interrupted finalization: %+v", quiesced)
	}
	staleSource := &staticDeviceHistoryAnchor{
		identity: sourceState.DeviceIdentity,
		state: kernelfabric.TaintRecoveryHistoryAnchorState{
			Sequence:   1,
			HeadDigest: h1Digest,
		},
	}
	quiescedSource, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(staleSource, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quiescedSource.Current(ctx); !errors.Is(err, ErrTaintRecoveryHistoryOwnershipMismatch) {
		t.Fatalf("source identity remained active while ownership was quiesced: %v", err)
	}
	ownedB, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localB, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownedB.Current(ctx); !errors.Is(err, ErrTaintRecoveryHistoryOwnershipMismatch) {
		t.Fatalf("destination became active before ownership finalization: %v", err)
	}

	g1.setFailure(0)
	g2.setFailure(0)
	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitness,
		ownership,
		signedTransfer,
		transferPub,
		now,
	); err != nil {
		t.Fatalf("retry did not resume quiesced transfer: %v", err)
	}
	currentB, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatalf("destination did not become active after resumed transfer: %v", err)
	}
	if currentB.Sequence != 1 || currentB.HeadDigest != h1Digest {
		t.Fatalf("resumed transfer changed history truth: %+v", currentB)
	}
}

type staticDeviceHistoryAnchor struct {
	identity string
	state    kernelfabric.TaintRecoveryHistoryAnchorState
}

func (a *staticDeviceHistoryAnchor) DeviceIdentity(context.Context) (string, error) {
	return a.identity, nil
}

func (a *staticDeviceHistoryAnchor) Current(
	context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	return a.state, nil
}

func (a *staticDeviceHistoryAnchor) CompareAndAdvance(
	_ context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a.state != expected {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, errors.New("static history anchor compare mismatch")
	}
	a.state = next
	return next, nil
}

func newHistoryTransferQuorum(
	t *testing.T,
	a,
	b,
	c journal.ExternalHeadStore,
) *journal.QuorumHeadStore {
	t.Helper()
	store, err := journal.NewQuorumHeadStore([]journal.QuorumHeadMember{
		{ID: "witness-a", Store: a},
		{ID: "witness-b", Store: b},
		{ID: "witness-c", Store: c},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
