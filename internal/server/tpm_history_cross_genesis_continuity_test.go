//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

type crossGenesisPolicyStore struct {
	mu                sync.Mutex
	base              journal.ExternalHeadStore
	trustManifestHash string
	policy            journal.QuorumPolicyState
	failWrite         bool
}

func (s *crossGenesisPolicyStore) QuorumTrustManifestHash() string {
	return s.trustManifestHash
}

func (s *crossGenesisPolicyStore) Load(
	ctx context.Context,
	journalID string,
) (journal.ExternalHead, error) {
	return s.base.Load(ctx, journalID)
}

func (s *crossGenesisPolicyStore) CompareAndAdvance(
	ctx context.Context,
	previous,
	next journal.ExternalHead,
) (journal.ExternalHead, error) {
	if s.failWrite {
		return journal.ExternalHead{}, errors.New("synthetic old-only witness write unavailable")
	}
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *crossGenesisPolicyStore) LoadForQuorum(
	ctx context.Context,
	journalID string,
	policy journal.QuorumPolicyState,
) (journal.ExternalHead, error) {
	s.mu.Lock()
	current := s.policy
	s.mu.Unlock()
	if current != policy || current.Phase != journal.QuorumPolicyPhaseActive {
		return journal.ExternalHead{}, journal.ErrQuorumPolicyMismatch
	}
	return s.base.Load(ctx, journalID)
}

func (s *crossGenesisPolicyStore) CompareAndAdvanceForQuorum(
	ctx context.Context,
	policy journal.QuorumPolicyState,
	previous,
	next journal.ExternalHead,
) (journal.ExternalHead, error) {
	s.mu.Lock()
	current := s.policy
	failWrite := s.failWrite
	s.mu.Unlock()
	if current != policy || current.Phase != journal.QuorumPolicyPhaseActive {
		return journal.ExternalHead{}, journal.ErrQuorumPolicyMismatch
	}
	if failWrite {
		return journal.ExternalHead{}, errors.New("synthetic old-only witness write unavailable")
	}
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *crossGenesisPolicyStore) CurrentQuorumPolicy(
	ctx context.Context,
) (journal.QuorumPolicyState, error) {
	if err := ctx.Err(); err != nil {
		return journal.QuorumPolicyState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy, nil
}

func (s *crossGenesisPolicyStore) ObserveQuorumRotationHead(
	ctx context.Context,
	journalID string,
) (journal.ExternalHead, error) {
	return s.base.Load(ctx, journalID)
}

func (s *crossGenesisPolicyStore) CompareAndTransitionQuorumPolicy(
	ctx context.Context,
	expected,
	next journal.QuorumPolicyState,
	journalID string,
	expectedHead journal.ExternalHead,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy != expected {
		return journal.ErrQuorumPolicyMismatch
	}
	if err := journal.ValidateQuorumPolicyTransition(expected, next); err != nil {
		return err
	}
	actual, err := s.base.Load(ctx, journalID)
	if err != nil {
		return err
	}
	if !sameExternalHeadSemanticsForCrossGenesisTest(actual, expectedHead) {
		return journal.ErrQuorumRotationContinuity
	}
	s.policy = next
	return nil
}

func (s *crossGenesisPolicyStore) setPolicy(policy journal.QuorumPolicyState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
}

func sameExternalHeadSemanticsForCrossGenesisTest(
	left,
	right journal.ExternalHead,
) bool {
	return left.JournalID == right.JournalID &&
		left.Sequence == right.Sequence &&
		left.HeadHash == right.HeadHash &&
		left.KeyID == right.KeyID
}

func crossGenesisDigestForTest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func crossGenesisTrustHashForTest(id string) string {
	switch id {
	case "witness-a":
		return "sha256:" + strings.Repeat("a", 64)
	case "witness-b":
		return "sha256:" + strings.Repeat("b", 64)
	case "witness-c":
		return "sha256:" + strings.Repeat("c", 64)
	case "witness-d":
		return "sha256:" + strings.Repeat("d", 64)
	default:
		return crossGenesisDigestForTest("trust:" + id)
	}
}

func crossGenesisBindingForServerTest(
	t *testing.T,
	ids ...string,
) journal.GenesisQuorumBinding {
	t.Helper()
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	members := make([]journal.QuorumTrustPolicyMember, 0, len(sorted))
	for _, id := range sorted {
		members = append(members, journal.QuorumTrustPolicyMember{
			ID:                id,
			TrustManifestHash: crossGenesisTrustHashForTest(id),
		})
	}
	policy := journal.QuorumTrustPolicy{
		Protocol:  journal.QuorumTrustPolicyVersion,
		Threshold: 2,
		Members:   members,
	}
	envelope := struct {
		Version               string                    `json:"version"`
		ExternalWitnessQuorum journal.QuorumTrustPolicy `json:"external_witness_quorum"`
	}{
		Version:               "aegis-ege/capability-envelope/v1",
		ExternalWitnessQuorum: policy,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	binding, err := journal.ParseGenesisQuorumBinding(
		raw,
		"sha256:"+hex.EncodeToString(sum[:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func newCrossGenesisRotatableQuorum(
	t *testing.T,
	oldGenesisEpoch,
	newGenesisEpoch uint64,
) (
	*journal.QuorumHeadStore,
	*journal.QuorumHeadStore,
	journal.QuorumRotationPlan,
) {
	t.Helper()

	oldBinding := crossGenesisBindingForServerTest(
		t,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	newBinding := crossGenesisBindingForServerTest(
		t,
		"witness-a",
		"witness-b",
		"witness-d",
	)

	a := &crossGenesisPolicyStore{
		base:              journal.NewMemoryHeadStore(),
		trustManifestHash: crossGenesisTrustHashForTest("witness-a"),
	}
	b := &crossGenesisPolicyStore{
		base:              journal.NewMemoryHeadStore(),
		trustManifestHash: crossGenesisTrustHashForTest("witness-b"),
	}
	c := &crossGenesisPolicyStore{
		base:              journal.NewMemoryHeadStore(),
		trustManifestHash: crossGenesisTrustHashForTest("witness-c"),
		failWrite:         true,
	}
	d := &crossGenesisPolicyStore{
		base:              journal.NewMemoryHeadStore(),
		trustManifestHash: crossGenesisTrustHashForTest("witness-d"),
	}

	oldStore, err := journal.NewGovernedQuorumHeadStore(
		[]journal.QuorumHeadMember{
			{ID: "witness-a", Store: a},
			{ID: "witness-b", Store: b},
			{ID: "witness-c", Store: c},
		},
		oldBinding,
		oldGenesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := journal.NewGovernedQuorumHeadStore(
		[]journal.QuorumHeadMember{
			{ID: "witness-a", Store: a},
			{ID: "witness-b", Store: b},
			{ID: "witness-d", Store: d},
		},
		newBinding,
		newGenesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}

	oldPolicy := journal.QuorumPolicyState{
		Phase:        journal.QuorumPolicyPhaseActive,
		GenesisEpoch: oldGenesisEpoch,
		PolicyHash:   oldStore.QuorumPolicyHash(),
	}
	newPolicy := journal.QuorumPolicyState{
		Phase:        journal.QuorumPolicyPhaseActive,
		GenesisEpoch: newGenesisEpoch,
		PolicyHash:   newStore.QuorumPolicyHash(),
	}
	a.setPolicy(oldPolicy)
	b.setPolicy(oldPolicy)
	c.setPolicy(oldPolicy)
	d.setPolicy(newPolicy)

	oldEpoch, err := journal.NewGovernedQuorumEpoch(
		oldBinding,
		oldGenesisEpoch,
		crossGenesisDigestForTest("genesis-old"),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch, err := journal.NewGovernedQuorumEpoch(
		newBinding,
		newGenesisEpoch,
		crossGenesisDigestForTest("genesis-new"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := journal.NewQuorumRotationPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return oldStore, newStore, plan
}

func TestTPMHistoryContinuitySurvivesGenesisQuorumRotationAndHardwareReplacement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 6, 0, 0, 0, time.UTC)

	historyOld, historyNew, historyRotation :=
		newCrossGenesisRotatableQuorum(t, 41, 42)
	ownershipOldStore, ownershipNewStore, ownershipRotation :=
		newCrossGenesisRotatableQuorum(t, 41, 42)

	if historyOld.QuorumPolicyHash() == historyNew.QuorumPolicyHash() {
		t.Fatal("history quorum policy did not change across Genesis epoch")
	}
	if ownershipOldStore.QuorumPolicyHash() == ownershipNewStore.QuorumPolicyHash() {
		t.Fatal("ownership quorum policy did not change across Genesis epoch")
	}

	historyWitnessOld, err := NewExternalHeadTaintRecoveryHistoryAnchor(
		historyOld,
		"taint-recovery/main",
	)
	if err != nil {
		t.Fatal(err)
	}
	ownershipOld, err := NewTaintRecoveryHistoryOwnershipWitness(
		ownershipOldStore,
		"taint-recovery/main/active-device",
	)
	if err != nil {
		t.Fatal(err)
	}

	simA, err := simulator.GetWithFixedSeedInsecure(801)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "cross-genesis-history-a.json"),
		IndexAuth:     []byte("cross-genesis-history-a"),
		HeadIndexAuth: []byte("cross-genesis-history-head-a"),
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
	if _, err := ownershipOld.Initialize(ctx, sourceIdentity); err != nil {
		t.Fatal(err)
	}
	ownedA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(
		localA,
		historyWitnessOld,
		ownershipOld,
	)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawStore := kernelfabric.TaintRecoveryHistoryStore{
		Dir: filepath.Join(dir, "cross-genesis-recovery-history"),
	}
	storeA := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: ownedA,
	}

	h1 := tpmHistoryAnchorReceipt("cross-genesis-h1", "", 1, now)
	signedH1, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h1, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h1Digest, err := storeA.Append(ctx, signedH1, publicKey)
	if err != nil {
		t.Fatalf("append H1 before Genesis rotation: %v", err)
	}
	h2 := tpmHistoryAnchorReceipt(
		"cross-genesis-h2",
		h1Digest,
		2,
		now.Add(time.Minute),
	)
	signedH2, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h2, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	h2Digest, err := storeA.Append(ctx, signedH2, publicKey)
	if err != nil {
		t.Fatalf("append H2 before Genesis rotation: %v", err)
	}

	sourceState, ok, err := readTPMNVHistoryAnchorState(cfgA.StatePath)
	if err != nil || !ok {
		t.Fatalf("read TPM-A history state: ok=%t err=%v", ok, err)
	}
	if sourceState.Sequence != 2 || sourceState.HeadDigest != h2Digest {
		t.Fatalf("TPM-A did not commit H2: %+v", sourceState)
	}

	historyResult, err := journal.ExecuteQuorumRotation(
		ctx,
		historyRotation,
		historyOld,
		historyNew,
		"taint-recovery/main",
	)
	if err != nil {
		t.Fatalf("rotate history quorum across Genesis: %v", err)
	}
	if historyResult.Head.Sequence != 2 || historyResult.Head.HeadHash != h2Digest {
		t.Fatalf("history rotation changed exact H2 truth: %+v", historyResult.Head)
	}
	ownershipResult, err := journal.ExecuteQuorumRotation(
		ctx,
		ownershipRotation,
		ownershipOldStore,
		ownershipNewStore,
		"taint-recovery/main/active-device",
	)
	if err != nil {
		t.Fatalf("rotate ownership quorum across Genesis: %v", err)
	}
	if ownershipResult.Head.Sequence != 0 ||
		ownershipResult.Head.HeadHash != sourceIdentity {
		t.Fatalf("ownership rotation changed active TPM-A truth: %+v", ownershipResult.Head)
	}

	if _, err := historyOld.Load(ctx, "taint-recovery/main"); !errors.Is(err, journal.ErrExternalHeadQuorum) {
		t.Fatalf("retired history quorum remained authoritative after rotation: %v", err)
	}
	if _, err := ownershipOldStore.Load(ctx, "taint-recovery/main/active-device"); !errors.Is(err, journal.ErrExternalHeadQuorum) {
		t.Fatalf("retired ownership quorum remained authoritative after rotation: %v", err)
	}

	historyWitnessNew, err := NewExternalHeadTaintRecoveryHistoryAnchor(
		historyNew,
		"taint-recovery/main",
	)
	if err != nil {
		t.Fatal(err)
	}
	ownershipNew, err := NewTaintRecoveryHistoryOwnershipWitness(
		ownershipNewStore,
		"taint-recovery/main/active-device",
	)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := historyWitnessNew.Current(ctx); err != nil ||
		current.Sequence != 2 || current.HeadDigest != h2Digest {
		t.Fatalf("new Genesis history quorum did not inherit H2: current=%+v err=%v", current, err)
	}
	if current, err := ownershipNew.Current(ctx); err != nil ||
		current.Epoch != 0 || current.ActiveDeviceIdentity != sourceIdentity {
		t.Fatalf("new Genesis ownership quorum did not inherit TPM-A: current=%+v err=%v", current, err)
	}

	if err := simA.Close(); err != nil {
		t.Fatalf("close TPM-A before replacement: %v", err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(802)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)
	cfgB := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "cross-genesis-history-b.json"),
		IndexAuth:     []byte("cross-genesis-history-b"),
		HeadIndexAuth: []byte("cross-genesis-history-head-b"),
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
		t.Fatalf("read TPM-B history state: ok=%t err=%v", ok, err)
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
	attestationPub, attestationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationTrust := migrationAttestationTrustForTest(
		t,
		attestationPub,
		42,
		1,
		"sha256:"+strings.Repeat("f", 64),
	)
	transferID := "cross-genesis-tpm-a-to-b"
	destinationAttestation := signHistoryTransferDestinationAttestationForTest(
		t,
		transferID,
		destinationIdentity,
		destinationBoot,
		destinationState.Generation,
		now,
		attestationPriv,
	)
	destinationAttestationDigest, err := TPMRootMigrationDestinationAttestationDigest(
		destinationAttestation,
	)
	if err != nil {
		t.Fatal(err)
	}

	auth := TPMHistoryContinuityTransferAuthorization{
		Version:                         TPMHistoryContinuityTransferAuthorizationVersion,
		TransferID:                      transferID,
		HistoryWitnessID:                "taint-recovery/main",
		HistoryWitnessPolicyHash:        historyWitnessNew.QuorumPolicyHash(),
		OwnershipWitnessID:              "taint-recovery/main/active-device",
		OwnershipWitnessPolicyHash:      ownershipNew.QuorumPolicyHash(),
		SourceDeviceIdentity:            sourceState.DeviceIdentity,
		SourceMeasuredBootIdentity:      sourceState.MeasuredBootIdentity,
		SourceStateDigest:               sourceState.Digest,
		SourceGeneration:                sourceState.Generation,
		SourceSequence:                  sourceState.Sequence,
		SourceHeadDigest:                sourceState.HeadDigest,
		SourceOwnershipEpoch:            0,
		DestinationDeviceIdentity:       destinationIdentity,
		DestinationMeasuredBootIdentity: destinationBoot,
		DestinationStateDigest:          destinationState.Digest,
		DestinationGeneration:           destinationState.Generation,
		DestinationNVIndex:              uint32(cfgB.NVIndex),
		DestinationHeadNVIndex:               uint32(cfgB.HeadNVIndex),
		DestinationAttestationDigest:         destinationAttestationDigest,
		DestinationAttestationGenesisEpoch:   attestationTrust.genesisEpoch,
		DestinationAttestationTrustRootRef:   attestationTrust.trustRootRef,
		DestinationAttestationTrustRootEpoch: attestationTrust.trustRootEpoch,
		DestinationAttestationPolicyHash:     attestationTrust.attestationPolicyHash,
		NotBefore:                            now.Add(-time.Minute),
		ExpiresAt:                       now.Add(5 * time.Minute),
	}

	destinationCounterBefore, err := localB.helper.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ownershipBefore, err := ownershipNew.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}

	staleEpochAuth := auth
	staleEpochAuth.HistoryWitnessPolicyHash = historyOld.QuorumPolicyHash()
	staleEpochAuth.OwnershipWitnessPolicyHash = ownershipOldStore.QuorumPolicyHash()
	staleEpochSigned, err := SignTPMHistoryContinuityTransferAuthorization(
		staleEpochAuth,
		transferPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitnessNew,
		ownershipNew,
		staleEpochSigned,
		transferPub,
		destinationAttestation,
		attestationTrust,
		now,
	)
	if !errors.Is(err, ErrTPMHistoryContinuityAuthorization) {
		t.Fatalf("pre-rotation quorum policy authorization was not rejected: %v", err)
	}
	destinationCounterAfterRejected, err := localB.helper.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if destinationCounterAfterRejected != destinationCounterBefore {
		t.Fatalf(
			"rejected old-epoch authorization changed TPM-B counter: before=%d after=%d",
			destinationCounterBefore,
			destinationCounterAfterRejected,
		)
	}
	ownershipAfterRejected, err := ownershipNew.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ownershipAfterRejected != ownershipBefore {
		t.Fatalf(
			"rejected old-epoch authorization changed ownership: before=%+v after=%+v",
			ownershipBefore,
			ownershipAfterRejected,
		)
	}

	signedTransfer, err := SignTPMHistoryContinuityTransferAuthorization(
		auth,
		transferPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitnessNew,
		ownershipNew,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
		now,
	); err != nil {
		t.Fatalf("cross-Genesis authorized TPM transfer failed: %v", err)
	}

	ownedB, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(
		localB,
		historyWitnessNew,
		ownershipNew,
	)
	if err != nil {
		t.Fatal(err)
	}
	currentB, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatalf("TPM-B did not inherit H2 after cross-Genesis transfer: %v", err)
	}
	if currentB.Sequence != 2 || currentB.HeadDigest != h2Digest {
		t.Fatalf("TPM-B continuity differs from H2: %+v", currentB)
	}

	staleSource := &staticDeviceHistoryAnchor{
		identity: sourceState.DeviceIdentity,
		state: kernelfabric.TaintRecoveryHistoryAnchorState{
			Sequence:   2,
			HeadDigest: h2Digest,
		},
	}
	retiredA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(
		staleSource,
		historyWitnessNew,
		ownershipNew,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retiredA.Current(ctx); !errors.Is(err, ErrTaintRecoveryHistoryOwnershipMismatch) {
		t.Fatalf("TPM-A regained authority after Genesis rotation and transfer: %v", err)
	}

	h3 := tpmHistoryAnchorReceipt(
		"cross-genesis-h3",
		h2Digest,
		3,
		now.Add(2*time.Minute),
	)
	signedH3, err := kernelfabric.SignTaintRecoveryHistoryReceipt(h3, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	storeB := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: ownedB,
	}
	h3Digest, err := storeB.Append(ctx, signedH3, publicKey)
	if err != nil {
		t.Fatalf("TPM-B could not continue H2 -> H3 under new Genesis quorum: %v", err)
	}
	currentB, err = ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if currentB.Sequence != 3 || currentB.HeadDigest != h3Digest {
		t.Fatalf("new hardware/new Genesis continuity did not reach H3: %+v", currentB)
	}

	if _, err := historyOld.Load(ctx, "taint-recovery/main"); !errors.Is(err, journal.ErrExternalHeadQuorum) {
		t.Fatalf("old history quorum resurrected after H3: %v", err)
	}
	if _, err := ownershipOldStore.Load(ctx, "taint-recovery/main/active-device"); !errors.Is(err, journal.ErrExternalHeadQuorum) {
		t.Fatalf("old ownership quorum resurrected after TPM-B activation: %v", err)
	}
}
