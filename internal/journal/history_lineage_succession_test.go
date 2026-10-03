package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type lineagePolicyTestStore struct {
	base              *MemoryHeadStore
	trustManifestHash string
	policy            QuorumPolicyState
}

func (s *lineagePolicyTestStore) QuorumTrustManifestHash() string {
	return s.trustManifestHash
}

func (s *lineagePolicyTestStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	return s.base.Load(ctx, journalID)
}

func (s *lineagePolicyTestStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *lineagePolicyTestStore) LoadForQuorum(
	ctx context.Context,
	journalID string,
	policy QuorumPolicyState,
) (ExternalHead, error) {
	if policy != s.policy {
		return ExternalHead{}, ErrQuorumPolicyMismatch
	}
	return s.base.Load(ctx, journalID)
}

func (s *lineagePolicyTestStore) CompareAndAdvanceForQuorum(
	ctx context.Context,
	policy QuorumPolicyState,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if policy != s.policy {
		return ExternalHead{}, ErrQuorumPolicyMismatch
	}
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *lineagePolicyTestStore) CurrentQuorumPolicy(
	context.Context,
) (QuorumPolicyState, error) {
	return s.policy, nil
}

func (s *lineagePolicyTestStore) ObserveQuorumRotationHead(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	return s.base.Load(ctx, journalID)
}

func (s *lineagePolicyTestStore) CompareAndTransitionQuorumPolicy(
	context.Context,
	QuorumPolicyState,
	QuorumPolicyState,
	string,
	ExternalHead,
) error {
	return errors.New("lineage succession fixture does not rotate policies")
}

func lineageEnvelopeForTest(
	t *testing.T,
	journalID string,
	predecessor *GovernedHistoryPredecessor,
) []byte {
	t.Helper()
	policy := QuorumTrustPolicy{
		Protocol:  QuorumTrustPolicyVersion,
		Threshold: 2,
		Members: []QuorumTrustPolicyMember{
			{ID: "witness-a", TrustManifestHash: quorumTrustHashForTest("witness-a")},
			{ID: "witness-b", TrustManifestHash: quorumTrustHashForTest("witness-b")},
			{ID: "witness-c", TrustManifestHash: quorumTrustHashForTest("witness-c")},
		},
	}
	history := GovernedHistoryTrustPolicy{
		Protocol: GovernedHistoryTrustPolicyVersion,
		Histories: []GovernedHistoryIdentity{{
			Purpose:     governedHistoryPurposeForTest,
			JournalID:   journalID,
			Predecessor: predecessor,
		}},
	}
	raw, err := json.Marshal(map[string]any{
		"version":                 "aegis-ege/capability-envelope/v1",
		"external_witness_quorum": policy,
		"governed_histories":      history,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func governedHistoryEpochForTest(
	t *testing.T,
	raw []byte,
	epoch uint64,
	manifestHash string,
) GovernedHistoryEpoch {
	t.Helper()
	binding, err := ParseGenesisHistoryBinding(
		raw,
		sha256Digest(raw),
		governedHistoryPurposeForTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewGovernedHistoryEpoch(binding, epoch, manifestHash)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func lineageTargetStoreForTest(
	t *testing.T,
	raw []byte,
	epoch uint64,
	predecessorHead ExternalHead,
) *QuorumHeadStore {
	t.Helper()
	binding, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := binding.ActivePolicy(epoch)
	if err != nil {
		t.Fatal(err)
	}

	members := make([]QuorumHeadMember, 0, 3)
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		base := NewMemoryHeadStore()
		zero := ExternalHead{
			JournalID: predecessorHead.JournalID,
			Sequence:  0,
			KeyID:     predecessorHead.KeyID,
		}
		current, err := base.CompareAndAdvance(
			context.Background(),
			ExternalHead{},
			zero,
		)
		if err != nil {
			t.Fatal(err)
		}
		if predecessorHead.Sequence != 0 || predecessorHead.HeadHash != "" {
			if _, err := base.CompareAndAdvance(
				context.Background(),
				current,
				predecessorHead,
			); err != nil {
				t.Fatal(err)
			}
		}
		members = append(members, QuorumHeadMember{
			ID: id,
			Store: &lineagePolicyTestStore{
				base:              base,
				trustManifestHash: quorumTrustHashForTest(id),
				policy:            policy,
			},
		})
	}
	store, err := NewGovernedQuorumHeadStore(members, binding, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestGovernedHistoryLineageSuccessionCreatesBoundAnchor(t *testing.T) {
	const (
		oldJournal = "operation-history/v1"
		newJournal = "operation-history/v2"
	)
	oldManifest := sha256Digest([]byte("genesis-70"))
	newManifest := sha256Digest([]byte("genesis-71"))
	oldEnvelope := lineageEnvelopeForTest(t, oldJournal, nil)
	oldEpoch := governedHistoryEpochForTest(t, oldEnvelope, 70, oldManifest)

	predecessor := &GovernedHistoryPredecessor{
		GenesisEpoch:           oldEpoch.GenesisEpoch(),
		GenesisManifestHash:    oldEpoch.GenesisManifestHash(),
		HistoryPolicyHash:      oldEpoch.Binding().PolicyHash(),
		CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
		JournalID:              oldJournal,
	}
	newEnvelope := lineageEnvelopeForTest(t, newJournal, predecessor)
	newEpoch := governedHistoryEpochForTest(t, newEnvelope, 71, newManifest)
	plan, err := NewHistoryLineageSuccessionPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}

	predecessorHead := ExternalHead{
		JournalID: oldJournal,
		Sequence:  19,
		HeadHash:  sha256Digest([]byte("old-history-head-19")),
		KeyID:     "history-authority-key",
	}
	store := lineageTargetStoreForTest(t, newEnvelope, 71, predecessorHead)

	result, err := ExecuteHistoryLineageSuccession(
		context.Background(),
		plan,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.PredecessorHead.JournalID != oldJournal ||
		result.PredecessorHead.Sequence != predecessorHead.Sequence ||
		result.PredecessorHead.HeadHash != predecessorHead.HeadHash {
		t.Fatalf("predecessor truth changed during succession: %+v", result.PredecessorHead)
	}
	if result.SuccessorHead.JournalID != newJournal ||
		result.SuccessorHead.Sequence != 0 ||
		result.SuccessorHead.HeadHash != result.TransitionHash ||
		result.SuccessorHead.KeyID != predecessorHead.KeyID {
		t.Fatalf("successor anchor does not bind predecessor authority: %+v", result.SuccessorHead)
	}
	if !validSHA256Digest(result.TransitionHash) {
		t.Fatalf("transition commitment is not sha256: %q", result.TransitionHash)
	}

	bound, err := NewGenesisBoundHistoryStore(store, newEpoch.Binding())
	if err != nil {
		t.Fatal(err)
	}
	current, err := bound.Load(context.Background(), newJournal)
	if err != nil || !sameSemanticHead(current, result.SuccessorHead) {
		t.Fatalf("new Genesis cannot read its succession anchor: head=%+v err=%v", current, err)
	}
	if _, err := bound.Load(
		context.Background(),
		oldJournal,
	); !errors.Is(err, ErrHistoryLineageMismatch) {
		t.Fatalf("new Genesis kept old lineage as governed runtime identity: %v", err)
	}

	replayed, err := ExecuteHistoryLineageSuccession(
		context.Background(),
		plan,
		store,
	)
	if err != nil || replayed.TransitionHash != result.TransitionHash ||
		!sameSemanticHead(replayed.SuccessorHead, result.SuccessorHead) {
		t.Fatalf("idempotent succession replay diverged: result=%+v err=%v", replayed, err)
	}
}

func TestHistoryLineageSuccessionRejectsUnprovenPredecessor(t *testing.T) {
	oldManifest := sha256Digest([]byte("genesis-80"))
	newManifest := sha256Digest([]byte("genesis-81"))
	oldEnvelope := lineageEnvelopeForTest(t, "history/old", nil)
	oldEpoch := governedHistoryEpochForTest(t, oldEnvelope, 80, oldManifest)

	cases := []struct {
		name        string
		predecessor *GovernedHistoryPredecessor
	}{
		{name: "missing"},
		{
			name: "wrong old manifest",
			predecessor: &GovernedHistoryPredecessor{
				GenesisEpoch:           80,
				GenesisManifestHash:    sha256Digest([]byte("different-old-genesis")),
				HistoryPolicyHash:      oldEpoch.Binding().PolicyHash(),
				CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
				JournalID:              "history/old",
			},
		},
		{
			name: "wrong old policy",
			predecessor: &GovernedHistoryPredecessor{
				GenesisEpoch:           80,
				GenesisManifestHash:    oldManifest,
				HistoryPolicyHash:      sha256Digest([]byte("different-history-policy")),
				CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
				JournalID:              "history/old",
			},
		},
		{
			name: "wrong old journal",
			predecessor: &GovernedHistoryPredecessor{
				GenesisEpoch:           80,
				GenesisManifestHash:    oldManifest,
				HistoryPolicyHash:      oldEpoch.Binding().PolicyHash(),
				CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
				JournalID:              "history/not-old",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newEnvelope := lineageEnvelopeForTest(t, "history/new", tc.predecessor)
			newEpoch := governedHistoryEpochForTest(t, newEnvelope, 81, newManifest)
			if _, err := NewHistoryLineageSuccessionPlan(
				oldEpoch,
				newEpoch,
			); !errors.Is(err, ErrHistoryLineageSuccessionUnauthorized) {
				t.Fatalf("unproven predecessor accepted: %v", err)
			}
		})
	}
}

func TestHistoryLineageSuccessionRequiresPredecessorOnNewGenesisQuorum(t *testing.T) {
	oldManifest := sha256Digest([]byte("genesis-90"))
	newManifest := sha256Digest([]byte("genesis-91"))
	oldEnvelope := lineageEnvelopeForTest(t, "history/old", nil)
	oldEpoch := governedHistoryEpochForTest(t, oldEnvelope, 90, oldManifest)
	predecessor := &GovernedHistoryPredecessor{
		GenesisEpoch:           90,
		GenesisManifestHash:    oldManifest,
		HistoryPolicyHash:      oldEpoch.Binding().PolicyHash(),
		CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
		JournalID:              "history/old",
	}
	newEnvelope := lineageEnvelopeForTest(t, "history/new", predecessor)
	newEpoch := governedHistoryEpochForTest(t, newEnvelope, 91, newManifest)
	plan, err := NewHistoryLineageSuccessionPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}

	store := lineageTargetStoreForTest(
		t,
		newEnvelope,
		91,
		ExternalHead{
			JournalID: "history/different",
			Sequence:  3,
			HeadHash:  sha256Digest([]byte("different-head")),
			KeyID:     "history-authority-key",
		},
	)
	if _, err := ExecuteHistoryLineageSuccession(
		context.Background(),
		plan,
		store,
	); !errors.Is(err, ErrHistoryLineageSuccessionContinuity) {
		t.Fatalf("missing predecessor lineage did not fail closed: %v", err)
	}
}

func TestHistoryLineageSuccessionRejectsConflictingSuccessorState(t *testing.T) {
	oldManifest := sha256Digest([]byte("genesis-100"))
	newManifest := sha256Digest([]byte("genesis-101"))
	oldEnvelope := lineageEnvelopeForTest(t, "history/old", nil)
	oldEpoch := governedHistoryEpochForTest(t, oldEnvelope, 100, oldManifest)
	predecessor := &GovernedHistoryPredecessor{
		GenesisEpoch:           100,
		GenesisManifestHash:    oldManifest,
		HistoryPolicyHash:      oldEpoch.Binding().PolicyHash(),
		CapabilityEnvelopeHash: oldEpoch.Binding().CapabilityEnvelopeHash(),
		JournalID:              "history/old",
	}
	newEnvelope := lineageEnvelopeForTest(t, "history/new", predecessor)
	newEpoch := governedHistoryEpochForTest(t, newEnvelope, 101, newManifest)
	plan, err := NewHistoryLineageSuccessionPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}
	predecessorHead := ExternalHead{
		JournalID: "history/old",
		Sequence:  4,
		HeadHash:  sha256Digest([]byte("old-head")),
		KeyID:     "history-authority-key",
	}
	store := lineageTargetStoreForTest(t, newEnvelope, 101, predecessorHead)

	conflict := ExternalHead{
		JournalID: "history/new",
		Sequence:  0,
		HeadHash:  sha256Digest([]byte("unrelated-new-root")),
		KeyID:     predecessorHead.KeyID,
	}
	if _, err := store.CompareAndAdvance(
		context.Background(),
		ExternalHead{},
		conflict,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecuteHistoryLineageSuccession(
		context.Background(),
		plan,
		store,
	); !errors.Is(err, ErrHistoryLineageSuccessionConflict) {
		t.Fatalf("conflicting successor root inherited continuity: %v", err)
	}
}
