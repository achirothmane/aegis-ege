package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

const historySuccessionPurposeForTest = "operation-history"

type historySuccessionFixture struct {
	plan       HistorySuccessionPlan
	oldStore   *QuorumHeadStore
	newStore   *QuorumHeadStore
	oldBinding GenesisHistoryBinding
	newBinding GenesisHistoryBinding
	head       ExternalHead
}

func historySuccessionEnvelopeForTest(
	t *testing.T,
	journalID string,
	includeAuditHistory bool,
) ([]byte, GenesisQuorumBinding, GenesisHistoryBinding) {
	t.Helper()
	histories := []GovernedHistoryIdentity{{
		Purpose:   historySuccessionPurposeForTest,
		JournalID: journalID,
	}}
	if includeAuditHistory {
		histories = append(histories, GovernedHistoryIdentity{
			Purpose:   "audit-history",
			JournalID: "audit-history/main",
		})
	}
	envelope := struct {
		Version               string                     `json:"version"`
		ExternalWitnessQuorum QuorumTrustPolicy          `json:"external_witness_quorum"`
		GovernedHistories     GovernedHistoryTrustPolicy `json:"governed_histories"`
	}{
		Version: "aegis-ege/capability-envelope/v1",
		ExternalWitnessQuorum: QuorumTrustPolicy{
			Protocol:  QuorumTrustPolicyVersion,
			Threshold: 2,
			Members: []QuorumTrustPolicyMember{
				{ID: "witness-a", TrustManifestHash: quorumTrustHashForTest("witness-a")},
				{ID: "witness-b", TrustManifestHash: quorumTrustHashForTest("witness-b")},
				{ID: "witness-c", TrustManifestHash: quorumTrustHashForTest("witness-c")},
			},
		},
		GovernedHistories: GovernedHistoryTrustPolicy{
			Protocol:  GovernedHistoryTrustPolicyVersion,
			Histories: histories,
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256Digest(raw)
	quorumBinding, err := ParseGenesisQuorumBinding(raw, hash)
	if err != nil {
		t.Fatal(err)
	}
	historyBinding, err := ParseGenesisHistoryBinding(
		raw,
		hash,
		historySuccessionPurposeForTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return raw, quorumBinding, historyBinding
}

func newHistorySuccessionFixture(t *testing.T) historySuccessionFixture {
	t.Helper()
	const journalID = "governed-history/main"

	_, oldQuorumBinding, oldHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		journalID,
		false,
	)
	_, newQuorumBinding, newHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		journalID,
		true,
	)
	oldManifest := sha256Digest([]byte("history-genesis-71"))
	newManifest := sha256Digest([]byte("history-genesis-72"))

	oldQuorumEpoch, err := NewGovernedQuorumEpoch(
		oldQuorumBinding,
		71,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newQuorumEpoch, err := NewGovernedQuorumEpoch(
		newQuorumBinding,
		72,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if oldQuorumBinding.policyHash != newQuorumBinding.policyHash {
		t.Fatal("control: witness policy unexpectedly changed")
	}
	if oldQuorumBinding.capabilityEnvelopeHash ==
		newQuorumBinding.capabilityEnvelopeHash {
		t.Fatal("control: Genesis capability envelope did not change")
	}
	quorumPlan, err := NewQuorumRotationPlan(oldQuorumEpoch, newQuorumEpoch)
	if err != nil {
		t.Fatal(err)
	}

	head := ExternalHead{
		JournalID: journalID,
		Sequence:  9,
		HeadHash:  sha256Digest([]byte("governed-history-head-9")),
		KeyID:     "history-head-key",
	}
	oldPolicy := oldQuorumEpoch.activePolicy()
	stores := map[string]*rotationPolicyTestStore{}
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		stores[id] = newRotationPolicyTestStore(
			head,
			quorumTrustHashForTest(id),
			oldPolicy,
		)
	}

	oldStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-a", Store: stores["witness-a"]},
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
		},
		oldQuorumBinding,
		71,
	)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-a", Store: stores["witness-a"]},
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
		},
		newQuorumBinding,
		72,
	)
	if err != nil {
		t.Fatal(err)
	}

	oldHistoryEpoch, err := NewGovernedHistoryEpoch(
		oldHistoryBinding,
		71,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newHistoryEpoch, err := NewGovernedHistoryEpoch(
		newHistoryBinding,
		72,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewHistorySuccessionPlan(
		oldHistoryEpoch,
		newHistoryEpoch,
		quorumPlan,
	)
	if err != nil {
		t.Fatal(err)
	}
	return historySuccessionFixture{
		plan:       plan,
		oldStore:   oldStore,
		newStore:   newStore,
		oldBinding: oldHistoryBinding,
		newBinding: newHistoryBinding,
		head:       head,
	}
}

func TestGovernedHistorySuccessionPreservesExactLineageAcrossGenesis(t *testing.T) {
	fixture := newHistorySuccessionFixture(t)
	ctx := context.Background()

	oldHistory, err := NewGenesisBoundHistoryStore(
		fixture.oldStore,
		fixture.oldBinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := oldHistory.Load(ctx, fixture.head.JournalID); err != nil ||
		!sameSemanticHead(got, fixture.head) {
		t.Fatalf("predecessor history is not authoritative: head=%+v err=%v", got, err)
	}

	newHistory, err := NewGenesisBoundHistoryStore(
		fixture.newStore,
		fixture.newBinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newHistory.Load(ctx, fixture.head.JournalID); !errors.Is(
		err,
		ErrExternalHeadQuorum,
	) {
		t.Fatalf("successor became authoritative before succession: %v", err)
	}

	result, err := ExecuteGovernedHistorySuccession(
		ctx,
		fixture.plan,
		fixture.oldStore,
		fixture.newStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(result.Head, fixture.head) {
		t.Fatalf("succession changed exact history truth: %+v", result.Head)
	}
	if !validSHA256Digest(result.TransitionHash) ||
		!validSHA256Digest(result.QuorumTransitionHash) {
		t.Fatalf(
			"succession omitted transition commitments: history=%q quorum=%q",
			result.TransitionHash,
			result.QuorumTransitionHash,
		)
	}
	if _, err := fixture.oldStore.Load(
		ctx,
		fixture.head.JournalID,
	); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("predecessor Genesis remained authoritative: %v", err)
	}
	got, err := newHistory.Load(ctx, fixture.head.JournalID)
	if err != nil || !sameSemanticHead(got, fixture.head) {
		t.Fatalf("successor did not inherit exact head: head=%+v err=%v", got, err)
	}

	next := fixture.head
	next.Sequence++
	next.HeadHash = sha256Digest([]byte("governed-history-head-10"))
	if _, err := newHistory.CompareAndAdvance(ctx, got, next); err != nil {
		t.Fatalf("successor could not continue inherited lineage: %v", err)
	}
}

func TestHistorySuccessionRejectsGenesisLineageReset(t *testing.T) {
	const oldJournalID = "governed-history/main"
	_, oldQuorumBinding, oldHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		oldJournalID,
		false,
	)
	_, newQuorumBinding, newHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		"replacement-history/main",
		false,
	)
	oldManifest := sha256Digest([]byte("reset-genesis-81"))
	newManifest := sha256Digest([]byte("reset-genesis-82"))

	oldQuorumEpoch, err := NewGovernedQuorumEpoch(
		oldQuorumBinding,
		81,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newQuorumEpoch, err := NewGovernedQuorumEpoch(
		newQuorumBinding,
		82,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	quorumPlan, err := NewQuorumRotationPlan(oldQuorumEpoch, newQuorumEpoch)
	if err != nil {
		t.Fatal(err)
	}
	oldHistoryEpoch, err := NewGovernedHistoryEpoch(
		oldHistoryBinding,
		81,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newHistoryEpoch, err := NewGovernedHistoryEpoch(
		newHistoryBinding,
		82,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewHistorySuccessionPlan(
		oldHistoryEpoch,
		newHistoryEpoch,
		quorumPlan,
	); !errors.Is(err, ErrHistorySuccessionUnsafe) {
		t.Fatalf("new Genesis silently reset lineage identity: %v", err)
	}
}

func TestHistorySuccessionRejectsQuorumFromDifferentGenesisEnvelope(t *testing.T) {
	const journalID = "governed-history/main"
	_, oldQuorumBinding, oldHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		journalID,
		false,
	)
	_, newQuorumBinding, newHistoryBinding := historySuccessionEnvelopeForTest(
		t,
		journalID,
		true,
	)
	rogueRaw := quorumCapabilityEnvelopeForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	rogueHistoryPolicy := GovernedHistoryTrustPolicy{
		Protocol: GovernedHistoryTrustPolicyVersion,
		Histories: []GovernedHistoryIdentity{{
			Purpose:   historySuccessionPurposeForTest,
			JournalID: journalID,
		}},
	}
	var rogue map[string]any
	if err := json.Unmarshal(rogueRaw, &rogue); err != nil {
		t.Fatal(err)
	}
	rogue["governed_histories"] = rogueHistoryPolicy
	rogueRaw, err := json.Marshal(rogue)
	if err != nil {
		t.Fatal(err)
	}
	rogueHistoryBinding, err := ParseGenesisHistoryBinding(
		rogueRaw,
		sha256Digest(rogueRaw),
		historySuccessionPurposeForTest,
	)
	if err != nil {
		t.Fatal(err)
	}

	oldManifest := sha256Digest([]byte("cobind-genesis-91"))
	newManifest := sha256Digest([]byte("cobind-genesis-92"))
	oldQuorumEpoch, err := NewGovernedQuorumEpoch(
		oldQuorumBinding,
		91,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newQuorumEpoch, err := NewGovernedQuorumEpoch(
		newQuorumBinding,
		92,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	quorumPlan, err := NewQuorumRotationPlan(oldQuorumEpoch, newQuorumEpoch)
	if err != nil {
		t.Fatal(err)
	}
	oldHistoryEpoch, err := NewGovernedHistoryEpoch(
		rogueHistoryBinding,
		91,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newHistoryEpoch, err := NewGovernedHistoryEpoch(
		newHistoryBinding,
		92,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewHistorySuccessionPlan(
		oldHistoryEpoch,
		newHistoryEpoch,
		quorumPlan,
	); !errors.Is(err, ErrHistorySuccessionUnsafe) {
		t.Fatalf("history binding crossed Genesis envelope boundary: %v", err)
	}

	_ = oldHistoryBinding
}

func TestQuorumEpochRolloverRequiresJointFenceEvenWhenPolicyIsUnchanged(t *testing.T) {
	fixture := newHistorySuccessionFixture(t)
	oldPolicy := fixture.plan.quorumPlan.oldEpoch.activePolicy()
	newPolicy := fixture.plan.quorumPlan.newEpoch.activePolicy()
	if oldPolicy.PolicyHash != newPolicy.PolicyHash {
		t.Fatal("control: quorum policy hash changed")
	}
	if oldPolicy.GenesisEpoch == newPolicy.GenesisEpoch {
		t.Fatal("control: Genesis epoch did not advance")
	}
	if err := ValidateQuorumPolicyTransition(oldPolicy, newPolicy); err == nil {
		t.Fatal("direct ACTIVE epoch rollover bypassed JOINT_FROZEN")
	}
	joint, _, err := fixture.plan.quorumPlan.jointPolicy(
		fixture.head.JournalID,
		fixture.head,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuorumPolicyTransition(oldPolicy, joint); err != nil {
		t.Fatalf("same-policy Genesis freeze rejected: %v", err)
	}
	if err := ValidateQuorumPolicyTransition(joint, newPolicy); err != nil {
		t.Fatalf("same-policy Genesis activation rejected: %v", err)
	}
}
