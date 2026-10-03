package journal

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
)

const historyGenesisPurposeForTest = "capability-root-history"

func historyGenesisBindingsForTest(
	t *testing.T,
	purpose string,
	journalID string,
	ids ...string,
) (GenesisQuorumBinding, GenesisHistoryBinding) {
	t.Helper()
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	members := make([]QuorumTrustPolicyMember, 0, len(sorted))
	for _, id := range sorted {
		members = append(members, QuorumTrustPolicyMember{
			ID:                id,
			TrustManifestHash: quorumTrustHashForTest(id),
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
			Members:   members,
		},
		GovernedHistories: GovernedHistoryTrustPolicy{
			Protocol: GovernedHistoryTrustPolicyVersion,
			Histories: []GovernedHistoryIdentity{{
				Purpose:   purpose,
				JournalID: journalID,
			}},
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
	historyBinding, err := ParseGenesisHistoryBinding(raw, hash, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return quorumBinding, historyBinding
}

type historyGenesisRotationFixture struct {
	oldHistory GovernedHistoryEpoch
	newHistory GovernedHistoryEpoch
	quorumPlan QuorumRotationPlan
	oldStore   *QuorumHeadStore
	newStore   *QuorumHeadStore
	stores     map[string]*rotationPolicyTestStore
	head       ExternalHead
}

func newHistoryGenesisRotationFixture(
	t *testing.T,
	oldPurpose string,
	oldJournalID string,
	newPurpose string,
	newJournalID string,
) historyGenesisRotationFixture {
	t.Helper()

	oldQuorumBinding, oldHistoryBinding := historyGenesisBindingsForTest(
		t,
		oldPurpose,
		oldJournalID,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	newQuorumBinding, newHistoryBinding := historyGenesisBindingsForTest(
		t,
		newPurpose,
		newJournalID,
		"witness-b",
		"witness-c",
		"witness-d",
	)
	oldManifest := sha256Digest([]byte("history-genesis-11"))
	newManifest := sha256Digest([]byte("history-genesis-12"))

	oldQuorumEpoch, err := NewGovernedQuorumEpoch(
		oldQuorumBinding,
		11,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newQuorumEpoch, err := NewGovernedQuorumEpoch(
		newQuorumBinding,
		12,
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
		11,
		oldManifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	newHistoryEpoch, err := NewGovernedHistoryEpoch(
		newHistoryBinding,
		12,
		newManifest,
	)
	if err != nil {
		t.Fatal(err)
	}

	head := quorumTestHead(17, "a")
	head.JournalID = oldJournalID
	oldPolicy := oldQuorumEpoch.activePolicy()
	newPolicy := newQuorumEpoch.activePolicy()
	stores := map[string]*rotationPolicyTestStore{
		"witness-a": newRotationPolicyTestStore(
			head,
			quorumTrustHashForTest("witness-a"),
			oldPolicy,
		),
		"witness-b": newRotationPolicyTestStore(
			head,
			quorumTrustHashForTest("witness-b"),
			oldPolicy,
		),
		"witness-c": newRotationPolicyTestStore(
			head,
			quorumTrustHashForTest("witness-c"),
			oldPolicy,
		),
		"witness-d": newRotationPolicyTestStore(
			head,
			quorumTrustHashForTest("witness-d"),
			newPolicy,
		),
	}

	oldStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-a", Store: stores["witness-a"]},
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
		},
		oldQuorumBinding,
		11,
	)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
			{ID: "witness-d", Store: stores["witness-d"]},
		},
		newQuorumBinding,
		12,
	)
	if err != nil {
		t.Fatal(err)
	}

	return historyGenesisRotationFixture{
		oldHistory: oldHistoryEpoch,
		newHistory: newHistoryEpoch,
		quorumPlan: quorumPlan,
		oldStore:   oldStore,
		newStore:   newStore,
		stores:     stores,
		head:       head,
	}
}

func TestGenesisHistoryQuorumRotationPreservesSameLineageAcrossGenesis(t *testing.T) {
	fixture := newHistoryGenesisRotationFixture(
		t,
		historyGenesisPurposeForTest,
		"capability-root",
		historyGenesisPurposeForTest,
		"capability-root",
	)
	ctx := context.Background()

	result, err := ExecuteGenesisHistoryQuorumRotation(
		ctx,
		fixture.oldHistory,
		fixture.newHistory,
		fixture.quorumPlan,
		fixture.oldStore,
		fixture.newStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(result.Head, fixture.head) {
		t.Fatalf("history head changed across Genesis: got=%+v want=%+v", result.Head, fixture.head)
	}
	if !validSHA256Digest(result.QuorumTransitionHash) {
		t.Fatalf("quorum transition hash is not bound: %q", result.QuorumTransitionHash)
	}
	if !validSHA256Digest(result.ContinuityHash) {
		t.Fatalf("history continuity hash is not bound: %q", result.ContinuityHash)
	}
	if _, err := fixture.oldStore.Load(
		ctx,
		fixture.head.JournalID,
	); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("old Genesis quorum remained authoritative: %v", err)
	}
	if got, err := fixture.newStore.Load(ctx, fixture.head.JournalID); err != nil ||
		!sameSemanticHead(got, fixture.head) {
		t.Fatalf("new Genesis did not inherit exact history: head=%+v err=%v", got, err)
	}
}

func TestGenesisHistoryQuorumRotationRejectsLineageSubstitutionBeforeWitnessMutation(t *testing.T) {
	fixture := newHistoryGenesisRotationFixture(
		t,
		historyGenesisPurposeForTest,
		"capability-root",
		historyGenesisPurposeForTest,
		"replacement-history",
	)
	ctx := context.Background()
	beforeB, err := fixture.stores["witness-b"].CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeC, err := fixture.stores["witness-c"].CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ExecuteGenesisHistoryQuorumRotation(
		ctx,
		fixture.oldHistory,
		fixture.newHistory,
		fixture.quorumPlan,
		fixture.oldStore,
		fixture.newStore,
	); !errors.Is(err, ErrHistorySuccessionRequired) {
		t.Fatalf("lineage substitution = %v, want %v", err, ErrHistorySuccessionRequired)
	}

	afterB, err := fixture.stores["witness-b"].CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	afterC, err := fixture.stores["witness-c"].CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if beforeB != afterB || beforeC != afterC {
		t.Fatalf(
			"rejected lineage substitution mutated witness policy: B=%+v->%+v C=%+v->%+v",
			beforeB,
			afterB,
			beforeC,
			afterC,
		)
	}
	if got, err := fixture.oldStore.Load(ctx, fixture.head.JournalID); err != nil ||
		!sameSemanticHead(got, fixture.head) {
		t.Fatalf("rejected succession disturbed predecessor truth: head=%+v err=%v", got, err)
	}
}

func TestGenesisHistoryQuorumRotationRejectsPurposeSubstitution(t *testing.T) {
	fixture := newHistoryGenesisRotationFixture(
		t,
		"effects-history",
		"capability-root",
		"recovery-history",
		"capability-root",
	)

	if _, err := ExecuteGenesisHistoryQuorumRotation(
		context.Background(),
		fixture.oldHistory,
		fixture.newHistory,
		fixture.quorumPlan,
		fixture.oldStore,
		fixture.newStore,
	); !errors.Is(err, ErrHistoryGenesisContinuity) {
		t.Fatalf("purpose substitution = %v, want %v", err, ErrHistoryGenesisContinuity)
	}
}

func TestGenesisHistoryQuorumRotationRejectsDetachedHistoryCustody(t *testing.T) {
	fixture := newHistoryGenesisRotationFixture(
		t,
		historyGenesisPurposeForTest,
		"capability-root",
		historyGenesisPurposeForTest,
		"capability-root",
	)

	_, detachedBinding := historyGenesisBindingsForTest(
		t,
		historyGenesisPurposeForTest,
		"capability-root",
		"witness-a",
		"witness-b",
		"witness-c",
		"witness-d",
	)
	detached, err := NewGovernedHistoryEpoch(
		detachedBinding,
		12,
		fixture.newHistory.genesisManifestHash,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ExecuteGenesisHistoryQuorumRotation(
		context.Background(),
		fixture.oldHistory,
		detached,
		fixture.quorumPlan,
		fixture.oldStore,
		fixture.newStore,
	); !errors.Is(err, ErrHistoryGenesisContinuity) {
		t.Fatalf("detached history custody = %v, want %v", err, ErrHistoryGenesisContinuity)
	}
}
