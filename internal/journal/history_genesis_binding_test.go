package journal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

const governedHistoryPurposeForTest = "operation-history"

func governedHistoryEnvelopeForTest(
	t *testing.T,
	journalID string,
) []byte {
	t.Helper()
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
			Protocol: GovernedHistoryTrustPolicyVersion,
			Histories: []GovernedHistoryIdentity{{
				Purpose:   governedHistoryPurposeForTest,
				JournalID: journalID,
			}},
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func governedHistoryQuorumForTest(
	t *testing.T,
	raw []byte,
) *QuorumHeadStore {
	t.Helper()
	binding, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewQuorumHeadStore([]QuorumHeadMember{
		quorumMemberForTest("witness-a", NewMemoryHeadStore()),
		quorumMemberForTest("witness-b", NewMemoryHeadStore()),
		quorumMemberForTest("witness-c", NewMemoryHeadStore()),
	}, binding)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func initializeHistoryNamespace(
	t *testing.T,
	store ExternalHeadStore,
	journalID string,
) ExternalHead {
	t.Helper()
	head, err := store.CompareAndAdvance(
		context.Background(),
		ExternalHead{},
		ExternalHead{
			JournalID: journalID,
			Sequence:  0,
			KeyID:     "history-key",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestGenesisBoundHistoryStoreRejectsAlternateNamespaceUnderSameWitnesses(t *testing.T) {
	const (
		governedID   = "governed-operation-history"
		replacementID = "replacement-history"
	)
	raw := governedHistoryEnvelopeForTest(t, governedID)
	historyBinding, err := ParseGenesisHistoryBinding(
		raw,
		sha256Digest(raw),
		governedHistoryPurposeForTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	quorum := governedHistoryQuorumForTest(t, raw)

	governed := initializeHistoryNamespace(t, quorum, governedID)
	replacement := initializeHistoryNamespace(t, quorum, replacementID)

	// This is the executable counterexample at the composition boundary:
	// a Genesis-bound witness quorum is intentionally namespace-generic and can
	// hold both internally coherent histories. Witness identity alone therefore
	// does not identify which history the relying context is entitled to trust.
	if rawReplacement, err := quorum.Load(context.Background(), replacementID); err != nil ||
		rawReplacement.JournalID != replacementID {
		t.Fatalf("control: raw quorum did not expose alternate lineage: head=%+v err=%v", rawReplacement, err)
	}

	bound, err := NewGenesisBoundHistoryStore(quorum, historyBinding)
	if err != nil {
		t.Fatal(err)
	}
	if bound.JournalID() != governedID {
		t.Fatalf("bound journal id=%q want %q", bound.JournalID(), governedID)
	}
	if got, err := bound.Load(context.Background(), governedID); err != nil ||
		got.JournalID != governed.JournalID ||
		got.StoreVersion == "" {
		t.Fatalf("exact governed history did not survive binding: head=%+v err=%v", got, err)
	}
	if _, err := bound.Load(context.Background(), replacementID); !errors.Is(
		err,
		ErrHistoryLineageMismatch,
	) {
		t.Fatalf("alternate lineage inherited trusted witness custody: %v", err)
	}
	if _, err := bound.CompareAndAdvance(
		context.Background(),
		replacement,
		ExternalHead{
			JournalID: replacementID,
			Sequence:  1,
			HeadHash:  sha256Digest([]byte("replacement-effect")),
			KeyID:     replacement.KeyID,
		},
	); !errors.Is(err, ErrHistoryLineageMismatch) {
		t.Fatalf("alternate lineage advanced through governed binding: %v", err)
	}
}

func TestGenesisBoundHistoryStoreRejectsLineageFromDifferentGenesisEnvelope(t *testing.T) {
	const (
		governedID    = "governed-operation-history"
		replacementID = "replacement-history"
	)
	governedEnvelope := governedHistoryEnvelopeForTest(t, governedID)
	replacementEnvelope := governedHistoryEnvelopeForTest(t, replacementID)

	quorum := governedHistoryQuorumForTest(t, governedEnvelope)
	replacementBinding, err := ParseGenesisHistoryBinding(
		replacementEnvelope,
		sha256Digest(replacementEnvelope),
		governedHistoryPurposeForTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewGenesisBoundHistoryStore(
		quorum,
		replacementBinding,
	); !errors.Is(err, ErrHistoryGenesisBindingMismatch) {
		t.Fatalf("joint lineage + witness substitution crossed Genesis boundary: %v", err)
	}
}

func TestGenesisHistoryBindingRejectsEnvelopeTamperAndUnknownPurpose(t *testing.T) {
	raw := governedHistoryEnvelopeForTest(t, "governed-operation-history")
	genesisHash := sha256Digest(raw)

	tampered := append(append([]byte(nil), raw...), byte(' '))
	if _, err := ParseGenesisHistoryBinding(
		tampered,
		genesisHash,
		governedHistoryPurposeForTest,
	); err == nil {
		t.Fatal("history identity changed outside Genesis without rejection")
	}
	if _, err := ParseGenesisHistoryBinding(
		raw,
		genesisHash,
		"different-purpose",
	); err == nil {
		t.Fatal("unknown history purpose inherited a lineage identity")
	}
}

func TestGovernedHistoryPolicyRejectsLineageAliasing(t *testing.T) {
	envelope := struct {
		GovernedHistories GovernedHistoryTrustPolicy `json:"governed_histories"`
	}{
		GovernedHistories: GovernedHistoryTrustPolicy{
			Protocol: GovernedHistoryTrustPolicyVersion,
			Histories: []GovernedHistoryIdentity{
				{Purpose: "effects", JournalID: "shared-history"},
				{Purpose: "recovery", JournalID: "shared-history"},
			},
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenesisHistoryBinding(
		raw,
		sha256Digest(raw),
		"effects",
	); err == nil {
		t.Fatal("two governance purposes silently aliased one history lineage")
	}
}
