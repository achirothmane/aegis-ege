package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ucarion/jcs"
)

const HistoryLineageSuccessionVersion = "aegis-ege/history-lineage-succession/v1"

var (
	ErrHistoryLineageSuccessionUnauthorized = errors.New(
		"history lineage succession is not authorized by Genesis",
	)
	ErrHistoryLineageSuccessionContinuity = errors.New(
		"history lineage succession continuity failed",
	)
	ErrHistoryLineageSuccessionConflict = errors.New(
		"history lineage successor already exists with different state",
	)
)

type GovernedHistoryEpoch struct {
	genesisEpoch        uint64
	genesisManifestHash string
	binding             GenesisHistoryBinding
}

func NewGovernedHistoryEpoch(
	binding GenesisHistoryBinding,
	genesisEpoch uint64,
	genesisManifestHash string,
) (GovernedHistoryEpoch, error) {
	if err := validateGenesisHistoryBinding(binding); err != nil {
		return GovernedHistoryEpoch{}, err
	}
	if genesisEpoch == 0 {
		return GovernedHistoryEpoch{}, errors.New("Genesis epoch must be positive")
	}
	if !validSHA256Digest(genesisManifestHash) {
		return GovernedHistoryEpoch{}, errors.New("Genesis manifest hash must be sha256")
	}
	return GovernedHistoryEpoch{
		genesisEpoch:        genesisEpoch,
		genesisManifestHash: genesisManifestHash,
		binding:             binding,
	}, nil
}

func (e GovernedHistoryEpoch) GenesisEpoch() uint64 {
	return e.genesisEpoch
}

func (e GovernedHistoryEpoch) GenesisManifestHash() string {
	return e.genesisManifestHash
}

func (e GovernedHistoryEpoch) Binding() GenesisHistoryBinding {
	return GenesisHistoryBinding{
		capabilityEnvelopeHash: e.binding.capabilityEnvelopeHash,
		policyHash:             e.binding.policyHash,
		purpose:                e.binding.purpose,
		journalID:              e.binding.journalID,
		predecessor:            cloneGovernedHistoryPredecessor(e.binding.predecessor),
	}
}

type HistoryLineageSuccessionPlan struct {
	oldEpoch GovernedHistoryEpoch
	newEpoch GovernedHistoryEpoch
}

func NewHistoryLineageSuccessionPlan(
	oldEpoch GovernedHistoryEpoch,
	newEpoch GovernedHistoryEpoch,
) (HistoryLineageSuccessionPlan, error) {
	if err := validateGenesisHistoryBinding(oldEpoch.binding); err != nil {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf("old history binding: %w", err)
	}
	if err := validateGenesisHistoryBinding(newEpoch.binding); err != nil {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf("new history binding: %w", err)
	}
	if oldEpoch.genesisEpoch == 0 || newEpoch.genesisEpoch == 0 {
		return HistoryLineageSuccessionPlan{}, errors.New(
			"both governed history Genesis epochs are required",
		)
	}
	if newEpoch.genesisEpoch <= oldEpoch.genesisEpoch {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf(
			"%w: Genesis epoch must advance: old=%d new=%d",
			ErrHistoryLineageSuccessionUnauthorized,
			oldEpoch.genesisEpoch,
			newEpoch.genesisEpoch,
		)
	}
	if oldEpoch.binding.purpose != newEpoch.binding.purpose {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf(
			"%w: governed purpose changed from %q to %q",
			ErrHistoryLineageSuccessionUnauthorized,
			oldEpoch.binding.purpose,
			newEpoch.binding.purpose,
		)
	}
	if oldEpoch.binding.journalID == newEpoch.binding.journalID {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf(
			"%w: unchanged journal identity needs continuity, not succession",
			ErrHistoryLineageSuccessionUnauthorized,
		)
	}
	predecessor := newEpoch.binding.predecessor
	if predecessor == nil {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf(
			"%w: new Genesis does not declare a predecessor",
			ErrHistoryLineageSuccessionUnauthorized,
		)
	}
	if predecessor.GenesisEpoch != oldEpoch.genesisEpoch ||
		predecessor.GenesisManifestHash != oldEpoch.genesisManifestHash ||
		predecessor.HistoryPolicyHash != oldEpoch.binding.policyHash ||
		predecessor.CapabilityEnvelopeHash != oldEpoch.binding.capabilityEnvelopeHash ||
		predecessor.JournalID != oldEpoch.binding.journalID {
		return HistoryLineageSuccessionPlan{}, fmt.Errorf(
			"%w: predecessor declaration does not match the verified old lineage",
			ErrHistoryLineageSuccessionUnauthorized,
		)
	}
	return HistoryLineageSuccessionPlan{
		oldEpoch: oldEpoch,
		newEpoch: newEpoch,
	}, nil
}

type historyLineageSuccessionCommitment struct {
	Version                   string
	Purpose                   string
	OldGenesisEpoch           uint64
	OldGenesisManifestHash    string
	OldCapabilityEnvelopeHash string
	OldHistoryPolicyHash      string
	OldJournalID              string
	OldSequence               uint64
	OldHeadHash               string
	OldKeyID                  string
	NewGenesisEpoch           uint64
	NewGenesisManifestHash    string
	NewCapabilityEnvelopeHash string
	NewHistoryPolicyHash      string
	NewJournalID              string
}

type HistoryLineageSuccessionResult struct {
	PredecessorHead ExternalHead
	SuccessorHead   ExternalHead
	TransitionHash  string
}

func ExecuteHistoryLineageSuccession(
	ctx context.Context,
	plan HistoryLineageSuccessionPlan,
	newGenesisStore *QuorumHeadStore,
) (HistoryLineageSuccessionResult, error) {
	if err := ctx.Err(); err != nil {
		return HistoryLineageSuccessionResult{}, err
	}
	if newGenesisStore == nil {
		return HistoryLineageSuccessionResult{}, errors.New(
			"new Genesis quorum store is required",
		)
	}
	if newGenesisStore.capabilityEnvelopeHash !=
		plan.newEpoch.binding.capabilityEnvelopeHash {
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: new quorum and history binding do not share a Genesis envelope",
			ErrHistoryGenesisBindingMismatch,
		)
	}
	policy, ok := newGenesisStore.governedPolicyState()
	if !ok ||
		policy.Phase != QuorumPolicyPhaseActive ||
		policy.GenesisEpoch != plan.newEpoch.genesisEpoch {
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: new quorum is not active in the target Genesis epoch",
			ErrHistoryLineageSuccessionUnauthorized,
		)
	}

	predecessorHead, err := newGenesisStore.Load(
		ctx,
		plan.oldEpoch.binding.journalID,
	)
	if err != nil {
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: predecessor lineage is not readable from the active new Genesis quorum: %v",
			ErrHistoryLineageSuccessionContinuity,
			err,
		)
	}
	if predecessorHead.JournalID != plan.oldEpoch.binding.journalID {
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: predecessor head identity=%q want %q",
			ErrHistoryLineageSuccessionContinuity,
			predecessorHead.JournalID,
			plan.oldEpoch.binding.journalID,
		)
	}
	if predecessorHead.KeyID == "" {
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: predecessor head has no authority key identity",
			ErrHistoryLineageSuccessionContinuity,
		)
	}

	transitionHash, err := historyLineageSuccessionDigest(plan, predecessorHead)
	if err != nil {
		return HistoryLineageSuccessionResult{}, err
	}
	expectedSuccessor := ExternalHead{
		JournalID: plan.newEpoch.binding.journalID,
		Sequence:  0,
		HeadHash:  transitionHash,
		KeyID:     predecessorHead.KeyID,
	}

	current, err := newGenesisStore.Load(ctx, expectedSuccessor.JournalID)
	switch {
	case err == nil:
		if !sameSemanticHead(current, expectedSuccessor) {
			return HistoryLineageSuccessionResult{}, fmt.Errorf(
				"%w: got %+v want %+v",
				ErrHistoryLineageSuccessionConflict,
				current,
				expectedSuccessor,
			)
		}
		expectedSuccessor.StoreVersion = current.StoreVersion
	case errors.Is(err, ErrExternalHeadNotFound):
		created, createErr := newGenesisStore.CompareAndAdvance(
			ctx,
			ExternalHead{},
			expectedSuccessor,
		)
		if createErr != nil {
			return HistoryLineageSuccessionResult{}, fmt.Errorf(
				"commit governed history succession anchor: %w",
				createErr,
			)
		}
		if !sameSemanticHead(created, expectedSuccessor) {
			return HistoryLineageSuccessionResult{}, fmt.Errorf(
				"%w: created successor head %+v differs from commitment %+v",
				ErrHistoryLineageSuccessionContinuity,
				created,
				expectedSuccessor,
			)
		}
		expectedSuccessor.StoreVersion = created.StoreVersion
	default:
		return HistoryLineageSuccessionResult{}, fmt.Errorf(
			"%w: cannot determine successor namespace state: %v",
			ErrHistoryLineageSuccessionContinuity,
			err,
		)
	}

	return HistoryLineageSuccessionResult{
		PredecessorHead: predecessorHead,
		SuccessorHead:   expectedSuccessor,
		TransitionHash:  transitionHash,
	}, nil
}

func historyLineageSuccessionDigest(
	plan HistoryLineageSuccessionPlan,
	predecessorHead ExternalHead,
) (string, error) {
	commitment := historyLineageSuccessionCommitment{
		Version:                   HistoryLineageSuccessionVersion,
		Purpose:                   plan.oldEpoch.binding.purpose,
		OldGenesisEpoch:           plan.oldEpoch.genesisEpoch,
		OldGenesisManifestHash:    plan.oldEpoch.genesisManifestHash,
		OldCapabilityEnvelopeHash: plan.oldEpoch.binding.capabilityEnvelopeHash,
		OldHistoryPolicyHash:      plan.oldEpoch.binding.policyHash,
		OldJournalID:              plan.oldEpoch.binding.journalID,
		OldSequence:               predecessorHead.Sequence,
		OldHeadHash:               predecessorHead.HeadHash,
		OldKeyID:                  predecessorHead.KeyID,
		NewGenesisEpoch:           plan.newEpoch.genesisEpoch,
		NewGenesisManifestHash:    plan.newEpoch.genesisManifestHash,
		NewCapabilityEnvelopeHash: plan.newEpoch.binding.capabilityEnvelopeHash,
		NewHistoryPolicyHash:      plan.newEpoch.binding.policyHash,
		NewJournalID:              plan.newEpoch.binding.journalID,
	}
	raw, err := json.Marshal(commitment)
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", err
	}
	return sha256Digest([]byte(canonical)), nil
}
