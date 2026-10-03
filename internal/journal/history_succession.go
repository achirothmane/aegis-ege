package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ucarion/jcs"
)

const HistorySuccessionVersion = "aegis-ege/history-succession/v1"

var (
	ErrHistorySuccessionUnsafe     = errors.New("governed history succession is not safety-preserving")
	ErrHistorySuccessionContinuity = errors.New("governed history succession continuity failed")
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

func (e GovernedHistoryEpoch) Purpose() string {
	return e.binding.purpose
}

func (e GovernedHistoryEpoch) JournalID() string {
	return e.binding.journalID
}

type HistorySuccessionPlan struct {
	oldEpoch   GovernedHistoryEpoch
	newEpoch   GovernedHistoryEpoch
	quorumPlan QuorumRotationPlan
}

func NewHistorySuccessionPlan(
	oldEpoch GovernedHistoryEpoch,
	newEpoch GovernedHistoryEpoch,
	quorumPlan QuorumRotationPlan,
) (HistorySuccessionPlan, error) {
	if err := validateGenesisHistoryBinding(oldEpoch.binding); err != nil {
		return HistorySuccessionPlan{}, fmt.Errorf("old history binding: %w", err)
	}
	if err := validateGenesisHistoryBinding(newEpoch.binding); err != nil {
		return HistorySuccessionPlan{}, fmt.Errorf("new history binding: %w", err)
	}
	if oldEpoch.genesisEpoch == 0 || newEpoch.genesisEpoch == 0 {
		return HistorySuccessionPlan{}, errors.New("both governed history epochs are required")
	}
	if newEpoch.genesisEpoch <= oldEpoch.genesisEpoch {
		return HistorySuccessionPlan{}, fmt.Errorf(
			"%w: Genesis epoch must advance: old=%d new=%d",
			ErrHistorySuccessionUnsafe,
			oldEpoch.genesisEpoch,
			newEpoch.genesisEpoch,
		)
	}
	if oldEpoch.binding.purpose != newEpoch.binding.purpose {
		return HistorySuccessionPlan{}, fmt.Errorf(
			"%w: governed purpose changed from %q to %q",
			ErrHistorySuccessionUnsafe,
			oldEpoch.binding.purpose,
			newEpoch.binding.purpose,
		)
	}

	if oldEpoch.binding.journalID != newEpoch.binding.journalID {
		return HistorySuccessionPlan{}, fmt.Errorf(
			"%w: lineage rename/reset from %q to %q requires an explicit migration protocol",
			ErrHistorySuccessionUnsafe,
			oldEpoch.binding.journalID,
			newEpoch.binding.journalID,
		)
	}

	if quorumPlan.oldEpoch.genesisEpoch != oldEpoch.genesisEpoch ||
		quorumPlan.newEpoch.genesisEpoch != newEpoch.genesisEpoch ||
		quorumPlan.oldEpoch.genesisManifestHash != oldEpoch.genesisManifestHash ||
		quorumPlan.newEpoch.genesisManifestHash != newEpoch.genesisManifestHash {
		return HistorySuccessionPlan{}, fmt.Errorf(
			"%w: history and quorum transitions do not name the same Genesis epochs",
			ErrHistorySuccessionUnsafe,
		)
	}
	if quorumPlan.oldEpoch.binding.capabilityEnvelopeHash !=
		oldEpoch.binding.capabilityEnvelopeHash ||
		quorumPlan.newEpoch.binding.capabilityEnvelopeHash !=
			newEpoch.binding.capabilityEnvelopeHash {
		return HistorySuccessionPlan{}, fmt.Errorf(
			"%w: history and quorum bindings do not come from the same Genesis capability envelopes",
			ErrHistorySuccessionUnsafe,
		)
	}

	return HistorySuccessionPlan{
		oldEpoch:   oldEpoch,
		newEpoch:   newEpoch,
		quorumPlan: quorumPlan,
	}, nil
}

type historySuccessionCommitment struct {
	Version                   string `json:"version"`
	Purpose                   string `json:"purpose"`
	JournalID                 string `json:"journal_id"`
	Sequence                  uint64 `json:"sequence"`
	HeadHash                  string `json:"head_hash"`
	KeyID                     string `json:"key_id"`
	OldGenesisEpoch           uint64 `json:"old_genesis_epoch"`
	OldGenesisManifestHash    string `json:"old_genesis_manifest_hash"`
	OldCapabilityEnvelopeHash string `json:"old_capability_envelope_hash"`
	OldHistoryPolicyHash      string `json:"old_history_policy_hash"`
	OldQuorumPolicyHash       string `json:"old_quorum_policy_hash"`
	NewGenesisEpoch           uint64 `json:"new_genesis_epoch"`
	NewGenesisManifestHash    string `json:"new_genesis_manifest_hash"`
	NewCapabilityEnvelopeHash string `json:"new_capability_envelope_hash"`
	NewHistoryPolicyHash      string `json:"new_history_policy_hash"`
	NewQuorumPolicyHash       string `json:"new_quorum_policy_hash"`
	QuorumTransitionHash      string `json:"quorum_transition_hash"`
}

type HistorySuccessionResult struct {
	Head                 ExternalHead
	TransitionHash       string
	QuorumTransitionHash string
}

func ExecuteGovernedHistorySuccession(
	ctx context.Context,
	plan HistorySuccessionPlan,
	oldStore *QuorumHeadStore,
	newStore *QuorumHeadStore,
) (HistorySuccessionResult, error) {
	if err := ctx.Err(); err != nil {
		return HistorySuccessionResult{}, err
	}
	if oldStore == nil || newStore == nil {
		return HistorySuccessionResult{}, errors.New("old and new quorum stores are required")
	}
	oldBound, err := NewGenesisBoundHistoryStore(oldStore, plan.oldEpoch.binding)
	if err != nil {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: old history composition: %v",
			ErrHistorySuccessionUnsafe,
			err,
		)
	}
	newBound, err := NewGenesisBoundHistoryStore(newStore, plan.newEpoch.binding)
	if err != nil {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: new history composition: %v",
			ErrHistorySuccessionUnsafe,
			err,
		)
	}

	journalID := plan.oldEpoch.binding.journalID
	before, err := oldBound.Load(ctx, journalID)
	if err != nil {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: old governed history is not authoritative: %v",
			ErrHistorySuccessionContinuity,
			err,
		)
	}

	rotation, err := ExecuteQuorumRotation(
		ctx,
		plan.quorumPlan,
		oldStore,
		newStore,
		journalID,
	)
	if err != nil {
		return HistorySuccessionResult{}, err
	}
	if !sameSemanticHead(rotation.Head, before) {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: quorum transition changed governed history head",
			ErrHistorySuccessionContinuity,
		)
	}

	after, err := newBound.Load(ctx, journalID)
	if err != nil {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: successor history is not authoritative: %v",
			ErrHistorySuccessionContinuity,
			err,
		)
	}
	if !sameSemanticHead(after, before) {
		return HistorySuccessionResult{}, fmt.Errorf(
			"%w: successor head %+v differs from predecessor %+v",
			ErrHistorySuccessionContinuity,
			after,
			before,
		)
	}

	transitionHash, err := plan.transitionHash(after, rotation.TransitionHash)
	if err != nil {
		return HistorySuccessionResult{}, err
	}
	return HistorySuccessionResult{
		Head:                 after,
		TransitionHash:       transitionHash,
		QuorumTransitionHash: rotation.TransitionHash,
	}, nil
}

func (p HistorySuccessionPlan) transitionHash(
	head ExternalHead,
	quorumTransitionHash string,
) (string, error) {
	if strings.TrimSpace(head.JournalID) != p.oldEpoch.binding.journalID ||
		!validSHA256Digest(quorumTransitionHash) {
		return "", ErrHistorySuccessionContinuity
	}
	commitment := historySuccessionCommitment{
		Version:                   HistorySuccessionVersion,
		Purpose:                   p.oldEpoch.binding.purpose,
		JournalID:                 head.JournalID,
		Sequence:                  head.Sequence,
		HeadHash:                  head.HeadHash,
		KeyID:                     head.KeyID,
		OldGenesisEpoch:           p.oldEpoch.genesisEpoch,
		OldGenesisManifestHash:    p.oldEpoch.genesisManifestHash,
		OldCapabilityEnvelopeHash: p.oldEpoch.binding.capabilityEnvelopeHash,
		OldHistoryPolicyHash:      p.oldEpoch.binding.policyHash,
		OldQuorumPolicyHash:       p.quorumPlan.oldEpoch.binding.policyHash,
		NewGenesisEpoch:           p.newEpoch.genesisEpoch,
		NewGenesisManifestHash:    p.newEpoch.genesisManifestHash,
		NewCapabilityEnvelopeHash: p.newEpoch.binding.capabilityEnvelopeHash,
		NewHistoryPolicyHash:      p.newEpoch.binding.policyHash,
		NewQuorumPolicyHash:       p.quorumPlan.newEpoch.binding.policyHash,
		QuorumTransitionHash:      quorumTransitionHash,
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
