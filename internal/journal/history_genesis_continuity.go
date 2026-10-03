package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ucarion/jcs"
)

const GovernedHistoryGenesisContinuityVersion = "aegis-ege/governed-history-genesis-continuity/v1"

var (
	ErrHistoryGenesisContinuity  = errors.New("governed history Genesis continuity failed")
	ErrHistorySuccessionRequired = errors.New("governed history lineage change requires explicit succession")
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

type historyGenesisContinuityCommitment struct {
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
	NewGenesisEpoch           uint64 `json:"new_genesis_epoch"`
	NewGenesisManifestHash    string `json:"new_genesis_manifest_hash"`
	NewCapabilityEnvelopeHash string `json:"new_capability_envelope_hash"`
	NewHistoryPolicyHash      string `json:"new_history_policy_hash"`
	QuorumTransitionHash      string `json:"quorum_transition_hash"`
}

type HistoryGenesisContinuityResult struct {
	Head                 ExternalHead
	QuorumTransitionHash string
	ContinuityHash       string
}

// ExecuteGenesisHistoryQuorumRotation is the governed relying-context wrapper
// for moving one history across Genesis-bound quorum epochs.
//
// v1 deliberately permits only identity-preserving continuity: the same
// purpose must resolve to the same JournalID in both Genesis epochs. A changed
// lineage is not treated as continuity and fails closed until an explicit
// succession protocol proves the inheritance.
func ExecuteGenesisHistoryQuorumRotation(
	ctx context.Context,
	oldHistory GovernedHistoryEpoch,
	newHistory GovernedHistoryEpoch,
	quorumPlan QuorumRotationPlan,
	oldStore *QuorumHeadStore,
	newStore *QuorumHeadStore,
) (HistoryGenesisContinuityResult, error) {
	if err := ctx.Err(); err != nil {
		return HistoryGenesisContinuityResult{}, err
	}
	if err := validateGovernedHistoryEpoch(oldHistory); err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: old history epoch: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}
	if err := validateGovernedHistoryEpoch(newHistory); err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: new history epoch: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}
	if newHistory.genesisEpoch <= oldHistory.genesisEpoch {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: Genesis epoch must advance: old=%d new=%d",
			ErrHistoryGenesisContinuity,
			oldHistory.genesisEpoch,
			newHistory.genesisEpoch,
		)
	}
	if oldHistory.binding.purpose != newHistory.binding.purpose {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: history purpose changed from %q to %q",
			ErrHistoryGenesisContinuity,
			oldHistory.binding.purpose,
			newHistory.binding.purpose,
		)
	}
	if oldHistory.binding.journalID != newHistory.binding.journalID {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: purpose %q changed lineage from %q to %q",
			ErrHistorySuccessionRequired,
			oldHistory.binding.purpose,
			oldHistory.binding.journalID,
			newHistory.binding.journalID,
		)
	}

	if oldHistory.genesisEpoch != quorumPlan.oldEpoch.genesisEpoch ||
		newHistory.genesisEpoch != quorumPlan.newEpoch.genesisEpoch ||
		oldHistory.genesisManifestHash != quorumPlan.oldEpoch.genesisManifestHash ||
		newHistory.genesisManifestHash != quorumPlan.newEpoch.genesisManifestHash {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: history and quorum transitions do not bind the same Genesis epochs",
			ErrHistoryGenesisContinuity,
		)
	}
	if oldHistory.binding.capabilityEnvelopeHash !=
		quorumPlan.oldEpoch.binding.capabilityEnvelopeHash ||
		newHistory.binding.capabilityEnvelopeHash !=
			quorumPlan.newEpoch.binding.capabilityEnvelopeHash {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: history identity and quorum custody are not derived from the same Genesis capability envelopes",
			ErrHistoryGenesisContinuity,
		)
	}

	oldBound, err := NewGenesisBoundHistoryStore(oldStore, oldHistory.binding)
	if err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: bind old history custody: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}
	newBound, err := NewGenesisBoundHistoryStore(newStore, newHistory.binding)
	if err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: bind new history custody: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}

	journalID := oldHistory.binding.journalID
	before, err := oldBound.Load(ctx, journalID)
	if err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: establish old governed history head: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}

	rotation, err := ExecuteQuorumRotation(
		ctx,
		quorumPlan,
		oldStore,
		newStore,
		journalID,
	)
	if err != nil {
		return HistoryGenesisContinuityResult{}, err
	}
	if !sameSemanticHead(rotation.Head, before) {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: quorum rotation changed governed history head",
			ErrHistoryGenesisContinuity,
		)
	}

	after, err := newBound.Load(ctx, journalID)
	if err != nil {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: establish new governed history head: %v",
			ErrHistoryGenesisContinuity,
			err,
		)
	}
	if !sameSemanticHead(after, before) {
		return HistoryGenesisContinuityResult{}, fmt.Errorf(
			"%w: new Genesis history differs from predecessor",
			ErrHistoryGenesisContinuity,
		)
	}

	continuityHash, err := historyGenesisContinuityDigest(
		oldHistory,
		newHistory,
		after,
		rotation.TransitionHash,
	)
	if err != nil {
		return HistoryGenesisContinuityResult{}, err
	}
	return HistoryGenesisContinuityResult{
		Head:                 after,
		QuorumTransitionHash: rotation.TransitionHash,
		ContinuityHash:       continuityHash,
	}, nil
}

func validateGovernedHistoryEpoch(epoch GovernedHistoryEpoch) error {
	if epoch.genesisEpoch == 0 {
		return errors.New("Genesis epoch must be positive")
	}
	if !validSHA256Digest(epoch.genesisManifestHash) {
		return errors.New("Genesis manifest hash must be sha256")
	}
	return validateGenesisHistoryBinding(epoch.binding)
}

func historyGenesisContinuityDigest(
	oldHistory GovernedHistoryEpoch,
	newHistory GovernedHistoryEpoch,
	head ExternalHead,
	quorumTransitionHash string,
) (string, error) {
	if !validSHA256Digest(quorumTransitionHash) {
		return "", fmt.Errorf(
			"%w: quorum transition hash must be sha256",
			ErrHistoryGenesisContinuity,
		)
	}
	commitment := historyGenesisContinuityCommitment{
		Version:                   GovernedHistoryGenesisContinuityVersion,
		Purpose:                   strings.TrimSpace(oldHistory.binding.purpose),
		JournalID:                 strings.TrimSpace(head.JournalID),
		Sequence:                  head.Sequence,
		HeadHash:                  strings.TrimSpace(head.HeadHash),
		KeyID:                     strings.TrimSpace(head.KeyID),
		OldGenesisEpoch:           oldHistory.genesisEpoch,
		OldGenesisManifestHash:    oldHistory.genesisManifestHash,
		OldCapabilityEnvelopeHash: oldHistory.binding.capabilityEnvelopeHash,
		OldHistoryPolicyHash:      oldHistory.binding.policyHash,
		NewGenesisEpoch:           newHistory.genesisEpoch,
		NewGenesisManifestHash:    newHistory.genesisManifestHash,
		NewCapabilityEnvelopeHash: newHistory.binding.capabilityEnvelopeHash,
		NewHistoryPolicyHash:      newHistory.binding.policyHash,
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
