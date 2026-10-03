package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ucarion/jcs"
)

const GovernedHistoryTrustPolicyVersion = "aegis-ege/governed-history-trust-policy/v1"

var (
	ErrHistoryLineageMismatch       = errors.New("governed history lineage does not match Genesis binding")
	ErrHistoryGenesisBindingMismatch = errors.New("history witness does not share the Genesis capability binding")
)

type GovernedHistoryIdentity struct {
	Purpose   string `json:"purpose"`
	JournalID string `json:"journal_id"`
}

type GovernedHistoryTrustPolicy struct {
	Protocol  string                    `json:"protocol"`
	Histories []GovernedHistoryIdentity `json:"histories"`
}

// GenesisHistoryBinding identifies one governed history lineage selected from
// the exact capability-envelope bytes pinned by Genesis.
type GenesisHistoryBinding struct {
	capabilityEnvelopeHash string
	policyHash             string
	purpose                string
	journalID              string
}

type governedHistoriesCapabilityEnvelope struct {
	GovernedHistories json.RawMessage `json:"governed_histories"`
}

// ParseGenesisHistoryBinding derives a history-lineage identity only from the
// exact capability-envelope bytes already pinned by Genesis. The purpose is a
// relying-context selector, not a source of identity: its journal ID must come
// from the pinned envelope.
func ParseGenesisHistoryBinding(
	capabilityEnvelope []byte,
	genesisCapabilityEnvelopeHash string,
	purpose string,
) (GenesisHistoryBinding, error) {
	if !validSHA256Digest(genesisCapabilityEnvelopeHash) {
		return GenesisHistoryBinding{}, errors.New(
			"Genesis capability envelope hash must be a sha256 digest",
		)
	}
	actualEnvelopeHash := sha256Digest(capabilityEnvelope)
	if actualEnvelopeHash != genesisCapabilityEnvelopeHash {
		return GenesisHistoryBinding{}, fmt.Errorf(
			"capability envelope hash mismatch: got %s want Genesis %s",
			actualEnvelopeHash,
			genesisCapabilityEnvelopeHash,
		)
	}
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return GenesisHistoryBinding{}, errors.New("governed history purpose is required")
	}

	var envelope governedHistoriesCapabilityEnvelope
	if err := decodeSingleJSON(capabilityEnvelope, &envelope, false); err != nil {
		return GenesisHistoryBinding{}, fmt.Errorf("decode capability envelope: %w", err)
	}
	if len(envelope.GovernedHistories) == 0 ||
		string(envelope.GovernedHistories) == "null" {
		return GenesisHistoryBinding{}, errors.New(
			"capability envelope is missing governed_histories",
		)
	}

	var policy GovernedHistoryTrustPolicy
	if err := decodeSingleJSON(envelope.GovernedHistories, &policy, true); err != nil {
		return GenesisHistoryBinding{}, fmt.Errorf(
			"decode governed history trust policy: %w",
			err,
		)
	}
	normalized, err := normalizeGovernedHistoryTrustPolicy(policy)
	if err != nil {
		return GenesisHistoryBinding{}, err
	}
	policyHash, err := governedHistoryTrustPolicyDigest(normalized)
	if err != nil {
		return GenesisHistoryBinding{}, err
	}
	for _, history := range normalized.Histories {
		if history.Purpose == purpose {
			return GenesisHistoryBinding{
				capabilityEnvelopeHash: actualEnvelopeHash,
				policyHash:             policyHash,
				purpose:                history.Purpose,
				journalID:              history.JournalID,
			}, nil
		}
	}
	return GenesisHistoryBinding{}, fmt.Errorf(
		"governed history purpose %q is not authorized by Genesis",
		purpose,
	)
}

func (b GenesisHistoryBinding) CapabilityEnvelopeHash() string {
	return b.capabilityEnvelopeHash
}

func (b GenesisHistoryBinding) PolicyHash() string {
	return b.policyHash
}

func (b GenesisHistoryBinding) Purpose() string {
	return b.purpose
}

func (b GenesisHistoryBinding) JournalID() string {
	return b.journalID
}

func validateGenesisHistoryBinding(b GenesisHistoryBinding) error {
	if !validSHA256Digest(b.capabilityEnvelopeHash) ||
		!validSHA256Digest(b.policyHash) ||
		strings.TrimSpace(b.purpose) == "" ||
		strings.TrimSpace(b.journalID) == "" {
		return errors.New("valid Genesis history binding is required")
	}
	return nil
}

func normalizeGovernedHistoryTrustPolicy(
	policy GovernedHistoryTrustPolicy,
) (GovernedHistoryTrustPolicy, error) {
	if policy.Protocol != GovernedHistoryTrustPolicyVersion {
		return GovernedHistoryTrustPolicy{}, fmt.Errorf(
			"governed history protocol mismatch: got %q want %q",
			policy.Protocol,
			GovernedHistoryTrustPolicyVersion,
		)
	}
	if len(policy.Histories) == 0 {
		return GovernedHistoryTrustPolicy{}, errors.New(
			"governed history policy requires histories",
		)
	}
	seenPurpose := make(map[string]struct{}, len(policy.Histories))
	histories := make([]GovernedHistoryIdentity, 0, len(policy.Histories))
	for _, history := range policy.Histories {
		history.Purpose = strings.TrimSpace(history.Purpose)
		history.JournalID = strings.TrimSpace(history.JournalID)
		if history.Purpose == "" || history.JournalID == "" {
			return GovernedHistoryTrustPolicy{}, errors.New(
				"governed history purpose and journal_id are required",
			)
		}
		if _, ok := seenPurpose[history.Purpose]; ok {
			return GovernedHistoryTrustPolicy{}, fmt.Errorf(
				"duplicate governed history purpose %q",
				history.Purpose,
			)
		}
		seenPurpose[history.Purpose] = struct{}{}
		histories = append(histories, history)
	}
	sort.Slice(histories, func(i, j int) bool {
		return histories[i].Purpose < histories[j].Purpose
	})
	policy.Histories = histories
	return policy, nil
}

func governedHistoryTrustPolicyDigest(
	policy GovernedHistoryTrustPolicy,
) (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode governed history trust policy: %w", err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("decode governed history trust policy: %w", err)
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize governed history trust policy: %w", err)
	}
	return sha256Digest([]byte(canonical)), nil
}

// GenesisBoundHistoryStore composes two separately useful primitives:
// a Genesis-bound witness quorum and a Genesis-bound history identity. The
// quorum remains capable of hosting multiple namespaces; this wrapper is the
// relying-context boundary that permits exactly one lineage.
type GenesisBoundHistoryStore struct {
	store   *QuorumHeadStore
	binding GenesisHistoryBinding
}

func NewGenesisBoundHistoryStore(
	store *QuorumHeadStore,
	binding GenesisHistoryBinding,
) (*GenesisBoundHistoryStore, error) {
	if store == nil {
		return nil, errors.New("Genesis-bound history requires a quorum head store")
	}
	if err := validateGenesisHistoryBinding(binding); err != nil {
		return nil, err
	}
	if store.capabilityEnvelopeHash != binding.capabilityEnvelopeHash {
		return nil, fmt.Errorf(
			"%w: quorum envelope=%q history envelope=%q",
			ErrHistoryGenesisBindingMismatch,
			store.capabilityEnvelopeHash,
			binding.capabilityEnvelopeHash,
		)
	}
	return &GenesisBoundHistoryStore{
		store:   store,
		binding: binding,
	}, nil
}

func (s *GenesisBoundHistoryStore) JournalID() string {
	if s == nil {
		return ""
	}
	return s.binding.journalID
}

func (s *GenesisBoundHistoryStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	if s == nil || s.store == nil {
		return ExternalHead{}, errors.New("Genesis-bound history store is unavailable")
	}
	if journalID != s.binding.journalID {
		return ExternalHead{}, fmt.Errorf(
			"%w: got %q want %q",
			ErrHistoryLineageMismatch,
			journalID,
			s.binding.journalID,
		)
	}
	head, err := s.store.Load(ctx, journalID)
	if err != nil {
		return ExternalHead{}, err
	}
	if head.JournalID != s.binding.journalID {
		return ExternalHead{}, fmt.Errorf(
			"%w: witness returned %q want %q",
			ErrHistoryLineageMismatch,
			head.JournalID,
			s.binding.journalID,
		)
	}
	return head, nil
}

func (s *GenesisBoundHistoryStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if s == nil || s.store == nil {
		return ExternalHead{}, errors.New("Genesis-bound history store is unavailable")
	}
	if next.JournalID != s.binding.journalID ||
		(previous.JournalID != "" && previous.JournalID != s.binding.journalID) {
		return ExternalHead{}, fmt.Errorf(
			"%w: previous=%q next=%q want %q",
			ErrHistoryLineageMismatch,
			previous.JournalID,
			next.JournalID,
			s.binding.journalID,
		)
	}
	head, err := s.store.CompareAndAdvance(ctx, previous, next)
	if err != nil {
		return ExternalHead{}, err
	}
	if head.JournalID != s.binding.journalID {
		return ExternalHead{}, fmt.Errorf(
			"%w: witness returned %q want %q",
			ErrHistoryLineageMismatch,
			head.JournalID,
			s.binding.journalID,
		)
	}
	return head, nil
}
