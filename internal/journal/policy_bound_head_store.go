package journal

import (
	"context"
	"errors"
)

type PolicyBoundExternalHeadStore struct {
	store  QuorumPolicyFencedStore
	policy QuorumPolicyState
}

func NewPolicyBoundExternalHeadStore(
	store QuorumPolicyFencedStore,
	policy QuorumPolicyState,
) (*PolicyBoundExternalHeadStore, error) {
	if store == nil {
		return nil, errors.New("policy-fenced external head store is required")
	}
	if err := validateQuorumPolicyState(policy); err != nil {
		return nil, err
	}
	if policy.Phase != QuorumPolicyPhaseActive {
		return nil, errors.New("policy-bound external head store requires ACTIVE policy")
	}
	return &PolicyBoundExternalHeadStore{
		store:  store,
		policy: policy,
	}, nil
}

func (s *PolicyBoundExternalHeadStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	if s == nil || s.store == nil {
		return ExternalHead{}, errors.New("policy-bound external head store is unavailable")
	}
	return s.store.LoadForQuorum(ctx, journalID, s.policy)
}

func (s *PolicyBoundExternalHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if s == nil || s.store == nil {
		return ExternalHead{}, errors.New("policy-bound external head store is unavailable")
	}
	return s.store.CompareAndAdvanceForQuorum(
		ctx,
		s.policy,
		previous,
		next,
	)
}
