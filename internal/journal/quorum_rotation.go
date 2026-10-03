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

const QuorumRotationVersion = "aegis-ege/quorum-rotation/v1"

var (
	ErrQuorumPolicyMismatch     = errors.New("quorum witness policy mismatch")
	ErrQuorumRotationUnsafe     = errors.New("quorum rotation is not safety-preserving")
	ErrQuorumRotationAmbiguous  = errors.New("quorum rotation is in an ambiguous mixed state")
	ErrQuorumRotationContinuity = errors.New("quorum rotation head continuity failed")
)

type QuorumPolicyPhase string

const (
	QuorumPolicyPhaseActive QuorumPolicyPhase = "ACTIVE"
	QuorumPolicyPhaseJoint  QuorumPolicyPhase = "JOINT_FROZEN"
)

type QuorumPolicyState struct {
	Phase          QuorumPolicyPhase `json:"phase"`
	GenesisEpoch   uint64            `json:"genesis_epoch"`
	PolicyHash     string            `json:"policy_hash"`
	FromPolicyHash string            `json:"from_policy_hash,omitempty"`
	ToPolicyHash   string            `json:"to_policy_hash,omitempty"`
}

type QuorumPolicyFencedStore interface {
	ExternalHeadStore
	QuorumTrustIdentityProvider

	LoadForQuorum(
		ctx context.Context,
		journalID string,
		policy QuorumPolicyState,
	) (ExternalHead, error)

	CompareAndAdvanceForQuorum(
		ctx context.Context,
		policy QuorumPolicyState,
		previous ExternalHead,
		next ExternalHead,
	) (ExternalHead, error)

	CurrentQuorumPolicy(ctx context.Context) (QuorumPolicyState, error)

	ObserveQuorumRotationHead(
		ctx context.Context,
		journalID string,
	) (ExternalHead, error)

	CompareAndTransitionQuorumPolicy(
		ctx context.Context,
		expected QuorumPolicyState,
		next QuorumPolicyState,
		journalID string,
		expectedHead ExternalHead,
	) error
}

type GovernedQuorumEpoch struct {
	genesisEpoch        uint64
	genesisManifestHash string
	binding             GenesisQuorumBinding
}

func NewGovernedQuorumEpoch(
	binding GenesisQuorumBinding,
	genesisEpoch uint64,
	genesisManifestHash string,
) (GovernedQuorumEpoch, error) {
	if genesisEpoch == 0 {
		return GovernedQuorumEpoch{}, errors.New("Genesis epoch must be positive")
	}
	if !validSHA256Digest(genesisManifestHash) {
		return GovernedQuorumEpoch{}, errors.New("Genesis manifest hash must be sha256")
	}
	if err := validateGenesisQuorumBinding(binding); err != nil {
		return GovernedQuorumEpoch{}, err
	}
	return GovernedQuorumEpoch{
		genesisEpoch:        genesisEpoch,
		genesisManifestHash: genesisManifestHash,
		binding:             binding,
	}, nil
}

func (e GovernedQuorumEpoch) activePolicy() QuorumPolicyState {
	return QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: e.genesisEpoch,
		PolicyHash:   e.binding.policyHash,
	}
}

type QuorumRotationPlan struct {
	oldEpoch         GovernedQuorumEpoch
	newEpoch         GovernedQuorumEpoch
	sharedWitnesses  []string
	oldBlockingCount int
	newBlockingCount int
}

type quorumRotationCommitment struct {
	Version                string   `json:"version"`
	JournalID              string   `json:"journal_id"`
	Sequence               uint64   `json:"sequence"`
	HeadHash               string   `json:"head_hash"`
	KeyID                  string   `json:"key_id"`
	OldGenesisEpoch        uint64   `json:"old_genesis_epoch"`
	OldGenesisManifestHash string   `json:"old_genesis_manifest_hash"`
	OldPolicyHash          string   `json:"old_policy_hash"`
	NewGenesisEpoch        uint64   `json:"new_genesis_epoch"`
	NewGenesisManifestHash string   `json:"new_genesis_manifest_hash"`
	NewPolicyHash          string   `json:"new_policy_hash"`
	SharedWitnesses        []string `json:"shared_witnesses"`
}

type QuorumRotationResult struct {
	Head           ExternalHead
	TransitionHash string
	SharedWitnesses []string
}

func NewQuorumRotationPlan(
	oldEpoch GovernedQuorumEpoch,
	newEpoch GovernedQuorumEpoch,
) (QuorumRotationPlan, error) {
	if err := validateGenesisQuorumBinding(oldEpoch.binding); err != nil {
		return QuorumRotationPlan{}, fmt.Errorf("old quorum binding: %w", err)
	}
	if err := validateGenesisQuorumBinding(newEpoch.binding); err != nil {
		return QuorumRotationPlan{}, fmt.Errorf("new quorum binding: %w", err)
	}
	if oldEpoch.genesisEpoch == 0 || newEpoch.genesisEpoch == 0 {
		return QuorumRotationPlan{}, errors.New("both governed Genesis epochs are required")
	}
	if newEpoch.genesisEpoch <= oldEpoch.genesisEpoch {
		return QuorumRotationPlan{}, fmt.Errorf(
			"%w: Genesis epoch must advance: old=%d new=%d",
			ErrQuorumRotationUnsafe,
			oldEpoch.genesisEpoch,
			newEpoch.genesisEpoch,
		)
	}
	shared := make([]string, 0)
	for id, oldTrustHash := range oldEpoch.binding.members {
		newTrustHash, ok := newEpoch.binding.members[id]
		if !ok || newTrustHash != oldTrustHash {
			continue
		}
		shared = append(shared, id)
	}
	sort.Strings(shared)

	oldBlocking := len(oldEpoch.binding.members) - oldEpoch.binding.threshold + 1
	newBlocking := len(newEpoch.binding.members) - newEpoch.binding.threshold + 1

	// v1 deliberately requires the stable shared set to:
	// 1. intersect every old quorum, so OLD can be killed;
	// 2. intersect every new quorum, so NEW cannot exist early; and
	// 3. itself form a new quorum after the frozen handoff, so exact-head
	//    continuity does not depend on newly introduced witnesses.
	if len(shared) < oldBlocking ||
		len(shared) < newBlocking ||
		len(shared) < newEpoch.binding.threshold {
		return QuorumRotationPlan{}, fmt.Errorf(
			"%w: stable shared witnesses=%d old_blocking=%d new_blocking=%d new_threshold=%d",
			ErrQuorumRotationUnsafe,
			len(shared),
			oldBlocking,
			newBlocking,
			newEpoch.binding.threshold,
		)
	}

	return QuorumRotationPlan{
		oldEpoch:         oldEpoch,
		newEpoch:         newEpoch,
		sharedWitnesses:  shared,
		oldBlockingCount: oldBlocking,
		newBlockingCount: newBlocking,
	}, nil
}

func ExecuteQuorumRotation(
	ctx context.Context,
	plan QuorumRotationPlan,
	oldStore *QuorumHeadStore,
	newStore *QuorumHeadStore,
	journalID string,
) (QuorumRotationResult, error) {
	if err := ctx.Err(); err != nil {
		return QuorumRotationResult{}, err
	}
	journalID = strings.TrimSpace(journalID)
	if journalID == "" {
		return QuorumRotationResult{}, errors.New("journal id is required")
	}
	if oldStore == nil || newStore == nil {
		return QuorumRotationResult{}, errors.New("old and new quorum stores are required")
	}
	oldPolicy, ok := oldStore.governedPolicyState()
	if !ok || oldPolicy != plan.oldEpoch.activePolicy() {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: old quorum store is not bound to planned Genesis policy",
			ErrQuorumPolicyMismatch,
		)
	}
	newPolicy, ok := newStore.governedPolicyState()
	if !ok || newPolicy != plan.newEpoch.activePolicy() {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: new quorum store is not bound to planned Genesis policy",
			ErrQuorumPolicyMismatch,
		)
	}

	sharedStores, err := plan.sharedPolicyStores(oldStore, newStore)
	if err != nil {
		return QuorumRotationResult{}, err
	}
	head, err := observeSharedRotationHead(ctx, sharedStores, journalID)
	if err != nil {
		return QuorumRotationResult{}, err
	}
	joint, transitionHash, err := plan.jointPolicy(journalID, head)
	if err != nil {
		return QuorumRotationResult{}, err
	}

	oldCount, jointCount, newCount, err := classifyRotationPolicies(
		ctx,
		sharedStores,
		oldPolicy,
		joint,
		newPolicy,
	)
	if err != nil {
		return QuorumRotationResult{}, err
	}
	if oldCount > 0 && newCount > 0 {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: shared witnesses span OLD and NEW before OLD is fully fenced",
			ErrQuorumRotationAmbiguous,
		)
	}
	if oldCount == len(plan.sharedWitnesses) {
		oldHead, err := oldStore.Load(ctx, journalID)
		if err != nil {
			return QuorumRotationResult{}, fmt.Errorf(
				"fresh rotation cannot establish old quorum truth: %w",
				err,
			)
		}
		if !sameSemanticHead(oldHead, head) {
			return QuorumRotationResult{}, fmt.Errorf(
				"%w: shared witness head differs from old quorum truth",
				ErrQuorumRotationContinuity,
			)
		}
	}

	// Phase 1: OLD -> JOINT_FROZEN. No NEW shared witness is activated until
	// every stable shared witness has stopped accepting OLD.
	if oldCount > 0 {
		for _, id := range plan.sharedWitnesses {
			pair := sharedStores[id]
			current, err := sharedPolicyState(ctx, id, pair)
			if err != nil {
				return QuorumRotationResult{}, err
			}
			switch current {
			case oldPolicy:
				if err := pair.old.CompareAndTransitionQuorumPolicy(
					ctx,
					oldPolicy,
					joint,
					journalID,
					head,
				); err != nil {
					return QuorumRotationResult{}, fmt.Errorf(
						"freeze witness %s into joint policy: %w",
						id,
						err,
					)
				}
				if err := requireSharedHandleConvergence(
					ctx, id, pair, joint, journalID, head,
				); err != nil {
					return QuorumRotationResult{}, err
				}
			case joint:
				if err := requireSharedHandleConvergence(
					ctx, id, pair, joint, journalID, head,
				); err != nil {
					return QuorumRotationResult{}, err
				}
			default:
				return QuorumRotationResult{}, fmt.Errorf(
					"%w: witness %s has unexpected phase-1 policy %+v",
					ErrQuorumRotationAmbiguous,
					id,
					current,
				)
			}
		}
		oldCount, jointCount, newCount, err = classifyRotationPolicies(
			ctx,
			sharedStores,
			oldPolicy,
			joint,
			newPolicy,
		)
		if err != nil {
			return QuorumRotationResult{}, err
		}
	}
	if oldCount != 0 {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: old quorum still has shared witnesses after freeze: %d",
			ErrQuorumRotationUnsafe,
			oldCount,
		)
	}
	if jointCount+newCount != len(plan.sharedWitnesses) {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: shared witness state is incomplete after freeze",
			ErrQuorumRotationAmbiguous,
		)
	}

	// At this point the stable shared set intersects every old quorum, so OLD
	// can no longer reach threshold. Advancing JOINT -> NEW one witness at a
	// time cannot resurrect OLD.
	for _, id := range plan.sharedWitnesses {
		pair := sharedStores[id]
		current, err := sharedPolicyState(ctx, id, pair)
		if err != nil {
			return QuorumRotationResult{}, err
		}
		switch current {
		case joint:
			if err := pair.old.CompareAndTransitionQuorumPolicy(
				ctx,
				joint,
				newPolicy,
				journalID,
				head,
			); err != nil {
				return QuorumRotationResult{}, fmt.Errorf(
					"activate witness %s into new policy: %w",
					id,
					err,
				)
			}
			if err := requireSharedHandleConvergence(
				ctx, id, pair, newPolicy, journalID, head,
			); err != nil {
				return QuorumRotationResult{}, err
			}
		case newPolicy:
			if err := requireSharedHandleConvergence(
				ctx, id, pair, newPolicy, journalID, head,
			); err != nil {
				return QuorumRotationResult{}, err
			}
		default:
			return QuorumRotationResult{}, fmt.Errorf(
				"%w: witness %s has unexpected phase-2 policy %+v",
				ErrQuorumRotationAmbiguous,
				id,
				current,
			)
		}
	}

	newHead, err := newStore.Load(ctx, journalID)
	if err != nil {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: new quorum did not become readable: %v",
			ErrQuorumRotationContinuity,
			err,
		)
	}
	if !sameSemanticHead(newHead, head) {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: new quorum head %+v differs from frozen old head %+v",
			ErrQuorumRotationContinuity,
			newHead,
			head,
		)
	}

	if oldHead, err := oldStore.Load(ctx, journalID); err == nil {
		return QuorumRotationResult{}, fmt.Errorf(
			"%w: retired old quorum still reads authoritative head %+v",
			ErrQuorumRotationUnsafe,
			oldHead,
		)
	}

	return QuorumRotationResult{
		Head:            newHead,
		TransitionHash:  transitionHash,
		SharedWitnesses: append([]string(nil), plan.sharedWitnesses...),
	}, nil
}

func (p QuorumRotationPlan) jointPolicy(
	journalID string,
	head ExternalHead,
) (QuorumPolicyState, string, error) {
	commitment := quorumRotationCommitment{
		Version:                QuorumRotationVersion,
		JournalID:              journalID,
		Sequence:               head.Sequence,
		HeadHash:               head.HeadHash,
		KeyID:                  head.KeyID,
		OldGenesisEpoch:        p.oldEpoch.genesisEpoch,
		OldGenesisManifestHash: p.oldEpoch.genesisManifestHash,
		OldPolicyHash:          p.oldEpoch.binding.policyHash,
		NewGenesisEpoch:        p.newEpoch.genesisEpoch,
		NewGenesisManifestHash: p.newEpoch.genesisManifestHash,
		NewPolicyHash:          p.newEpoch.binding.policyHash,
		SharedWitnesses:        append([]string(nil), p.sharedWitnesses...),
	}
	raw, err := json.Marshal(commitment)
	if err != nil {
		return QuorumPolicyState{}, "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return QuorumPolicyState{}, "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return QuorumPolicyState{}, "", err
	}
	transitionHash := sha256Digest([]byte(canonical))
	return QuorumPolicyState{
		Phase:          QuorumPolicyPhaseJoint,
		GenesisEpoch:   p.newEpoch.genesisEpoch,
		PolicyHash:     transitionHash,
		FromPolicyHash: p.oldEpoch.binding.policyHash,
		ToPolicyHash:   p.newEpoch.binding.policyHash,
	}, transitionHash, nil
}

func ValidateQuorumPolicyTransition(
	current QuorumPolicyState,
	next QuorumPolicyState,
) error {
	if current == next {
		return nil
	}
	if err := validateQuorumPolicyState(current); err != nil {
		return fmt.Errorf("current quorum policy: %w", err)
	}
	if err := validateQuorumPolicyState(next); err != nil {
		return fmt.Errorf("next quorum policy: %w", err)
	}

	switch {
	case current.Phase == QuorumPolicyPhaseActive &&
		next.Phase == QuorumPolicyPhaseJoint:
		if next.GenesisEpoch <= current.GenesisEpoch {
			return errors.New("joint transition must advance Genesis epoch")
		}
		if next.FromPolicyHash != current.PolicyHash {
			return errors.New("joint transition does not bind current policy")
		}
		// A Genesis epoch may advance while retaining the exact same witness
		// policy. The JOINT commitment still changes because it binds the old and
		// new Genesis epochs/manifests, so ACTIVE(N,P) -> JOINT(N+1,P->P) ->
		// ACTIVE(N+1,P) remains an explicit fenced transition rather than a direct
		// epoch jump.
		return nil

	case current.Phase == QuorumPolicyPhaseJoint &&
		next.Phase == QuorumPolicyPhaseActive:
		if next.GenesisEpoch != current.GenesisEpoch {
			return errors.New("joint activation must stay in the target Genesis epoch")
		}
		if next.PolicyHash != current.ToPolicyHash {
			return errors.New("joint activation does not match committed target policy")
		}
		return nil

	default:
		return errors.New("direct or rollback quorum policy transition is forbidden")
	}
}

func validateQuorumPolicyState(state QuorumPolicyState) error {
	if state.GenesisEpoch == 0 {
		return errors.New("quorum policy Genesis epoch must be positive")
	}
	if !validSHA256Digest(state.PolicyHash) {
		return errors.New("quorum policy hash must be sha256")
	}
	switch state.Phase {
	case QuorumPolicyPhaseActive:
		if state.FromPolicyHash != "" || state.ToPolicyHash != "" {
			return errors.New("active quorum policy cannot carry transition endpoints")
		}
	case QuorumPolicyPhaseJoint:
		if !validSHA256Digest(state.FromPolicyHash) ||
			!validSHA256Digest(state.ToPolicyHash) {
			return errors.New("joint quorum policy must bind old and new policy hashes")
		}
	default:
		return fmt.Errorf("unsupported quorum policy phase %q", state.Phase)
	}
	return nil
}

func validateGenesisQuorumBinding(binding GenesisQuorumBinding) error {
	if len(binding.members) == 0 ||
		binding.threshold <= len(binding.members)/2 ||
		binding.threshold > len(binding.members) ||
		!validSHA256Digest(binding.policyHash) ||
		!validSHA256Digest(binding.capabilityEnvelopeHash) {
		return errors.New("valid Genesis quorum binding is required")
	}
	return nil
}


type sharedPolicyStoreHandles struct {
	old QuorumPolicyFencedStore
	new QuorumPolicyFencedStore
}

func (p QuorumRotationPlan) sharedPolicyStores(
	oldStore *QuorumHeadStore,
	newStore *QuorumHeadStore,
) (map[string]sharedPolicyStoreHandles, error) {
	oldMembers := make(map[string]QuorumHeadMember, len(oldStore.members))
	for _, member := range oldStore.members {
		oldMembers[member.ID] = member
	}
	newMembers := make(map[string]QuorumHeadMember, len(newStore.members))
	for _, member := range newStore.members {
		newMembers[member.ID] = member
	}

	result := make(map[string]sharedPolicyStoreHandles, len(p.sharedWitnesses))
	for _, id := range p.sharedWitnesses {
		oldMember, ok := oldMembers[id]
		if !ok {
			return nil, fmt.Errorf("old quorum store is missing shared witness %s", id)
		}
		newMember, ok := newMembers[id]
		if !ok {
			return nil, fmt.Errorf("new quorum store is missing shared witness %s", id)
		}
		oldPolicyStore, ok := oldMember.Store.(QuorumPolicyFencedStore)
		if !ok {
			return nil, fmt.Errorf("old shared witness %s is not policy fenced", id)
		}
		newPolicyStore, ok := newMember.Store.(QuorumPolicyFencedStore)
		if !ok {
			return nil, fmt.Errorf("new shared witness %s is not policy fenced", id)
		}
		if oldPolicyStore.QuorumTrustManifestHash() !=
			newPolicyStore.QuorumTrustManifestHash() {
			return nil, fmt.Errorf(
				"shared witness %s resolves to different trust identities",
				id,
			)
		}
		result[id] = sharedPolicyStoreHandles{
			old: oldPolicyStore,
			new: newPolicyStore,
		}
	}
	return result, nil
}

func sharedPolicyState(
	ctx context.Context,
	id string,
	pair sharedPolicyStoreHandles,
) (QuorumPolicyState, error) {
	oldState, err := pair.old.CurrentQuorumPolicy(ctx)
	if err != nil {
		return QuorumPolicyState{}, fmt.Errorf(
			"read old handle policy for witness %s: %w",
			id,
			err,
		)
	}
	newState, err := pair.new.CurrentQuorumPolicy(ctx)
	if err != nil {
		return QuorumPolicyState{}, fmt.Errorf(
			"read new handle policy for witness %s: %w",
			id,
			err,
		)
	}
	if oldState != newState {
		return QuorumPolicyState{}, fmt.Errorf(
			"%w: shared witness %s old/new handles disagree: old=%+v new=%+v",
			ErrQuorumRotationAmbiguous,
			id,
			oldState,
			newState,
		)
	}
	return oldState, nil
}

func observeSharedHandleHead(
	ctx context.Context,
	id string,
	pair sharedPolicyStoreHandles,
	journalID string,
) (ExternalHead, error) {
	oldHead, err := pair.old.ObserveQuorumRotationHead(ctx, journalID)
	if err != nil {
		return ExternalHead{}, fmt.Errorf(
			"observe old handle for shared witness %s: %w",
			id,
			err,
		)
	}
	newHead, err := pair.new.ObserveQuorumRotationHead(ctx, journalID)
	if err != nil {
		return ExternalHead{}, fmt.Errorf(
			"observe new handle for shared witness %s: %w",
			id,
			err,
		)
	}
	if !sameSemanticHead(oldHead, newHead) {
		return ExternalHead{}, fmt.Errorf(
			"%w: shared witness %s old/new handles disagree on head: old=%+v new=%+v",
			ErrQuorumRotationContinuity,
			id,
			oldHead,
			newHead,
		)
	}
	return oldHead, nil
}

func requireSharedHandleConvergence(
	ctx context.Context,
	id string,
	pair sharedPolicyStoreHandles,
	expectedPolicy QuorumPolicyState,
	journalID string,
	expectedHead ExternalHead,
) error {
	state, err := sharedPolicyState(ctx, id, pair)
	if err != nil {
		return err
	}
	if state != expectedPolicy {
		return fmt.Errorf(
			"%w: shared witness %s did not converge to expected policy: got=%+v want=%+v",
			ErrQuorumRotationAmbiguous,
			id,
			state,
			expectedPolicy,
		)
	}
	head, err := observeSharedHandleHead(ctx, id, pair, journalID)
	if err != nil {
		return err
	}
	if !sameSemanticHead(head, expectedHead) {
		return fmt.Errorf(
			"%w: shared witness %s changed head during policy transition: got=%+v want=%+v",
			ErrQuorumRotationContinuity,
			id,
			head,
			expectedHead,
		)
	}
	return nil
}

func observeSharedRotationHead(
	ctx context.Context,
	stores map[string]sharedPolicyStoreHandles,
	journalID string,
) (ExternalHead, error) {
	ids := make([]string, 0, len(stores))
	for id := range stores {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var frozen ExternalHead
	haveFrozen := false
	for _, id := range ids {
		head, err := observeSharedHandleHead(ctx, id, stores[id], journalID)
		if err != nil {
			return ExternalHead{}, err
		}
		if !haveFrozen {
			frozen = head
			haveFrozen = true
			continue
		}
		if !sameSemanticHead(frozen, head) {
			return ExternalHead{}, fmt.Errorf(
				"%w: shared witness %s has divergent head %+v, frozen %+v",
				ErrQuorumRotationContinuity,
				id,
				head,
				frozen,
			)
		}
	}
	if !haveFrozen {
		return ExternalHead{}, fmt.Errorf(
			"%w: no shared witness head is available",
			ErrQuorumRotationContinuity,
		)
	}
	return frozen, nil
}

func classifyRotationPolicies(
	ctx context.Context,
	stores map[string]sharedPolicyStoreHandles,
	oldPolicy QuorumPolicyState,
	joint QuorumPolicyState,
	newPolicy QuorumPolicyState,
) (oldCount int, jointCount int, newCount int, err error) {
	ids := make([]string, 0, len(stores))
	for id := range stores {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		current, currentErr := sharedPolicyState(ctx, id, stores[id])
		if currentErr != nil {
			return 0, 0, 0, currentErr
		}
		switch current {
		case oldPolicy:
			oldCount++
		case joint:
			jointCount++
		case newPolicy:
			newCount++
		default:
			return 0, 0, 0, fmt.Errorf(
				"%w: witness %s has unrelated policy %+v",
				ErrQuorumRotationAmbiguous,
				id,
				current,
			)
		}
	}
	return oldCount, jointCount, newCount, nil
}

