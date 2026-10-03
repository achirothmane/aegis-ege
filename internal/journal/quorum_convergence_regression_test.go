package journal

import (
	"context"
	"errors"
	"testing"
)

func TestQuorumConvergenceRepairsReadableMinorityEvenWithTargetMajority(t *testing.T) {
	f := newVCS14RotationFixture(t)
	target, err := jointSuccessorGovernanceHead(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"witness-a", "witness-b"} {
		head, err := f.stores[id].base.Load(f.ctx, f.oldHead.JournalID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.stores[id].base.CompareAndAdvance(f.ctx, head, target); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.oldStore.ConvergeAuthorizedTransition(f.ctx, []ExternalHead{f.oldHead, target}, target); err != nil {
		t.Fatal(err)
	}
	minority, err := f.stores["witness-c"].base.Load(f.ctx, f.oldHead.JournalID)
	if err != nil || !sameSemanticHead(minority, target) {
		t.Fatalf("majority hid unconverged shared witness: %+v %v", minority, err)
	}
}

// The read is admissible; policy changes before the actual CAS. Convergence
// must use the member's native epoch fence, just like ordinary advancement.
type policyChangesAfterRead struct {
	*rotationPolicyTestStore
	next QuorumPolicyState
}

func (s *policyChangesAfterRead) LoadForQuorum(ctx context.Context, id string, policy QuorumPolicyState) (ExternalHead, error) {
	head, err := s.rotationPolicyTestStore.LoadForQuorum(ctx, id, policy)
	if err == nil {
		s.setPolicy(s.next)
	}
	return head, err
}

func TestQuorumConvergenceCannotBypassEpochFence(t *testing.T) {
	f := newVCS14RotationFixture(t)
	target, err := jointSuccessorGovernanceHead(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	members := make([]QuorumHeadMember, 0, 3)
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		members = append(members, QuorumHeadMember{ID: id, Store: &policyChangesAfterRead{f.stores[id], f.plan.newEpoch.activePolicy()}})
	}
	store, err := NewGovernedQuorumHeadStore(members, f.plan.oldEpoch.binding, f.oldBinding.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConvergeAuthorizedTransition(f.ctx, []ExternalHead{f.oldHead, target}, target); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("epoch-fenced CAS bypassed: %v", err)
	}
	for _, member := range members {
		head, err := member.Store.Load(f.ctx, f.oldHead.JournalID)
		if err != nil || !sameSemanticHead(head, f.oldHead) {
			t.Fatalf("retired epoch mutated head: %+v %v", head, err)
		}
	}
}
