package journal

import (
	"errors"
	"testing"
)

func TestSuccessorInitializationSeedsAbsentReadableMinority(t *testing.T) {
	f := newVCS14RotationFixture(t)
	f.stores["witness-c"].base = newQuorumTestStore(nil)
	if _, err := InitializeSuccessorGovernanceAuthority(f.ctx, f.oldStore, f.oldHead.JournalID, f.oldBinding); err != nil {
		t.Fatal(err)
	}
	head, err := f.stores["witness-c"].base.Load(f.ctx, f.oldHead.JournalID)
	if err != nil || !sameSemanticHead(head, f.oldHead) {
		t.Fatalf("current majority omitted readable Genesis seed: head=%+v err=%v", head, err)
	}
	if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, f.signed, f.oldBinding, f.newBinding, f.plan, f.oldStore, f.newStore, f.now); err != nil {
		t.Fatalf("initialized minority prevented subsequent exact handoff: %v", err)
	}
}

func TestSuccessorInitializationDoesNotResetRetainedMinority(t *testing.T) {
	f := newVCS14RotationFixture(t)
	// Two missing heads are not permission to erase a retained successor.
	f.stores["witness-a"].base = newQuorumTestStore(nil)
	f.stores["witness-b"].base = newQuorumTestStore(nil)
	retained, err := jointSuccessorGovernanceHead(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	f.stores["witness-c"].base = newQuorumTestStore(&retained)
	if _, err := InitializeSuccessorGovernanceAuthority(f.ctx, f.oldStore, f.oldHead.JournalID, f.oldBinding); err == nil {
		current, activeErr := RequireActiveSuccessorGovernanceAuthority(f.ctx, f.oldStore, f.oldHead.JournalID, f.oldBinding)
		t.Fatalf("initialization reset retained JOINT_FROZEN: retained_sequence=%d retained_hash=%s current_sequence=%d old_authority_current=%t", retained.Sequence, retained.HeadHash, current.Sequence, activeErr == nil)
	}
	for _, id := range []string{"witness-a", "witness-b"} {
		if _, err := f.stores[id].base.Load(f.ctx, f.oldHead.JournalID); !errors.Is(err, ErrExternalHeadNotFound) {
			t.Fatalf("initialization changed missing witness before rejecting retained history: %s %v", id, err)
		}
	}
}
