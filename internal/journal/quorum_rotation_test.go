package journal

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type rotationPolicyTestStore struct {
	mu                sync.Mutex
	base              *quorumTestStore
	trustManifestHash string
	policy            QuorumPolicyState
	failJoint         int
	failActiveHash    string
	failActive        int
}

func newRotationPolicyTestStore(
	head ExternalHead,
	trustManifestHash string,
	policy QuorumPolicyState,
) *rotationPolicyTestStore {
	return &rotationPolicyTestStore{
		base:              newQuorumTestStore(&head),
		trustManifestHash: trustManifestHash,
		policy:            policy,
	}
}

func (s *rotationPolicyTestStore) QuorumTrustManifestHash() string {
	return s.trustManifestHash
}

func (s *rotationPolicyTestStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	return s.base.Load(ctx, journalID)
}

func (s *rotationPolicyTestStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *rotationPolicyTestStore) LoadForQuorum(
	ctx context.Context,
	journalID string,
	policy QuorumPolicyState,
) (ExternalHead, error) {
	s.mu.Lock()
	current := s.policy
	s.mu.Unlock()
	if current != policy || current.Phase != QuorumPolicyPhaseActive {
		return ExternalHead{}, ErrQuorumPolicyMismatch
	}
	return s.base.Load(ctx, journalID)
}

func (s *rotationPolicyTestStore) CompareAndAdvanceForQuorum(
	ctx context.Context,
	policy QuorumPolicyState,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	s.mu.Lock()
	current := s.policy
	s.mu.Unlock()
	if current != policy || current.Phase != QuorumPolicyPhaseActive {
		return ExternalHead{}, ErrQuorumPolicyMismatch
	}
	return s.base.CompareAndAdvance(ctx, previous, next)
}

func (s *rotationPolicyTestStore) CurrentQuorumPolicy(
	ctx context.Context,
) (QuorumPolicyState, error) {
	if err := ctx.Err(); err != nil {
		return QuorumPolicyState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy, nil
}

func (s *rotationPolicyTestStore) CompareAndTransitionQuorumPolicy(
	ctx context.Context,
	expected QuorumPolicyState,
	next QuorumPolicyState,
	journalID string,
	expectedHead ExternalHead,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy != expected {
		return ErrQuorumPolicyMismatch
	}
	if err := ValidateQuorumPolicyTransition(expected, next); err != nil {
		return err
	}
	actual, err := s.base.Load(ctx, journalID)
	if err != nil {
		return err
	}
	if !sameSemanticHead(actual, expectedHead) {
		return ErrQuorumRotationContinuity
	}
	if next.Phase == QuorumPolicyPhaseJoint && s.failJoint > 0 {
		s.failJoint--
		return errors.New("synthetic joint transition interruption")
	}
	if next.Phase == QuorumPolicyPhaseActive &&
		next.PolicyHash == s.failActiveHash &&
		s.failActive > 0 {
		s.failActive--
		return errors.New("synthetic activation interruption")
	}
	s.policy = next
	return nil
}

func (s *rotationPolicyTestStore) setPolicy(policy QuorumPolicyState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
}

func governedRotationFixture(
	t *testing.T,
) (
	QuorumRotationPlan,
	*QuorumHeadStore,
	*QuorumHeadStore,
	map[string]*rotationPolicyTestStore,
	ExternalHead,
) {
	t.Helper()

	oldBinding := quorumBindingForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	newBinding := quorumBindingForTest(
		t,
		2,
		"witness-b",
		"witness-c",
		"witness-d",
	)
	oldEpoch, err := NewGovernedQuorumEpoch(
		oldBinding,
		11,
		sha256Digest([]byte("genesis-11")),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch, err := NewGovernedQuorumEpoch(
		newBinding,
		12,
		sha256Digest([]byte("genesis-12")),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewQuorumRotationPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}

	head := quorumTestHead(17, "a")
	oldPolicy := oldEpoch.activePolicy()
	newPolicy := newEpoch.activePolicy()
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
		// New-only D may already carry the target policy. It cannot form a
		// target quorum before B/C move because the stable shared set is also a
		// blocking set of every new quorum.
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
		oldBinding,
		oldEpoch.genesisEpoch,
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
		newBinding,
		newEpoch.genesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan, oldStore, newStore, stores, head
}

func TestGovernedQuorumRotationABCToBCDPreventsSplitTruth(t *testing.T) {
	plan, oldStore, newStore, stores, head := governedRotationFixture(t)
	ctx := context.Background()

	if got, err := oldStore.Load(ctx, head.JournalID); err != nil ||
		!sameSemanticHead(got, head) {
		t.Fatalf("old quorum not initially authoritative: head=%+v err=%v", got, err)
	}
	if _, err := newStore.Load(ctx, head.JournalID); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("new quorum became authoritative before rotation: %v", err)
	}

	result, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(result.Head, head) {
		t.Fatalf("rotated head = %+v, want %+v", result.Head, head)
	}
	if !validSHA256Digest(result.TransitionHash) {
		t.Fatalf("rotation transition hash is not bound: %q", result.TransitionHash)
	}

	if _, err := oldStore.Load(ctx, head.JournalID); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("retired old quorum remained readable: %v", err)
	}
	if got, err := newStore.Load(ctx, head.JournalID); err != nil ||
		!sameSemanticHead(got, head) {
		t.Fatalf("new quorum did not inherit exact head: head=%+v err=%v", got, err)
	}

	for _, id := range []string{"witness-b", "witness-c"} {
		state, err := stores[id].CurrentQuorumPolicy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state != plan.newEpoch.activePolicy() {
			t.Fatalf("%s final policy = %+v, want NEW", id, state)
		}
	}

	next := quorumTestHead(head.Sequence+1, "b")
	if _, err := oldStore.CompareAndAdvance(ctx, head, next); err == nil {
		t.Fatal("retired old quorum unexpectedly advanced")
	}
	previous, err := newStore.Load(ctx, head.JournalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newStore.CompareAndAdvance(ctx, previous, next); err != nil {
		t.Fatalf("new quorum could not advance after rotation: %v", err)
	}
}

func TestQuorumRotationPlanRejectsInsufficientStableOverlap(t *testing.T) {
	oldBinding := quorumBindingForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	newBinding := quorumBindingForTest(
		t,
		2,
		"witness-c",
		"witness-d",
		"witness-e",
	)
	oldEpoch, err := NewGovernedQuorumEpoch(
		oldBinding,
		21,
		sha256Digest([]byte("genesis-21")),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch, err := NewGovernedQuorumEpoch(
		newBinding,
		22,
		sha256Digest([]byte("genesis-22")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQuorumRotationPlan(oldEpoch, newEpoch); !errors.Is(
		err,
		ErrQuorumRotationUnsafe,
	) {
		t.Fatalf("unsafe one-member overlap = %v, want %v", err, ErrQuorumRotationUnsafe)
	}
}

func TestQuorumRotationPhaseOneInterruptionIsRetryableAndNeverEnablesNew(t *testing.T) {
	plan, oldStore, newStore, stores, head := governedRotationFixture(t)
	ctx := context.Background()
	stores["witness-c"].failJoint = 1

	if _, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	); err == nil {
		t.Fatal("phase-one interruption unexpectedly reported success")
	}

	if _, err := oldStore.Load(ctx, head.JournalID); err != nil {
		t.Fatalf("old quorum should remain possible before all blockers freeze: %v", err)
	}
	if _, err := newStore.Load(ctx, head.JournalID); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("new quorum became possible during partial phase one: %v", err)
	}

	if _, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	); err != nil {
		t.Fatalf("phase-one retry failed: %v", err)
	}
}

func TestQuorumRotationPhaseTwoInterruptionLeavesOldDeadAndRetryable(t *testing.T) {
	plan, oldStore, newStore, stores, head := governedRotationFixture(t)
	ctx := context.Background()
	stores["witness-c"].failActiveHash = plan.newEpoch.binding.policyHash
	stores["witness-c"].failActive = 1

	if _, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	); err == nil {
		t.Fatal("phase-two interruption unexpectedly reported success")
	}

	if _, err := oldStore.Load(ctx, head.JournalID); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("old quorum resurrected after joint freeze: %v", err)
	}
	// B + D can already form the new quorum after B enters NEW. This is safe
	// because every old quorum was killed before phase two began.
	if got, err := newStore.Load(ctx, head.JournalID); err != nil ||
		!sameSemanticHead(got, head) {
		t.Fatalf("new quorum was not safely available after partial phase two: head=%+v err=%v", got, err)
	}

	if _, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	); err != nil {
		t.Fatalf("phase-two retry failed: %v", err)
	}
}

func TestQuorumRotationRejectsPreexistingOldNewSplit(t *testing.T) {
	plan, oldStore, newStore, stores, head := governedRotationFixture(t)
	ctx := context.Background()
	stores["witness-b"].setPolicy(plan.newEpoch.activePolicy())

	if _, err := oldStore.Load(ctx, head.JournalID); err != nil {
		t.Fatalf("old A+C quorum should still exist in split setup: %v", err)
	}
	if _, err := newStore.Load(ctx, head.JournalID); err != nil {
		t.Fatalf("new B+D quorum should exist in split setup: %v", err)
	}
	if _, err := ExecuteQuorumRotation(
		ctx,
		plan,
		oldStore,
		newStore,
		head.JournalID,
	); !errors.Is(err, ErrQuorumRotationAmbiguous) {
		t.Fatalf("preexisting split = %v, want %v", err, ErrQuorumRotationAmbiguous)
	}
}

func TestQuorumPolicyTransitionForbidsDirectOldToNewAndRollback(t *testing.T) {
	old := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 7,
		PolicyHash:   sha256Digest([]byte("old")),
	}
	newState := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 8,
		PolicyHash:   sha256Digest([]byte("new")),
	}
	if err := ValidateQuorumPolicyTransition(old, newState); err == nil {
		t.Fatal("direct OLD -> NEW policy transition unexpectedly accepted")
	}

	joint := QuorumPolicyState{
		Phase:          QuorumPolicyPhaseJoint,
		GenesisEpoch:   8,
		PolicyHash:     sha256Digest([]byte("transition")),
		FromPolicyHash: old.PolicyHash,
		ToPolicyHash:   newState.PolicyHash,
	}
	if err := ValidateQuorumPolicyTransition(old, joint); err != nil {
		t.Fatalf("OLD -> JOINT rejected: %v", err)
	}
	if err := ValidateQuorumPolicyTransition(joint, newState); err != nil {
		t.Fatalf("JOINT -> NEW rejected: %v", err)
	}
	if err := ValidateQuorumPolicyTransition(newState, old); err == nil {
		t.Fatal("NEW -> OLD rollback unexpectedly accepted")
	}
}
