package journal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type quorumTestStore struct {
	mu         sync.Mutex
	head       ExternalHead
	exists     bool
	revision   int
	loadErr    error
	advanceErr error
}

func newQuorumTestStore(head *ExternalHead) *quorumTestStore {
	store := &quorumTestStore{}
	if head != nil {
		store.exists = true
		store.revision = 1
		store.head = *head
		if store.head.StoreVersion == "" {
			store.head.StoreVersion = "v1"
		}
	}
	return store
}

func (s *quorumTestStore) Load(ctx context.Context, journalID string) (ExternalHead, error) {
	if err := ctx.Err(); err != nil {
		return ExternalHead{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return ExternalHead{}, s.loadErr
	}
	if !s.exists {
		return ExternalHead{}, ErrExternalHeadNotFound
	}
	if s.head.JournalID != journalID {
		return ExternalHead{}, ErrExternalHeadNotFound
	}
	return s.head, nil
}

func (s *quorumTestStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if err := ctx.Err(); err != nil {
		return ExternalHead{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.advanceErr != nil {
		return ExternalHead{}, s.advanceErr
	}
	if !s.exists {
		if previous.JournalID != "" || previous.Sequence != 0 ||
			previous.HeadHash != "" || previous.KeyID != "" ||
			previous.StoreVersion != "" || next.Sequence != 0 {
			return ExternalHead{}, ErrExternalHeadConflict
		}
		s.revision++
		next.StoreVersion = fmt.Sprintf("v%d", s.revision)
		s.head = next
		s.exists = true
		return s.head, nil
	}
	if !sameSemanticHead(previous, s.head) ||
		previous.StoreVersion != s.head.StoreVersion {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if next.Sequence < s.head.Sequence {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if next.Sequence == s.head.Sequence &&
		(next.HeadHash != s.head.HeadHash || next.KeyID != s.head.KeyID) {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	s.revision++
	next.StoreVersion = fmt.Sprintf("v%d", s.revision)
	s.head = next
	return s.head, nil
}

func (s *quorumTestStore) snapshot() (ExternalHead, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head, s.exists
}

func (s *quorumTestStore) setAdvanceErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advanceErr = err
}

func quorumTestHead(sequence uint64, hashByte string) ExternalHead {
	return ExternalHead{
		JournalID: "capability-root",
		Sequence:  sequence,
		HeadHash:  strings.Repeat(hashByte, 64),
		KeyID:     "aegis-ege/capability-root-head/v1",
	}
}

func quorumStoreForTest(
	t *testing.T,
	a ExternalHeadStore,
	b ExternalHeadStore,
	c ExternalHeadStore,
) *QuorumHeadStore {
	t.Helper()
	store, err := NewQuorumHeadStore([]QuorumHeadMember{
		{ID: "witness-a", Store: a},
		{ID: "witness-b", Store: b},
		{ID: "witness-c", Store: c},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestQuorumHeadStoreRequiresStrictMajority(t *testing.T) {
	base := newQuorumTestStore(nil)
	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		{ID: "a", Store: base},
		{ID: "b", Store: base},
		{ID: "c", Store: base},
	}, 1); err == nil {
		t.Fatal("1-of-3 quorum unexpectedly accepted")
	}
	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		{ID: "a", Store: base},
		{ID: "b", Store: base},
		{ID: "c", Store: base},
		{ID: "d", Store: base},
	}, 2); err == nil {
		t.Fatal("2-of-4 non-intersecting quorum unexpectedly accepted")
	}
	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		{ID: "a", Store: base},
		{ID: "a", Store: base},
		{ID: "c", Store: base},
	}, 2); err == nil {
		t.Fatal("duplicate witness identity unexpectedly accepted")
	}
	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		{ID: "a", Store: base},
		{ID: "b", Store: base},
		{ID: "c", Store: base},
	}, 2); err != nil {
		t.Fatalf("2-of-3 quorum rejected: %v", err)
	}
}

func TestQuorumHeadStoreOneWitnessCannotInventHigherTruth(t *testing.T) {
	honest := quorumTestHead(2, "a")
	forged := quorumTestHead(99, "f")
	a := newQuorumTestStore(&honest)
	b := newQuorumTestStore(&honest)
	c := newQuorumTestStore(&forged)
	store := quorumStoreForTest(t, a, b, c)

	head, err := store.Load(context.Background(), "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(head, honest) {
		t.Fatalf("quorum selected %+v, want honest majority %+v", head, honest)
	}
	if !strings.HasPrefix(head.StoreVersion, quorumHeadStoreVersion+":") {
		t.Fatalf("aggregate store version %q does not contain quorum vector", head.StoreVersion)
	}
}

func TestQuorumHeadStoreToleratesOneUnavailableWitness(t *testing.T) {
	current := quorumTestHead(4, "b")
	a := newQuorumTestStore(&current)
	b := newQuorumTestStore(&current)
	c := newQuorumTestStore(nil)
	c.loadErr = errors.New("witness unavailable")
	store := quorumStoreForTest(t, a, b, c)

	head, err := store.Load(context.Background(), "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(head, current) {
		t.Fatalf("quorum selected %+v, want %+v", head, current)
	}
}

func TestQuorumHeadStoreFailsClosedWithoutAgreement(t *testing.T) {
	aHead := quorumTestHead(5, "a")
	bHead := quorumTestHead(6, "b")
	a := newQuorumTestStore(&aHead)
	b := newQuorumTestStore(&bHead)
	c := newQuorumTestStore(nil)
	c.loadErr = errors.New("witness unavailable")
	store := quorumStoreForTest(t, a, b, c)

	if _, err := store.Load(context.Background(), "capability-root"); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("Load split witness state = %v, want %v", err, ErrExternalHeadQuorum)
	}
}

func TestQuorumHeadStoreAdvancesOnlyAfterTwoOfThree(t *testing.T) {
	current := quorumTestHead(8, "c")
	forged := quorumTestHead(42, "f")
	a := newQuorumTestStore(&current)
	b := newQuorumTestStore(&current)
	c := newQuorumTestStore(&forged)
	store := quorumStoreForTest(t, a, b, c)

	previous, err := store.Load(context.Background(), "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	next := quorumTestHead(9, "d")
	advanced, err := store.CompareAndAdvance(context.Background(), previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(advanced, next) {
		t.Fatalf("advanced head = %+v, want %+v", advanced, next)
	}

	aHead, _ := a.snapshot()
	bHead, _ := b.snapshot()
	cHead, _ := c.snapshot()
	if !sameSemanticHead(aHead, next) || !sameSemanticHead(bHead, next) {
		t.Fatalf("honest quorum did not advance: a=%+v b=%+v", aHead, bHead)
	}
	if !sameSemanticHead(cHead, forged) {
		t.Fatalf("divergent witness unexpectedly defined quorum truth: %+v", cHead)
	}
}

func TestQuorumHeadStorePartialAdvanceDoesNotBecomeTruth(t *testing.T) {
	current := quorumTestHead(11, "a")
	next := quorumTestHead(12, "b")
	a := newQuorumTestStore(&current)
	b := newQuorumTestStore(&current)
	c := newQuorumTestStore(&current)
	b.setAdvanceErr(errors.New("write unavailable"))
	c.setAdvanceErr(errors.New("write unavailable"))
	store := quorumStoreForTest(t, a, b, c)

	previous, err := store.Load(context.Background(), "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndAdvance(context.Background(), previous, next); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("partial advance = %v, want %v", err, ErrExternalHeadQuorum)
	}

	stillCurrent, err := store.Load(context.Background(), "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(stillCurrent, current) {
		t.Fatalf("single-member partial write became quorum truth: %+v", stillCurrent)
	}

	b.setAdvanceErr(nil)
	c.setAdvanceErr(nil)
	recovered, err := store.CompareAndAdvance(context.Background(), stillCurrent, next)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(recovered, next) {
		t.Fatalf("recovered head = %+v, want %+v", recovered, next)
	}
}

func TestQuorumHeadStoreInitializesAbsentMajority(t *testing.T) {
	a := newQuorumTestStore(nil)
	b := newQuorumTestStore(nil)
	c := newQuorumTestStore(nil)
	store := quorumStoreForTest(t, a, b, c)

	if _, err := store.Load(context.Background(), "capability-root"); !errors.Is(err, ErrExternalHeadNotFound) {
		t.Fatalf("Load absent quorum = %v, want %v", err, ErrExternalHeadNotFound)
	}
	zero := ExternalHead{
		JournalID: "capability-root",
		Sequence:  0,
		KeyID:     "aegis-ege/capability-root-head/v1",
	}
	initialized, err := store.CompareAndAdvance(context.Background(), ExternalHead{}, zero)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(initialized, zero) {
		t.Fatalf("initialized head = %+v, want %+v", initialized, zero)
	}
}
