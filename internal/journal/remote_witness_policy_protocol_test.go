package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
)

type memoryGovernedWitnessStateStore struct {
	mu      sync.Mutex
	exists  bool
	version uint64
	state   GovernedWitnessState
}

func (s *memoryGovernedWitnessStateStore) Load(
	ctx context.Context,
) (GovernedWitnessState, error) {
	if err := ctx.Err(); err != nil {
		return GovernedWitnessState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists {
		return GovernedWitnessState{}, ErrGovernedWitnessStateNotFound
	}
	return cloneMemoryGovernedWitnessState(s.state, s.version), nil
}

func (s *memoryGovernedWitnessStateStore) CompareAndSwap(
	ctx context.Context,
	expectedVersion string,
	next GovernedWitnessState,
) (GovernedWitnessState, error) {
	if err := ctx.Err(); err != nil {
		return GovernedWitnessState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentVersion := ""
	if s.exists {
		currentVersion = fmt.Sprintf("rv-%d", s.version)
	}
	if currentVersion != expectedVersion {
		return GovernedWitnessState{}, ErrGovernedWitnessStateConflict
	}
	if err := validateGovernedWitnessState(next); err != nil {
		return GovernedWitnessState{}, err
	}
	s.version++
	s.exists = true
	s.state = cloneMemoryGovernedWitnessState(next, 0)
	s.state.StoreVersion = ""
	return cloneMemoryGovernedWitnessState(s.state, s.version), nil
}

func cloneMemoryGovernedWitnessState(
	state GovernedWitnessState,
	version uint64,
) GovernedWitnessState {
	cloned := state
	cloned.Heads = make(map[string]ExternalHead, len(state.Heads))
	storeVersion := ""
	if version != 0 {
		storeVersion = fmt.Sprintf("rv-%d", version)
	}
	cloned.StoreVersion = storeVersion
	for id, head := range state.Heads {
		head.StoreVersion = storeVersion
		cloned.Heads[id] = head
	}
	return cloned
}

type remoteGovernedWitnessFixture struct {
	state  *memoryGovernedWitnessStateStore
	remote *RemoteHeadStore
	server *httptest.Server
}

func newRemoteGovernedWitnessFixture(
	t *testing.T,
	id string,
	policy QuorumPolicyState,
	head ExternalHead,
) *remoteGovernedWitnessFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateStore := &memoryGovernedWitnessStateStore{}
	if _, err := stateStore.CompareAndSwap(
		context.Background(),
		"",
		GovernedWitnessState{
			Protocol: GovernedWitnessStateVersion,
			Policy:   policy,
			Heads: map[string]ExternalHead{
				head.JournalID: head,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	handler, err := NewGovernedRemoteWitnessHandler(
		stateStore,
		"runtime-key/"+id,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	remote, err := NewRemoteHeadStore(
		server.URL,
		"runtime-key/"+id,
		publicKey,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	remote.trustManifestHash = quorumTrustHashForTest(id)
	return &remoteGovernedWitnessFixture{
		state:  stateStore,
		remote: remote,
		server: server,
	}
}

func bumpRemoteGovernedWitnessVersion(
	t *testing.T,
	fixture *remoteGovernedWitnessFixture,
) {
	t.Helper()
	ctx := context.Background()
	state, err := fixture.state.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.state.CompareAndSwap(
		ctx,
		state.StoreVersion,
		state,
	); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteWitnessGovernedRotationFencesStaleGenesisClient(t *testing.T) {
	ctx := context.Background()
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
		31,
		sha256Digest([]byte("remote-genesis-31")),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch, err := NewGovernedQuorumEpoch(
		newBinding,
		32,
		sha256Digest([]byte("remote-genesis-32")),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewQuorumRotationPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}

	head := quorumTestHead(23, "d")
	a := newRemoteGovernedWitnessFixture(
		t,
		"witness-a",
		oldEpoch.activePolicy(),
		head,
	)
	b := newRemoteGovernedWitnessFixture(
		t,
		"witness-b",
		oldEpoch.activePolicy(),
		head,
	)
	c := newRemoteGovernedWitnessFixture(
		t,
		"witness-c",
		oldEpoch.activePolicy(),
		head,
	)
	d := newRemoteGovernedWitnessFixture(
		t,
		"witness-d",
		newEpoch.activePolicy(),
		head,
	)

	// Give B a different server-side CAS generation from C. Rotation must use
	// each witness's own observed version rather than copying one CAS token to
	// all shared witnesses.
	bumpRemoteGovernedWitnessVersion(t, b)
	bumpRemoteGovernedWitnessVersion(t, b)

	oldStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-a", Store: a.remote},
			{ID: "witness-b", Store: b.remote},
			{ID: "witness-c", Store: c.remote},
		},
		oldBinding,
		oldEpoch.genesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-b", Store: b.remote},
			{ID: "witness-c", Store: c.remote},
			{ID: "witness-d", Store: d.remote},
		},
		newBinding,
		newEpoch.genesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := oldStore.Load(ctx, head.JournalID); err != nil ||
		!sameSemanticHead(got, head) {
		t.Fatalf("old remote quorum not authoritative: head=%+v err=%v", got, err)
	}
	if _, err := newStore.Load(ctx, head.JournalID); !errors.Is(
		err,
		ErrExternalHeadQuorum,
	) {
		t.Fatalf("new remote quorum became authoritative early: %v", err)
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
		t.Fatalf("rotated remote head = %+v, want %+v", result.Head, head)
	}

	if _, err := oldStore.Load(ctx, head.JournalID); !errors.Is(
		err,
		ErrExternalHeadQuorum,
	) {
		t.Fatalf("retired remote OLD quorum remained usable: %v", err)
	}
	if got, err := newStore.Load(ctx, head.JournalID); err != nil ||
		!sameSemanticHead(got, head) {
		t.Fatalf("remote NEW quorum missing exact head: head=%+v err=%v", got, err)
	}

	if _, err := b.remote.LoadForQuorum(
		ctx,
		head.JournalID,
		oldEpoch.activePolicy(),
	); !errors.Is(err, ErrQuorumPolicyMismatch) {
		t.Fatalf("stale Genesis client load = %v, want policy mismatch", err)
	}

	staleNext := quorumTestHead(head.Sequence+1, "e")
	if _, err := b.remote.CompareAndAdvanceForQuorum(
		ctx,
		oldEpoch.activePolicy(),
		head,
		staleNext,
	); !errors.Is(err, ErrQuorumPolicyMismatch) {
		t.Fatalf("stale Genesis client advance = %v, want policy mismatch", err)
	}

	// Raw pre-governance protocol calls cannot silently bypass policy fencing.
	if _, err := b.remote.Load(ctx, head.JournalID); err == nil {
		t.Fatal("raw remote load bypassed governed witness policy")
	}

	previous, err := newStore.Load(ctx, head.JournalID)
	if err != nil {
		t.Fatal(err)
	}
	next := quorumTestHead(head.Sequence+1, "f")
	if _, err := newStore.CompareAndAdvance(ctx, previous, next); err != nil {
		t.Fatalf("NEW remote quorum could not advance: %v", err)
	}
}

func TestRemoteWitnessTransitionRefusesHeadChangedAfterObservation(t *testing.T) {
	ctx := context.Background()
	old := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 41,
		PolicyHash:   sha256Digest([]byte("remote-old")),
	}
	joint := QuorumPolicyState{
		Phase:          QuorumPolicyPhaseJoint,
		GenesisEpoch:   42,
		PolicyHash:     sha256Digest([]byte("remote-transition")),
		FromPolicyHash: old.PolicyHash,
		ToPolicyHash:   sha256Digest([]byte("remote-new")),
	}
	head := quorumTestHead(8, "a")
	fixture := newRemoteGovernedWitnessFixture(
		t,
		"witness-head-change",
		old,
		head,
	)

	observed, err := fixture.remote.ObserveQuorumRotationHead(
		ctx,
		head.JournalID,
	)
	if err != nil {
		t.Fatal(err)
	}

	state, err := fixture.state.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := quorumTestHead(head.Sequence+1, "b")
	state.Heads[head.JournalID] = changed
	if _, err := fixture.state.CompareAndSwap(
		ctx,
		state.StoreVersion,
		state,
	); err != nil {
		t.Fatal(err)
	}

	if err := fixture.remote.CompareAndTransitionQuorumPolicy(
		ctx,
		old,
		joint,
		head.JournalID,
		observed,
	); !errors.Is(err, ErrQuorumRotationContinuity) {
		t.Fatalf(
			"transition over changed head = %v, want continuity failure",
			err,
		)
	}
	current, err := fixture.remote.CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current != old {
		t.Fatalf("policy changed despite head race: %+v", current)
	}
}

func TestGovernedRemoteWitnessRejectsDirectPolicyReplacement(t *testing.T) {
	ctx := context.Background()
	old := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 51,
		PolicyHash:   sha256Digest([]byte("policy-51")),
	}
	newPolicy := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 52,
		PolicyHash:   sha256Digest([]byte("policy-52")),
	}
	head := quorumTestHead(4, "c")
	fixture := newRemoteGovernedWitnessFixture(
		t,
		"witness-direct",
		old,
		head,
	)

	if err := fixture.remote.CompareAndTransitionQuorumPolicy(
		ctx,
		old,
		newPolicy,
		head.JournalID,
		head,
	); err == nil {
		t.Fatal("direct OLD -> NEW remote policy replacement was accepted")
	}
	current, err := fixture.remote.CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current != old {
		t.Fatalf("direct replacement mutated witness policy: %+v", current)
	}
}

func TestInitializeGovernedWitnessStateRejectsStartupPolicyRollback(t *testing.T) {
	ctx := context.Background()
	store := &memoryGovernedWitnessStateStore{}
	current := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 62,
		PolicyHash:   sha256Digest([]byte("current-policy")),
	}
	if _, err := InitializeGovernedWitnessState(
		ctx,
		store,
		current,
	); err != nil {
		t.Fatal(err)
	}
	stale := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 61,
		PolicyHash:   sha256Digest([]byte("stale-policy")),
	}
	if _, err := InitializeGovernedWitnessState(
		ctx,
		store,
		stale,
	); !errors.Is(err, ErrQuorumPolicyMismatch) {
		t.Fatalf("startup policy rollback = %v, want mismatch", err)
	}
}
