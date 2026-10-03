package server

import (
	"context"
	"errors"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/journal"
)

func capabilityRootTestCommitment(seed string) string {
	return "sha256:" + seed + "00000000000000000000000000000000000000000000000000000000"
}

func TestExternalHeadCapabilityRootAnchorInitializesAndAdvances(t *testing.T) {
	store := journal.NewMemoryHeadStore()
	anchor, err := NewExternalHeadCapabilityRootAnchor(store, "capability-root-test")
	if err != nil {
		t.Fatal(err)
	}

	current, err := anchor.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != (CapabilityRootAnchorState{}) {
		t.Fatalf("initial current = %+v, want zero state", current)
	}

	next := CapabilityRootAnchorState{
		Sequence:   1,
		Commitment: capabilityRootTestCommitment("aaaaaaaa"),
	}
	got, err := anchor.Advance(context.Background(), CapabilityRootAnchorState{}, next)
	if err != nil {
		t.Fatal(err)
	}
	if got != next {
		t.Fatalf("advance = %+v, want %+v", got, next)
	}

	current, err = anchor.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != next {
		t.Fatalf("current = %+v, want %+v", current, next)
	}

	head, err := store.Load(context.Background(), "capability-root-test")
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != next.Sequence ||
		head.HeadHash != next.Commitment ||
		head.KeyID != capabilityRootExternalHeadKeyID {
		t.Fatalf("unexpected external head: %+v", head)
	}
}

func TestExternalHeadCapabilityRootAnchorRejectsStaleExpectedState(t *testing.T) {
	store := journal.NewMemoryHeadStore()
	anchor, err := NewExternalHeadCapabilityRootAnchor(store, "capability-root-stale")
	if err != nil {
		t.Fatal(err)
	}

	t1 := CapabilityRootAnchorState{
		Sequence:   1,
		Commitment: capabilityRootTestCommitment("11111111"),
	}
	if _, err := anchor.Advance(context.Background(), CapabilityRootAnchorState{}, t1); err != nil {
		t.Fatal(err)
	}

	t2 := CapabilityRootAnchorState{
		Sequence:   2,
		Commitment: capabilityRootTestCommitment("22222222"),
	}
	if _, err := anchor.Advance(context.Background(), CapabilityRootAnchorState{}, t2); !errors.Is(err, ErrCapabilityRootAnchorMismatch) {
		t.Fatalf("stale expected error = %v, want %v", err, ErrCapabilityRootAnchorMismatch)
	}

	current, err := anchor.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != t1 {
		t.Fatalf("stale advance changed protected head: got %+v want %+v", current, t1)
	}
}

func TestExternalHeadCapabilityRootAnchorRejectsUnexpectedHeadIdentity(t *testing.T) {
	store := journal.NewMemoryHeadStore()
	rootID := "capability-root-identity"

	zero := journal.ExternalHead{
		JournalID: rootID,
		Sequence:  0,
		KeyID:     "wrong-key-id",
	}
	if _, err := store.CompareAndAdvance(context.Background(), journal.ExternalHead{}, zero); err != nil {
		t.Fatal(err)
	}

	anchor, err := NewExternalHeadCapabilityRootAnchor(store, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.Current(context.Background()); !errors.Is(err, ErrCapabilityRootAnchorMismatch) {
		t.Fatalf("identity mismatch error = %v, want %v", err, ErrCapabilityRootAnchorMismatch)
	}
}

func TestExternalHeadCapabilityRootAnchorRejectsNonDigestCommitment(t *testing.T) {
	store := journal.NewMemoryHeadStore()
	anchor, err := NewExternalHeadCapabilityRootAnchor(store, "capability-root-invalid")
	if err != nil {
		t.Fatal(err)
	}

	next := CapabilityRootAnchorState{
		Sequence:   1,
		Commitment: "not-a-digest",
	}
	if _, err := anchor.Advance(context.Background(), CapabilityRootAnchorState{}, next); !errors.Is(err, ErrCapabilityRootAnchorMismatch) {
		t.Fatalf("invalid commitment error = %v, want %v", err, ErrCapabilityRootAnchorMismatch)
	}
}
