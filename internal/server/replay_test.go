package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestFileReplayGuardRejectsSecondClaimAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	guard, err := NewFileReplayGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	auth := decision.Authorization{
		ActionID: "act-1",
		Action: "drain",
		Target: "node/node-7",
		ResourceVersion: "100",
		EvidenceDigest: "sha256:evidence",
		PlanDigest: "sha256:plan",
		ValidUntil: time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
	}
	if err := guard.Claim(context.Background(), auth); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	if err := guard.Claim(context.Background(), auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("second claim should be replay, got %v", err)
	}

	reopened, err := NewFileReplayGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Claim(context.Background(), auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("replay must survive process reopen, got %v", err)
	}
}

func TestReplayKeyChangesWhenAuthorizationBindingChanges(t *testing.T) {
	base := decision.Authorization{
		ActionID: "act-1",
		Action: "drain",
		Target: "node/node-7",
		ResourceVersion: "100",
		EvidenceDigest: "sha256:evidence",
		PlanDigest: "sha256:plan",
		ValidUntil: time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
	}
	a, err := authorizationReplayKey(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.ResourceVersion = "101"
	b, err := authorizationReplayKey(changed)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("state-bound authorization change must change replay key")
	}
}


func TestReplayKeyChangesWhenCapabilityEpochChanges(t *testing.T) {
	base := decision.Authorization{
		ActionID:           "act-1",
		Action:             "drain",
		Target:             "node/node-7",
		ResourceVersion:    "100",
		EvidenceDigest:     "sha256:evidence",
		PlanDigest:         "sha256:plan",
		AuthorityDomain:    "cluster-a/control-plane",
		AuthorityTerm:      4,
		DecisionEpoch:      21,
		RevocationEpoch:    2,
		TargetIdentity:     "uid-7",
		StateBindingDigest: "sha256:state",
		ValidUntil:         time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
	}
	first, err := authorizationReplayKey(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.DecisionEpoch++
	second, err := authorizationReplayKey(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("decision epoch change must produce a distinct capability replay key")
	}
}

func TestReplayKeyChangesWhenAuthorityTermChanges(t *testing.T) {
	base := decision.Authorization{
		ActionID:           "act-1",
		Action:             "drain",
		Target:             "node/node-7",
		ResourceVersion:    "100",
		EvidenceDigest:     "sha256:evidence",
		PlanDigest:         "sha256:plan",
		AuthorityDomain:    "cluster-a/control-plane",
		AuthorityTerm:      4,
		DecisionEpoch:      21,
		RevocationEpoch:    2,
		TargetIdentity:     "uid-7",
		StateBindingDigest: "sha256:state",
		ValidUntil:         time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
	}
	first, err := authorizationReplayKey(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.AuthorityTerm++
	second, err := authorizationReplayKey(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("authority term change must produce a distinct capability replay key")
	}
}


func lifecycleTestAuthorization() decision.Authorization {
	return decision.Authorization{
		ActionID:           "cap-1",
		Action:             "drain",
		Target:             "node/node-7",
		ResourceVersion:    "100",
		EvidenceDigest:     "sha256:evidence",
		PlanDigest:         "sha256:plan",
		AuthorityDomain:    "cluster-a/control-plane",
		AuthorityTerm:      4,
		DecisionEpoch:      21,
		RevocationEpoch:    2,
		TargetIdentity:     "uid-7",
		StateBindingDigest: "sha256:state",
		ValidUntil:         time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC),
	}
}

func TestFileReplayGuardCapabilityLifecyclePersists(t *testing.T) {
	dir := t.TempDir()
	guard, err := NewFileReplayGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	auth := lifecycleTestAuthorization()
	ctx := context.Background()

	if err := guard.Issue(ctx, auth); err != nil {
		t.Fatalf("issue capability: %v", err)
	}
	record, err := guard.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimIssued {
		t.Fatalf("expected ISSUED, got %s", record.State)
	}

	if err := guard.Claim(ctx, auth); err != nil {
		t.Fatalf("claim capability: %v", err)
	}
	record, err = guard.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimClaimed {
		t.Fatalf("expected CLAIMED, got %s", record.State)
	}

	if err := guard.Consume(ctx, auth, "ALLOW"); err != nil {
		t.Fatalf("consume capability: %v", err)
	}
	record, err = guard.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimConsumed || record.Outcome != "ALLOW" {
		t.Fatalf("expected CONSUMED/ALLOW, got %+v", record)
	}

	reopened, err := NewFileReplayGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err = reopened.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimConsumed {
		t.Fatalf("terminal state did not survive reopen: %+v", record)
	}
	if err := reopened.Claim(ctx, auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("consumed capability must never be reusable, got %v", err)
	}
}

func TestFileReplayGuardAbortedCapabilityIsTerminal(t *testing.T) {
	guard, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := lifecycleTestAuthorization()
	auth.ActionID = "cap-abort"
	ctx := context.Background()

	if err := guard.Issue(ctx, auth); err != nil {
		t.Fatal(err)
	}
	if err := guard.Claim(ctx, auth); err != nil {
		t.Fatal(err)
	}
	if err := guard.Abort(ctx, auth, "mutation controller was never entered"); err != nil {
		t.Fatalf("abort capability: %v", err)
	}

	record, err := guard.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimAborted {
		t.Fatalf("expected ABORTED, got %+v", record)
	}
	if err := guard.Claim(ctx, auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("aborted capability must not reopen, got %v", err)
	}
	if err := guard.Consume(ctx, auth, "ALLOW"); !errors.Is(err, ErrExecutionClaimTransition) {
		t.Fatalf("ABORTED -> CONSUMED must be rejected, got %v", err)
	}
}


func TestFileReplayGuardAtomicClaimAllowsExactlyOneWinner(t *testing.T) {
	guard, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := lifecycleTestAuthorization()
	auth.ActionID = "cap-race"
	ctx := context.Background()
	if err := guard.Issue(ctx, auth); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	go func() { results <- guard.Claim(ctx, auth) }()
	go func() { results <- guard.Claim(ctx, auth) }()

	successes := 0
	replays := 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrExecutionReplay):
			replays++
		default:
			t.Fatalf("unexpected concurrent claim error: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("expected one winner and one replay rejection, got successes=%d replays=%d", successes, replays)
	}
}


func TestFileReplayGuardIssueIsIdempotentOnlyBeforeClaim(t *testing.T) {
	guard, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := lifecycleTestAuthorization()
	auth.ActionID = "cap-idempotent-issue"
	ctx := context.Background()

	if err := guard.Issue(ctx, auth); err != nil {
		t.Fatalf("first issue failed: %v", err)
	}
	if err := guard.Issue(ctx, auth); err != nil {
		t.Fatalf("identical unclaimed re-issue should be idempotent, got %v", err)
	}
	if err := guard.Claim(ctx, auth); err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if err := guard.Issue(ctx, auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("claimed capability must not be re-issued, got %v", err)
	}
}
