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
