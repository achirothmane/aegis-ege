//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMNVRootBlocksEffectAfterMutableAndCompanionRollback(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A125),
		StatePath: filepath.Join(t.TempDir(), "root.json"),
		IndexAuth: []byte("aegis-root-test"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report: kubeadapter.GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
		},
	}
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(
		controller,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			MutationsEnabled:         true,
			RequireAuthentication:    true,
			Authorizer:               allowAuthorizer{},
			ReplayGuard:              replay,
			RequireCapabilityFencing: true,
			CapabilityFenceAuthority: authority,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	permitT1 := prepareRootedCapabilityPermit(t, srv)
	stateAtT1, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	t2Issue := t1Issue
	t2Issue.DecisionEpoch++
	t2 := capabilityAuthoritySnapshotFromIssue(t2Issue)
	mutable.issue = t2Issue
	mutable.coordination = t2
	mutable.witness = t2
	_ = prepareRootedCapabilityPermit(t, srv)

	mutable.issue = t1Issue
	mutable.coordination = t1
	mutable.witness = t1
	if err := os.WriteFile(cfg.StatePath, stateAtT1, 0o600); err != nil {
		t.Fatal(err)
	}

	recorder := executeRootedCapabilityPermit(t, srv, permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected rollback denial 409, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_ROOT_ROLLBACK_DETECTED") {
		t.Fatalf("unexpected rollback denial: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("rollback schedule reached mutation controller %d times", controller.executeCalls)
	}

	scope := CapabilityFenceScope{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
	}
	if _, err := root.Current(context.Background(), scope); !errors.Is(err, ErrTPMMonotonicRootRollback) {
		t.Fatalf("expected TPM rollback evidence, got %v", err)
	}
}

func TestTPMNVCounterDeleteRedefineCannotRestoreOldGeneration(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A126),
		StatePath: filepath.Join(dir, "root.json"),
		IndexAuth: []byte("aegis-root-test"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	scope := CapabilityFenceScope{
		IntentID: "intent-delete-redefine",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
	}
	t1 := egeproto.CapabilityAuthoritySnapshot{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t2 := t1
	t2.DecisionEpoch++
	if _, err := root.Advance(context.Background(), scope, t1); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Advance(context.Background(), scope, t2); err != nil {
		t.Fatal(err)
	}
	oldCounter, err := root.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	public, err := root.readNVPublic()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(cfg.OwnerAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: cfg.NVIndex,
			Name:   public.NVName,
		},
	}).Execute(device); err != nil {
		t.Fatalf("undefine TPM counter: %v", err)
	}

	redefined := cfg
	redefined.StatePath = filepath.Join(dir, "redefined.json")
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, redefined); err != nil {
		t.Fatalf("redefine TPM counter: %v", err)
	}
	newRoot, err := NewTPMNVMonotonicRoot(device, redefined)
	if err != nil {
		t.Fatal(err)
	}
	newCounter, err := newRoot.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if newCounter <= oldCounter {
		t.Fatalf("redefined TPM counter repeated/regressed: old=%d new=%d", oldCounter, newCounter)
	}

	if _, err := root.Current(context.Background(), scope); !errors.Is(err, ErrTPMMonotonicRootRollback) {
		t.Fatalf("expected old companion state to fail closed after delete/redefine, got %v", err)
	}
}
