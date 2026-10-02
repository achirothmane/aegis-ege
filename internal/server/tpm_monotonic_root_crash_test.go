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

type tpmRootCrashFixture struct {
	cfg        TPMNVMonotonicRootConfig
	root       *TPMNVMonotonicRoot
	authority  *IndependentRootCapabilityAuthority
	mutable    *dualMutableCapabilityFenceAuthority
	controller *fakeController
	srv        *Server
	permitT1   egeproto.Permit
	scope      CapabilityFenceScope
	t1         egeproto.CapabilityAuthoritySnapshot
	t2         egeproto.CapabilityAuthoritySnapshot
}

func newTPMRootCrashFixture(t *testing.T, index tpm2.TPMHandle) *tpmRootCrashFixture {
	t.Helper()

	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	device := transport.FromReadWriter(sim)

	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   index,
		StatePath: filepath.Join(t.TempDir(), "root.json"),
		IndexAuth: []byte("aegis-root-crash-test"),
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
	t2 := t1
	t2.DecisionEpoch++

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
	return &tpmRootCrashFixture{
		cfg:        cfg,
		root:       root,
		authority:  authority,
		mutable:    mutable,
		controller: controller,
		srv:        srv,
		permitT1:   permitT1,
		scope: CapabilityFenceScope{
			IntentID: "intent-cap-1",
			Kind:     egeNodeDrainKind,
			Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
		},
		t1: t1,
		t2: t2,
	}
}

func stageTPMRootPendingCrashState(
	t *testing.T,
	f *tpmRootCrashFixture,
	nextSnapshot egeproto.CapabilityAuthoritySnapshot,
) uint64 {
	t.Helper()

	committed, ok, err := readTPMNVRootState(f.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("committed TPM root state missing")
	}
	scopeKey, err := capabilityMonotonicScopeKey(f.scope)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneTPMNVRootState(committed)
	next.PreviousGeneration = committed.Generation
	next.Generation = committed.Generation + 1
	next.Scopes[scopeKey] = nextSnapshot
	if err := writeTPMNVRootStateAtomic(f.cfg.StatePath+".pending", next); err != nil {
		t.Fatal(err)
	}
	return next.Generation
}

func restartTPMRootAfterCrash(t *testing.T, f *tpmRootCrashFixture) *TPMNVMonotonicRoot {
	t.Helper()
	restarted, err := NewTPMNVMonotonicRoot(f.root.tpm, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.authority.Root = restarted
	return restarted
}

func TestTPMRootCrashBeforeIncrementDiscardsFuturePendingAndKeepsT1Executable(t *testing.T) {
	f := newTPMRootCrashFixture(t, tpm2.TPMHandle(0x0180A131))

	counterBefore, err := f.root.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stagedGeneration := stageTPMRootPendingCrashState(t, f, f.t2)
	if stagedGeneration != counterBefore+1 {
		t.Fatalf("unexpected staged generation: staged=%d counter=%d", stagedGeneration, counterBefore)
	}

	restarted := restartTPMRootAfterCrash(t, f)
	recorder := executeRootedCapabilityPermit(t, f.srv, f.permitT1)
	if recorder.Code != http.StatusOK {
		t.Fatalf("T1 should remain executable when TPM increment never happened: got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if f.controller.executeCalls != 1 {
		t.Fatalf("expected exactly one mutation after pre-increment crash recovery, got %d", f.controller.executeCalls)
	}
	if _, err := os.Stat(f.cfg.StatePath + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("future pending state was not discarded: %v", err)
	}
	counterAfter, err := restarted.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfter != counterBefore {
		t.Fatalf("pre-increment crash changed TPM generation: before=%d after=%d", counterBefore, counterAfter)
	}
	current, err := restarted.Current(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if current != f.t1 {
		t.Fatalf("pre-increment recovery changed committed authority: got=%+v want=%+v", current, f.t1)
	}
}

func TestTPMRootCrashAfterIncrementPromotesPendingAndKeepsT1Superseded(t *testing.T) {
	f := newTPMRootCrashFixture(t, tpm2.TPMHandle(0x0180A132))

	stagedGeneration := stageTPMRootPendingCrashState(t, f, f.t2)
	counterAfterIncrement, err := f.root.incrementCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfterIncrement != stagedGeneration {
		t.Fatalf("TPM increment did not reach pending generation: counter=%d pending=%d", counterAfterIncrement, stagedGeneration)
	}

	restarted := restartTPMRootAfterCrash(t, f)
	recorder := executeRootedCapabilityPermit(t, f.srv, f.permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("old T1 expected 409 after post-increment crash, got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_DECISION_SUPERSEDED") {
		t.Fatalf("unexpected post-increment denial: %s", recorder.Body.String())
	}
	if f.controller.executeCalls != 0 {
		t.Fatalf("superseded T1 reached mutation controller %d times", f.controller.executeCalls)
	}
	if _, err := os.Stat(f.cfg.StatePath + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("pending state was not promoted/cleared: %v", err)
	}
	current, err := restarted.Current(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if current != f.t2 {
		t.Fatalf("post-increment recovery did not promote T2: got=%+v want=%+v", current, f.t2)
	}
	committed, ok, err := readTPMNVRootState(f.cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read promoted state: ok=%t err=%v", ok, err)
	}
	if committed.Generation != stagedGeneration {
		t.Fatalf("promoted generation mismatch: got=%d want=%d", committed.Generation, stagedGeneration)
	}
}

func TestTPMRootCounterAheadWithLostPendingFailsClosedAtEffectBoundary(t *testing.T) {
	f := newTPMRootCrashFixture(t, tpm2.TPMHandle(0x0180A133))

	stagedGeneration := stageTPMRootPendingCrashState(t, f, f.t2)
	counterAfterIncrement, err := f.root.incrementCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfterIncrement != stagedGeneration {
		t.Fatalf("TPM increment did not reach pending generation: counter=%d pending=%d", counterAfterIncrement, stagedGeneration)
	}
	if err := os.Remove(f.cfg.StatePath + ".pending"); err != nil {
		t.Fatal(err)
	}

	restarted := restartTPMRootAfterCrash(t, f)
	recorder := executeRootedCapabilityPermit(t, f.srv, f.permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("lost pending expected 409, got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_ROOT_ROLLBACK_DETECTED") {
		t.Fatalf("unexpected lost-pending denial: %s", recorder.Body.String())
	}
	if f.controller.executeCalls != 0 {
		t.Fatalf("lost-pending state reached mutation controller %d times", f.controller.executeCalls)
	}
	if _, err := restarted.Current(context.Background(), f.scope); !errors.Is(err, ErrTPMMonotonicRootRollback) {
		t.Fatalf("expected rollback evidence when counter is ahead and pending is lost, got %v", err)
	}
}
