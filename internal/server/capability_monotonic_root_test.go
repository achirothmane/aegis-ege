package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

type dualMutableCapabilityFenceAuthority struct {
	issue        CapabilityFenceIssue
	coordination egeproto.CapabilityAuthoritySnapshot
	witness      egeproto.CapabilityAuthoritySnapshot
}

func (a *dualMutableCapabilityFenceAuthority) Issue(
	context.Context,
	CapabilityFenceScope,
) (CapabilityFenceIssue, error) {
	return a.issue, nil
}

func (a *dualMutableCapabilityFenceAuthority) Current(
	context.Context,
	CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	if a.coordination != a.witness {
		return egeproto.CapabilityAuthoritySnapshot{}, errors.New("mutable coordination and witness disagree")
	}
	return a.coordination, nil
}

type testCapabilityMonotonicRoot struct {
	mu          sync.Mutex
	initialized bool
	current     egeproto.CapabilityAuthoritySnapshot
}

func (r *testCapabilityMonotonicRoot) Advance(
	_ context.Context,
	_ CapabilityFenceScope,
	observed egeproto.CapabilityAuthoritySnapshot,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.initialized {
		if err := validateCapabilityAuthoritySnapshot(observed); err != nil {
			return egeproto.CapabilityAuthoritySnapshot{}, err
		}
		r.current = observed
		r.initialized = true
		return r.current, nil
	}

	relation, err := compareCapabilityMonotonicRoot(r.current, observed)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	switch relation {
	case capabilityRootEqual, capabilityRootAhead:
		// The root never regresses.
		return r.current, nil
	case capabilityRootBehind:
		r.current = observed
		return r.current, nil
	default:
		return egeproto.CapabilityAuthoritySnapshot{}, ErrCapabilityMonotonicRootInvalid
	}
}

func (r *testCapabilityMonotonicRoot) Current(
	context.Context,
	CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.initialized {
		return egeproto.CapabilityAuthoritySnapshot{}, errors.New("monotonic root is not initialized")
	}
	return r.current, nil
}

func TestEGEIndependentMonotonicRootRejectsCoordinatedRollback(t *testing.T) {
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
	root := &testCapabilityMonotonicRoot{}
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

	t2Issue := t1Issue
	t2Issue.DecisionEpoch++
	t2 := capabilityAuthoritySnapshotFromIssue(t2Issue)
	mutable.issue = t2Issue
	mutable.coordination = t2
	mutable.witness = t2

	permitT2 := prepareRootedCapabilityPermit(t, srv)
	rootAtT2, err := root.Current(context.Background(), CapabilityFenceScope{})
	if err != nil {
		t.Fatal(err)
	}
	if rootAtT2 != t2 {
		t.Fatalf("independent root did not advance to T2: got=%+v want=%+v", rootAtT2, t2)
	}

	// Coordinated rollback: both mutable views are restored to the previously
	// valid T1. The independent root deliberately remains at T2.
	mutable.coordination = t1
	mutable.witness = t1

	oldRecorder := executeRootedCapabilityPermit(t, srv, permitT1)
	if oldRecorder.Code != http.StatusConflict {
		t.Fatalf("old T1 expected 409, got %d body=%s", oldRecorder.Code, oldRecorder.Body.String())
	}
	if !strings.Contains(oldRecorder.Body.String(), "CAPABILITY_DECISION_SUPERSEDED") {
		t.Fatalf("unexpected rollback denial: %s", oldRecorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("coordinated mutable rollback reached mutation controller %d times", controller.executeCalls)
	}

	// Convergence is allowed only when mutable coordination catches up to the
	// independent root again.
	mutable.coordination = t2
	mutable.witness = t2

	currentRecorder := executeRootedCapabilityPermit(t, srv, permitT2)
	if currentRecorder.Code != http.StatusOK {
		t.Fatalf("converged T2 expected 200, got %d body=%s", currentRecorder.Code, currentRecorder.Body.String())
	}
	if controller.executeCalls != 1 {
		t.Fatalf("expected exactly one mutation-controller call after convergence, got %d", controller.executeCalls)
	}
}

func TestIndependentMonotonicRootRefusesSupersededReissue(t *testing.T) {
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t2 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	t2.DecisionEpoch++

	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: capabilityAuthoritySnapshotFromIssue(t1Issue),
		witness:      capabilityAuthoritySnapshotFromIssue(t1Issue),
	}
	root := &testCapabilityMonotonicRoot{}
	if _, err := root.Advance(context.Background(), CapabilityFenceScope{}, t2); err != nil {
		t.Fatal(err)
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authority.Issue(context.Background(), CapabilityFenceScope{}); !errors.Is(err, egeproto.ErrCapabilityDecisionSuperseded) {
		t.Fatalf("expected superseded reissue rejection, got %v", err)
	}
	current, err := root.Current(context.Background(), CapabilityFenceScope{})
	if err != nil {
		t.Fatal(err)
	}
	if current != t2 {
		t.Fatalf("superseded reissue regressed root: got=%+v want=%+v", current, t2)
	}
}

func prepareRootedCapabilityPermit(t *testing.T, srv *Server) egeproto.Permit {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-cap-1",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"}
		}`),
	)
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("prepare expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	var response egePrepareResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Permit == nil {
		t.Fatal("prepare did not return permit")
	}
	return *response.Permit
}

func executeRootedCapabilityPermit(
	t *testing.T,
	srv *Server,
	permit egeproto.Permit,
) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	return recorder
}
