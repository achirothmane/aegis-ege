package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

type fakeCapabilityFenceAuthority struct {
	issue   CapabilityFenceIssue
	current egeproto.CapabilityAuthoritySnapshot
}

func (f *fakeCapabilityFenceAuthority) Issue(
	context.Context,
	CapabilityFenceScope,
) (CapabilityFenceIssue, error) {
	return f.issue, nil
}

func (f *fakeCapabilityFenceAuthority) Current(
	context.Context,
	CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	return f.current, nil
}

func capabilityTestPreparation(now time.Time) kubeadapter.NodeDrainPreparation {
	return kubeadapter.NodeDrainPreparation{
		Decision:   decision.Allow,
		PlanDigest: "sha256:plan",
		Snapshot: kubeadapter.NodeDrainSnapshot{
			NodeName:        "node-7",
			NodeUID:         "uid-node-7",
			ResourceVersion: "101",
			ObservedAt:      now,
		},
		Authorization: &decision.Authorization{
			ActionID:        "intent-cap-1",
			Action:          "drain",
			Target:          "node/node-7",
			ResourceVersion: "101",
			EvidenceDigest:  "sha256:evidence",
			PlanDigest:      "sha256:plan",
			ValidUntil:      now.Add(time.Minute),
		},
	}
}

func TestEGEPrepareBindsCapabilityFenceIntoSignedPermit(t *testing.T) {
	now := time.Now().UTC()
	controller := &fakeController{preparation: capabilityTestPreparation(now)}
	authority := &fakeCapabilityFenceAuthority{
		issue: CapabilityFenceIssue{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
		current: egeproto.CapabilityAuthoritySnapshot{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(controller, nil, Config{
		ReplayGuard:              replay,
		RequireCapabilityFencing: true,
		CapabilityFenceAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}

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
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	var body egePrepareResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Permit == nil || body.Permit.Claims.CapabilityFence == nil {
		t.Fatalf("expected signed capability fence, got %+v", body.Permit)
	}
	fence := body.Permit.Claims.CapabilityFence
	if fence.AuthorityTerm != 7 || fence.DecisionEpoch != 31 || fence.TargetIdentity != "uid-node-7" {
		t.Fatalf("unexpected capability fence: %+v", fence)
	}
	if err := egeproto.VerifyPermit(request.Context(), s.permitAuthority, *body.Permit); err != nil {
		t.Fatalf("capability-bound permit failed signature verification: %v", err)
	}
}

func TestEGEExecuteRejectsSupersededCapabilityBeforeReplayClaimAndController(t *testing.T) {
	now := time.Now().UTC()
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report:      kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	authority := &fakeCapabilityFenceAuthority{
		issue: CapabilityFenceIssue{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
		current: egeproto.CapabilityAuthoritySnapshot{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(
		controller,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			MutationsEnabled:          true,
			RequireAuthentication:     true,
			Authorizer:                allowAuthorizer{},
			ReplayGuard:               replay,
			RequireCapabilityFencing:  true,
			CapabilityFenceAuthority:  authority,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	prepareRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-cap-1",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"}
		}`),
	)
	prepareRecorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(prepareRecorder, prepareRequest)
	if prepareRecorder.Code != http.StatusOK {
		t.Fatalf("prepare expected 200, got %d body=%s", prepareRecorder.Code, prepareRecorder.Body.String())
	}
	var preparation egePrepareResponse
	if err := json.Unmarshal(prepareRecorder.Body.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.Permit == nil {
		t.Fatal("expected permit")
	}

	authority.current.DecisionEpoch = 32

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   *preparation.Permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_DECISION_SUPERSEDED") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("superseded capability must not reach mutation controller")
	}
	if controller.prepareCalls != 2 {
		t.Fatalf("expected prepare plus live capability revalidation, got %d prepare calls", controller.prepareCalls)
	}
}


func TestEGECapabilityClaimLifecycleIssuedToConsumed(t *testing.T) {
	now := time.Now().UTC()
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report:      kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	authority := &fakeCapabilityFenceAuthority{
		issue: CapabilityFenceIssue{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
		current: egeproto.CapabilityAuthoritySnapshot{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(
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

	prepareRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-cap-1",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"}
		}`),
	)
	prepareRecorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(prepareRecorder, prepareRequest)
	if prepareRecorder.Code != http.StatusOK {
		t.Fatalf("prepare expected 200, got %d body=%s", prepareRecorder.Code, prepareRecorder.Body.String())
	}
	var preparation egePrepareResponse
	if err := json.Unmarshal(prepareRecorder.Body.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.Permit == nil {
		t.Fatal("expected permit")
	}

	adapter, err := s.egeAdapters.Resolve(egeNodeDrainKind, egeNodeTarget)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := adapter.AuthorizationFromPermit(
		"intent-cap-1",
		egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		preparation.Permit.Claims,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := replay.State(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimIssued {
		t.Fatalf("prepare must persist ISSUED, got %+v", record)
	}

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   *preparation.Permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("execute expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response egeExecuteResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.CapabilityClaimState != ExecutionClaimConsumed {
		t.Fatalf("expected response claim state CONSUMED, got %+v", response)
	}
	record, err = replay.State(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimConsumed || record.Outcome != string(decision.Allow) {
		t.Fatalf("expected durable CONSUMED/ALLOW, got %+v", record)
	}
	if controller.executeCalls != 1 {
		t.Fatalf("expected one mutation-controller call, got %d", controller.executeCalls)
	}
}

type cancelAfterClaimGuard struct {
	*FileReplayGuard
	cancel context.CancelFunc
}

func (g *cancelAfterClaimGuard) Claim(
	ctx context.Context,
	auth decision.Authorization,
) error {
	if err := g.FileReplayGuard.Claim(ctx, auth); err != nil {
		return err
	}
	if g.cancel != nil {
		g.cancel()
	}
	return nil
}

func TestEGECapabilityClaimAbortsOnlyBeforeMutationController(t *testing.T) {
	now := time.Now().UTC()
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report:      kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	authority := &fakeCapabilityFenceAuthority{
		issue: CapabilityFenceIssue{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
		current: egeproto.CapabilityAuthoritySnapshot{
			AuthorityDomain: "cluster-a/control-plane",
			AuthorityTerm:   7,
			DecisionEpoch:   31,
			RevocationEpoch: 4,
		},
	}
	fileGuard, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	guard := &cancelAfterClaimGuard{FileReplayGuard: fileGuard}
	s, err := New(
		controller,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			MutationsEnabled:         true,
			RequireAuthentication:    true,
			Authorizer:               allowAuthorizer{},
			ReplayGuard:              guard,
			RequireCapabilityFencing: true,
			CapabilityFenceAuthority: authority,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	prepareRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-cap-1",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"}
		}`),
	)
	prepareRecorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(prepareRecorder, prepareRequest)
	if prepareRecorder.Code != http.StatusOK {
		t.Fatalf("prepare expected 200, got %d body=%s", prepareRecorder.Code, prepareRecorder.Body.String())
	}
	var preparation egePrepareResponse
	if err := json.Unmarshal(prepareRecorder.Body.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}

	adapter, err := s.egeAdapters.Resolve(egeNodeDrainKind, egeNodeTarget)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := adapter.AuthorizationFromPermit(
		"intent-cap-1",
		egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		preparation.Permit.Claims,
	)
	if err != nil {
		t.Fatal(err)
	}

	requestCtx, cancel := context.WithCancel(context.Background())
	guard.cancel = cancel
	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   *preparation.Permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload)).WithContext(requestCtx)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestTimeout {
		t.Fatalf("expected 408, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "EXECUTION_ABORTED_BEFORE_MUTATION") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("ABORTED capability must not enter mutation controller")
	}
	record, err := fileGuard.State(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimAborted {
		t.Fatalf("expected durable ABORTED state, got %+v", record)
	}
}
