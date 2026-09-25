package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/kubeadapter"
)

func TestEGEPrepareTranslatesIntentToStateLatchNodeDrain(t *testing.T) {
	validUntil := time.Date(2026, 9, 25, 15, 0, 0, 0, time.UTC)
	controller := &fakeController{
		preparation: kubeadapter.NodeDrainPreparation{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
			Authorization: &decision.Authorization{
				ActionID: "intent-1",
				Action: "drain",
				Target: "node/node-7",
				ResourceVersion: "101",
				EvidenceDigest: "sha256:evidence",
				PlanDigest: "sha256:plan",
				ValidUntil: validUntil,
			},
		},
	}
	s, err := New(controller, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-1",
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
	if body.APIVersion != egeAPIVersion || body.IntentID != "intent-1" || body.Kind != egeNodeDrainKind {
		t.Fatalf("unexpected EGE envelope: %+v", body)
	}
	if body.Decision != decision.Allow || body.Authorization == nil {
		t.Fatalf("expected ALLOW with authorization, got %+v", body)
	}
	if body.Authorization.ActionID != "intent-1" || body.Authorization.Target != "node/node-7" {
		t.Fatalf("authorization not bound to original intent: %+v", body.Authorization)
	}
	if controller.prepareCalls != 1 {
		t.Fatalf("expected one prepare call, got %d", controller.prepareCalls)
	}
}

func TestEGEPrepareRejectsUnknownIntentKindWithoutCallingController(t *testing.T) {
	controller := &fakeController{}
	s, err := New(controller, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-2",
			"kind":"aws.ec2.terminate",
			"target":{"type":"aws.ec2.instance","name":"i-123"}
		}`),
	)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.prepareCalls != 0 {
		t.Fatalf("unsupported intent must not reach controller")
	}
	if !strings.Contains(recorder.Body.String(), "UNSUPPORTED_INTENT_KIND") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestEGEExecuteDisabledByDefault(t *testing.T) {
	controller := &fakeController{}
	s, err := New(controller, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/execute",
		strings.NewReader(`{
			"intent_id":"intent-3",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"},
			"authorization":{}
		}`),
	)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("disabled EGE execution must not call controller")
	}
}

func TestEGEExecuteRequiresExactIntentAuthorizationBinding(t *testing.T) {
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{
		report: kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	s, err := New(controller, store, Config{
		MutationsEnabled: true,
		RequireAuthentication: true,
		Authorizer: allowAuthorizer{},
		ReplayGuard: replay,
	})
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"intent_id": "intent-4",
		"kind": egeNodeDrainKind,
		"target": map[string]any{
			"type": egeNodeTarget,
			"name": "node-7",
		},
		"authorization": map[string]any{
			"action_id": "different-intent",
			"action": "drain",
			"target": "node/node-7",
			"resource_version": "100",
			"evidence_digest": "sha256:evidence",
			"plan_digest": "sha256:plan",
			"valid_until": "2026-09-25T15:00:00Z",
		},
	}
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("authorization mismatch must not reach controller")
	}
	if !strings.Contains(recorder.Body.String(), "AUTHORIZATION_MISMATCH") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}
