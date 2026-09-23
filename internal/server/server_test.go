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

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/kubeadapter"
)

type fakeController struct {
	preparation  kubeadapter.NodeDrainPreparation
	report       kubeadapter.GuardedDrainExecutionReport
	prepareCalls int
	executeCalls int
}

func (f *fakeController) PrepareNodeDrainExecution(
	context.Context,
	string,
	string,
	kubeadapter.NodeDrainPolicy,
) (kubeadapter.NodeDrainPreparation, error) {
	f.prepareCalls++
	return f.preparation, nil
}

func (f *fakeController) ExecuteAuthorizedNodeDrainWithCheckpointStore(
	context.Context,
	decision.Authorization,
	string,
	kubeadapter.NodeDrainPolicy,
	kubeadapter.DrainCheckpointStore,
) (kubeadapter.GuardedDrainExecutionReport, error) {
	f.executeCalls++
	return f.report, nil
}

func TestPrepareReturnsStableDecisionDTO(t *testing.T) {
	validUntil := time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC)
	controller := &fakeController{
		preparation: kubeadapter.NodeDrainPreparation{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
			Authorization: &decision.Authorization{
				ActionID: "act-1", Action: "drain", Target: "node/node-7",
				ResourceVersion: "100", EvidenceDigest: "sha256:evidence",
				PlanDigest: "sha256:plan", ValidUntil: validUntil,
			},
		},
	}
	s, err := New(controller, nil, Config{})
	if err != nil { t.Fatal(err) }

	request := httptest.NewRequest(http.MethodPost, "/v1/node-drains/prepare",
		strings.NewReader("{\"action_id\":\"act-1\",\"node_name\":\"node-7\"}"))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	var body prepareResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body.Decision != decision.Allow || body.PlanDigest != "sha256:plan" {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.Authorization == nil || !body.Authorization.ValidUntil.Equal(validUntil) {
		t.Fatalf("authorization missing or changed: %+v", body.Authorization)
	}
	if controller.prepareCalls != 1 {
		t.Fatalf("expected one prepare call, got %d", controller.prepareCalls)
	}
}

func TestExecuteDisabledByDefaultAndNeverCallsController(t *testing.T) {
	controller := &fakeController{}
	s, err := New(controller, nil, Config{})
	if err != nil { t.Fatal(err) }

	request := httptest.NewRequest(http.MethodPost, "/v1/node-drains/execute",
		bytes.NewBufferString("{\"node_name\":\"node-7\",\"authorization\":{}}"))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("disabled mutation endpoint called controller %d time(s)", controller.executeCalls)
	}
	if !strings.Contains(recorder.Body.String(), "MUTATIONS_DISABLED") {
		t.Fatalf("expected MUTATIONS_DISABLED body, got %s", recorder.Body.String())
	}
}

func TestExecuteRequiresCheckpointStoreWhenEnabled(t *testing.T) {
	_, err := New(&fakeController{}, nil, Config{MutationsEnabled: true})
	if err == nil || !strings.Contains(err.Error(), "checkpoint store") {
		t.Fatalf("expected checkpoint store requirement, got %v", err)
	}
}

func TestExecuteEnabledPassesBoundAuthorization(t *testing.T) {
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	controller := &fakeController{
		report: kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	s, err := New(controller, store, Config{MutationsEnabled: true})
	if err != nil { t.Fatal(err) }

	body := map[string]any{
		"node_name": "node-7",
		"authorization": map[string]any{
			"action_id": "act-1", "action": "drain", "target": "node/node-7",
			"resource_version": "100", "evidence_digest": "sha256:evidence",
			"plan_digest": "sha256:plan", "valid_until": "2026-09-23T20:00:00Z",
		},
	}
	payload, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/node-drains/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 1 {
		t.Fatalf("expected one execute call, got %d", controller.executeCalls)
	}
}

func TestPrepareRejectsUnknownJSONField(t *testing.T) {
	s, err := New(&fakeController{}, nil, Config{})
	if err != nil { t.Fatal(err) }
	request := httptest.NewRequest(http.MethodPost, "/v1/node-drains/prepare",
		strings.NewReader("{\"action_id\":\"a\",\"node_name\":\"n\",\"policy\":{\"force\":true}}"))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestHealth(t *testing.T) {
	s, err := New(&fakeController{}, nil, Config{})
	if err != nil { t.Fatal(err) }
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}
