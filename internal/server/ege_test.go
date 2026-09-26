package server

import (
	"bytes"
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

func TestEGEPrepareProducesEvidenceManifestAndSignedPermit(t *testing.T) {
	observedAt := time.Now().UTC()
	validUntil := observedAt.Add(time.Minute)
	controller := &fakeController{
		preparation: kubeadapter.NodeDrainPreparation{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
			Snapshot: kubeadapter.NodeDrainSnapshot{
				NodeName:        "node-7",
				ResourceVersion: "101",
				ObservedAt:      observedAt,
			},
			Authorization: &decision.Authorization{
				ActionID:        "intent-1",
				Action:          "drain",
				Target:          "node/node-7",
				ResourceVersion: "101",
				EvidenceDigest:  "sha256:evidence",
				PlanDigest:      "sha256:plan",
				ValidUntil:      validUntil,
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
	if body.Decision != decision.Allow || body.EvidenceManifest == nil || body.Permit == nil {
		t.Fatalf("expected ALLOW with evidence manifest and permit, got %+v", body)
	}
	if body.Permit.Claims.IntentID != "intent-1" ||
		body.Permit.Claims.Target.Name != "node-7" ||
		body.Permit.Claims.ResourceVersion != "101" ||
		body.Permit.Claims.EvidenceDigest != "sha256:evidence" ||
		body.Permit.Claims.PlanDigest != "sha256:plan" {
		t.Fatalf("permit not bound to original evidence/state/intent: %+v", body.Permit)
	}
	manifestDigest, err := egeproto.DigestEvidenceManifest(*body.EvidenceManifest)
	if err != nil {
		t.Fatal(err)
	}
	if body.Permit.Claims.EvidenceManifestDigest != manifestDigest {
		t.Fatalf("permit is not bound to evidence manifest: got %s want %s", body.Permit.Claims.EvidenceManifestDigest, manifestDigest)
	}
	if err := egeproto.VerifyPermit(request.Context(), s.permitAuthority, *body.Permit); err != nil {
		t.Fatalf("issued permit failed verification: %v", err)
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
			"permit":{}
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

func TestEGEExecuteRejectsTamperedPermitBeforeController(t *testing.T) {
	controller := &fakeController{
		preparation: kubeadapter.NodeDrainPreparation{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
			Snapshot: kubeadapter.NodeDrainSnapshot{
				NodeName:        "node-7",
				ResourceVersion: "100",
				ObservedAt:      time.Now().UTC(),
			},
			Authorization: &decision.Authorization{
				ActionID:        "intent-4",
				Action:          "drain",
				Target:          "node/node-7",
				ResourceVersion: "100",
				EvidenceDigest:  "sha256:evidence",
				PlanDigest:      "sha256:plan",
				ValidUntil:      time.Now().UTC().Add(time.Minute),
			},
		},
		report: kubeadapter.GuardedDrainExecutionReport{Decision: decision.Allow, PlanDigest: "sha256:plan"},
	}
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(controller, store, Config{
		MutationsEnabled:      true,
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		ReplayGuard:           replay,
	})
	if err != nil {
		t.Fatal(err)
	}

	prepareRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-4",
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
		t.Fatal("expected signed permit")
	}

	tampered := *preparation.Permit
	tampered.Claims.PlanDigest = "sha256:attacker-plan"
	payload, _ := json.Marshal(egeExecuteRequest{
		IntentID: "intent-4",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   tampered,
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("tampered permit must not reach controller")
	}
	if !strings.Contains(recorder.Body.String(), "INVALID_EXECUTION_PERMIT") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestEGEExecuteRequiresSignedPermitToMatchOuterIntent(t *testing.T) {
	controller := &fakeController{
		preparation: kubeadapter.NodeDrainPreparation{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
			Snapshot: kubeadapter.NodeDrainSnapshot{
				NodeName:        "node-7",
				ResourceVersion: "100",
				ObservedAt:      time.Now().UTC(),
			},
			Authorization: &decision.Authorization{
				ActionID:        "intent-5",
				Action:          "drain",
				Target:          "node/node-7",
				ResourceVersion: "100",
				EvidenceDigest:  "sha256:evidence",
				PlanDigest:      "sha256:plan",
				ValidUntil:      time.Now().UTC().Add(time.Minute),
			},
		},
	}
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(controller, store, Config{
		MutationsEnabled:      true,
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		ReplayGuard:           replay,
	})
	if err != nil {
		t.Fatal(err)
	}

	prepareRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/ege/prepare",
		strings.NewReader(`{
			"intent_id":"intent-5",
			"kind":"kubernetes.node_drain",
			"target":{"type":"kubernetes.node","name":"node-7"}
		}`),
	)
	prepareRecorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(prepareRecorder, prepareRequest)
	var preparation egePrepareResponse
	if err := json.Unmarshal(prepareRecorder.Body.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	if preparation.Permit == nil {
		t.Fatal("expected signed permit")
	}

	payload, _ := json.Marshal(egeExecuteRequest{
		IntentID: "intent-5",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-8"},
		Permit:   *preparation.Permit,
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("permit/intent mismatch must not reach controller")
	}
	if !strings.Contains(recorder.Body.String(), "PERMIT_INTENT_MISMATCH") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}
