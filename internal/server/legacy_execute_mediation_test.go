package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

func legacyExecuteTestAuthorization() decision.Authorization {
	return decision.Authorization{
		ActionID:        "act-c01",
		Action:          "drain",
		Target:          "node/node-7",
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ValidUntil:      time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
	}
}

func executeLegacyNodeDrain(
	t *testing.T,
	s *Server,
	auth decision.Authorization,
) *httptest.ResponseRecorder {
	t.Helper()

	payload, err := json.Marshal(executeRequest{
		NodeName:       "node-7",
		Authorization: authorizationToDTO(auth),
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/node-drains/execute",
		bytes.NewReader(payload),
	)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	return recorder
}

func assertLegacyExecutionBlockedBeforeClaim(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	controller *fakeController,
	replay *FileReplayGuard,
	auth decision.Authorization,
) {
	t.Helper()

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "EGE_EXECUTION_REQUIRED") {
		t.Fatalf("expected EGE_EXECUTION_REQUIRED, got %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("legacy governed request reached controller %d time(s)", controller.executeCalls)
	}
	if _, err := replay.State(context.Background(), auth); !errors.Is(err, ErrExecutionClaimNotFound) {
		t.Fatalf("legacy governed request must not consume replay/capability claim, got %v", err)
	}
}

func TestLegacyExecuteBlockedWhenEBAConformanceRequired(t *testing.T) {
	approvalAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{}
	s, err := New(controller, kubeadapter.NewMemoryDrainCheckpointStore(), Config{
		MutationsEnabled:       true,
		EASLRuntime:            readyEASLRuntime(t),
		RequireAuthentication:  true,
		Authorizer:             allowAuthorizer{},
		ReplayGuard:            replay,
		RequireEBAConformance:  true,
		EBAApprovalAuthority:   approvalAuthority,
		EBAExecutionPrincipal:  "aegis-ege",
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := legacyExecuteTestAuthorization()
	recorder := executeLegacyNodeDrain(t, s, auth)
	assertLegacyExecutionBlockedBeforeClaim(t, recorder, controller, replay, auth)
}

func TestLegacyExecuteBlockedWhenCapabilityFencingRequired(t *testing.T) {
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{}
	s, err := New(controller, kubeadapter.NewMemoryDrainCheckpointStore(), Config{
		MutationsEnabled:          true,
		EASLRuntime:               readyEASLRuntime(t),
		RequireAuthentication:     true,
		Authorizer:                allowAuthorizer{},
		ReplayGuard:               replay,
		RequireCapabilityFencing:  true,
		CapabilityFenceAuthority:  &fakeCapabilityFenceAuthority{},
	})
	if err != nil {
		t.Fatal(err)
	}

	auth := legacyExecuteTestAuthorization()
	recorder := executeLegacyNodeDrain(t, s, auth)
	assertLegacyExecutionBlockedBeforeClaim(t, recorder, controller, replay, auth)
}
