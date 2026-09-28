package server

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/achirothmane/aegis-ege/internal/evidencepipeline"
)

func TestN8NEEPCompileUsesAuthenticatedPrincipalAndRedactsData(t *testing.T) {
    now := time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)
    s, err := New(&fakeController{}, nil, Config{
        RequireAuthentication: true,
        Authorizer:            allowAuthorizer{},
        EnableN8NEEPAdapter:   true,
        Clock: func() time.Time { return now },
    })
    if err != nil {
        t.Fatal(err)
    }

    request := httptest.NewRequest(http.MethodPost, "/v1/eep/n8n/compile", strings.NewReader(`{
        "intent_id":"intent-crm-1",
        "event_id":"evt-1",
        "workflow_id":"wf-crm-sync",
        "execution_id":"exec-77",
        "agent_id":"agent-crm",
        "observed_at":"2026-09-28T03:59:58Z",
        "action":{
            "kind":"crm.customer_update",
            "tool":"salesforce",
            "operation":"update_customer",
            "target":"customer/c-17",
            "side_effect":true
        },
        "data":{
            "customer":{"id":"c-17","email":"alice@example.com"},
            "auth":{"token":"secret-token"},
            "ticket":"T-42"
        },
        "authority_ref":"authority://crm/customer-update/v3",
        "policy_ref":"policy://agent-actions/v8",
        "redaction_profile_ref":"redaction://crm/pii/v4",
        "consequence_class":"customer-record-write",
        "control_refs":["soc2:CC6.1"],
        "approval_refs":["approval://ticket/T-42"],
        "sensitive_paths":["/customer/email","/auth/token"]
    }`))
    recorder := httptest.NewRecorder()
    s.Handler().ServeHTTP(recorder, request)

    if recorder.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
    }
    var body n8nEEPCompileResponse
    if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
        t.Fatal(err)
    }
    if body.APIVersion != n8nEEPAPIVersion {
        t.Fatalf("api version = %q", body.APIVersion)
    }
    if body.Packet.Actor.PrincipalID != "spiffe://test/operator" {
        t.Fatalf("principal = %q, want authenticated caller", body.Packet.Actor.PrincipalID)
    }
    if body.Packet.Provenance.Source.Name != "n8n.http-request" ||
        body.Packet.Provenance.Source.TrustDomain != "n8n-workflow-runtime" {
        t.Fatalf("unexpected source: %+v", body.Packet.Provenance.Source)
    }
    if err := evidencepipeline.Verify(body.Packet); err != nil {
        t.Fatalf("compiled packet failed verification: %v", err)
    }
    raw := recorder.Body.String()
    for _, secret := range []string{"alice@example.com", "secret-token"} {
        if strings.Contains(raw, secret) {
            t.Fatalf("response leaked %q", secret)
        }
    }
}

func TestN8NEEPAdapterRequiresAuthenticatedTransportAtConfiguration(t *testing.T) {
    _, err := New(&fakeController{}, nil, Config{EnableN8NEEPAdapter: true})
    if err == nil || !strings.Contains(err.Error(), "authenticated transport") {
        t.Fatalf("expected authentication requirement, got %v", err)
    }
}

func TestN8NEEPCompileRejectsMissingAuthorityContext(t *testing.T) {
    s, err := New(&fakeController{}, nil, Config{
        RequireAuthentication: true,
        Authorizer:            allowAuthorizer{},
        EnableN8NEEPAdapter:   true,
    })
    if err != nil {
        t.Fatal(err)
    }

    request := httptest.NewRequest(http.MethodPost, "/v1/eep/n8n/compile", strings.NewReader(`{
        "intent_id":"intent-crm-1",
        "event_id":"evt-1",
        "workflow_id":"wf-crm-sync",
        "execution_id":"exec-77",
        "observed_at":"2026-09-28T03:59:58Z",
        "action":{
            "kind":"crm.customer_update",
            "tool":"salesforce",
            "operation":"update_customer",
            "target":"customer/c-17",
            "side_effect":true
        },
        "data":{"customer":{"id":"c-17"}},
        "policy_ref":"policy://agent-actions/v8",
        "redaction_profile_ref":"redaction://crm/pii/v4",
        "consequence_class":"customer-record-write",
        "sensitive_paths":[]
    }`))
    recorder := httptest.NewRecorder()
    s.Handler().ServeHTTP(recorder, request)

    if recorder.Code != http.StatusUnprocessableEntity {
        t.Fatalf("expected 422, got %d body=%s", recorder.Code, recorder.Body.String())
    }
    if !strings.Contains(recorder.Body.String(), "authority_ref is required") {
        t.Fatalf("unexpected body: %s", recorder.Body.String())
    }
}

func TestN8NEEPRouteIsAbsentUnlessEnabled(t *testing.T) {
    s, err := New(&fakeController{}, nil, Config{})
    if err != nil {
        t.Fatal(err)
    }
    request := httptest.NewRequest(http.MethodPost, "/v1/eep/n8n/compile", strings.NewReader(`{}`))
    recorder := httptest.NewRecorder()
    s.Handler().ServeHTTP(recorder, request)

    if recorder.Code != http.StatusNotFound {
        t.Fatalf("expected 404 when n8n adapter is disabled, got %d", recorder.Code)
    }
}
