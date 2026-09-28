package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/eepcrm"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

func TestN8NEEPCRMEndToEndEvidenceBeforeAction(t *testing.T) {
	now := time.Date(2026, 9, 28, 4, 30, 0, 0, time.UTC)

	aegis, err := New(&fakeController{}, nil, Config{
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		EnableN8NEEPAdapter:   true,
		Clock:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	compileRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/eep/n8n/compile",
		strings.NewReader(`{
			"intent_id":"intent-crm-e2e-1",
			"event_id":"evt-crm-e2e-1",
			"workflow_id":"wf-customer-upgrade",
			"execution_id":"exec-101",
			"agent_id":"agent-customer-ops",
			"observed_at":"2026-09-28T04:29:58Z",
			"action":{
				"kind":"crm.customer_update",
				"tool":"crm.http-json",
				"operation":"update_customer",
				"target":"customer/c-17",
				"side_effect":true
			},
			"data":{
				"customer":{"id":"c-17","email":"alice@example.com","current_tier":"standard"},
				"requested_tier":"gold",
				"ticket":"T-42"
			},
			"authority_ref":"authority://crm/customer-update/v3",
			"policy_ref":"policy://agent-actions/v8",
			"redaction_profile_ref":"redaction://crm/pii/v4",
			"consequence_class":"customer-record-write",
			"control_refs":["soc2:CC6.1"],
			"approval_refs":["approval://ticket/T-42"],
			"sensitive_paths":["/customer/email"]
		}`),
	)
	compileRecorder := httptest.NewRecorder()
	aegis.Handler().ServeHTTP(compileRecorder, compileRequest)
	if compileRecorder.Code != http.StatusOK {
		t.Fatalf("compile expected 200, got %d body=%s", compileRecorder.Code, compileRecorder.Body.String())
	}

	var compiled n8nEEPCompileResponse
	if err := json.Unmarshal(compileRecorder.Body.Bytes(), &compiled); err != nil {
		t.Fatal(err)
	}
	if err := evidencepipeline.Verify(compiled.Packet); err != nil {
		t.Fatalf("compiled packet failed verification: %v", err)
	}
	if strings.Contains(compileRecorder.Body.String(), "alice@example.com") {
		t.Fatal("compiled evidence leaked redacted customer email")
	}

	plan := eepcrm.CustomerUpdatePlan{
		CustomerID: "c-17",
		Patch:      map[string]any{"tier": "gold"},
	}
	planDigest, err := eepcrm.DigestCustomerUpdatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}

	permitAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := evidencepipeline.SignEvidenceBoundPermit(
		context.Background(),
		permitAuthority,
		compiled.Packet,
		egeproto.PermitClaims{
			IntentID:        compiled.Packet.IntentID,
			Kind:            compiled.Packet.Action.Kind,
			Target:          egeproto.Target{Type: "customer", Name: "c-17"},
			Action:          compiled.Packet.Action.Operation,
			ResourceVersion: "crm-rv-1",
			EvidenceDigest:  compiled.Packet.Provenance.InputDigest,
			PlanDigest:      planDigest,
			ValidUntil:      now.Add(time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu         sync.Mutex
		patchCalls int
		customer   = map[string]any{
			"id":    "c-17",
			"email": "alice@example.com",
			"tier":  "standard",
		}
	)
	crm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/customers/c-17" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(customer)
		case http.MethodPatch:
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for key, value := range patch {
				customer[key] = value
			}
			patchCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer crm.Close()

	_, journalPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "eep-crm.jsonl")
	anchorPath := filepath.Join(dir, "eep-crm.anchor.json")
	j, err := journal.NewFileJournal(journalPath, anchorPath, journalPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	executor, err := eepcrm.NewExecutor(
		crm.URL,
		crm.Client(),
		permitAuthority,
		j,
		func() time.Time { return now.Add(5 * time.Second) },
	)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := executor.Execute(context.Background(), compiled.Packet, permit, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := eepcrm.VerifyOutcome(outcome); err != nil {
		t.Fatalf("outcome evidence failed verification: %v", err)
	}
	if outcome.Result != "APPLIED" {
		t.Fatalf("outcome = %q, want APPLIED", outcome.Result)
	}
	if outcome.EvidencePacketDigest != compiled.Packet.Integrity.Digest {
		t.Fatalf("outcome packet digest = %q, want %q", outcome.EvidencePacketDigest, compiled.Packet.Integrity.Digest)
	}
	if outcome.BeforeDigest == outcome.AfterDigest {
		t.Fatal("expected before/after state digests to differ")
	}

	mu.Lock()
	gotTier := customer["tier"]
	gotPatchCalls := patchCalls
	mu.Unlock()
	if gotTier != "gold" {
		t.Fatalf("CRM tier = %v, want gold", gotTier)
	}
	if gotPatchCalls != 1 {
		t.Fatalf("CRM PATCH calls = %d, want 1", gotPatchCalls)
	}

	verification := j.Verify(context.Background())
	if !verification.Valid || verification.EntryCount != 2 {
		t.Fatalf("expected authorization + outcome journal entries, got %+v", verification)
	}
}

func TestCRMExecutorRejectsDifferentValidEvidencePacketBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 28, 4, 40, 0, 0, time.UTC)
	original := e2eCRMPacket(t, "evt-original", "T-1")
	substitute := e2eCRMPacket(t, "evt-substitute", "T-2")

	plan := eepcrm.CustomerUpdatePlan{
		CustomerID: "c-17",
		Patch:      map[string]any{"tier": "gold"},
	}
	planDigest, err := eepcrm.DigestCustomerUpdatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}

	permitAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := evidencepipeline.SignEvidenceBoundPermit(
		context.Background(),
		permitAuthority,
		original,
		egeproto.PermitClaims{
			IntentID:        original.IntentID,
			Kind:            original.Action.Kind,
			Target:          egeproto.Target{Type: "customer", Name: "c-17"},
			Action:          original.Action.Operation,
			ResourceVersion: "crm-rv-1",
			EvidenceDigest:  original.Provenance.InputDigest,
			PlanDigest:      planDigest,
			ValidUntil:      now.Add(time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var patchCalls int
	crm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "c-17", "tier": "standard"})
		case http.MethodPatch:
			patchCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer crm.Close()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	j, err := journal.NewFileJournal(
		filepath.Join(dir, "journal.jsonl"),
		filepath.Join(dir, "journal.anchor.json"),
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := eepcrm.NewExecutor(
		crm.URL,
		crm.Client(),
		permitAuthority,
		j,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := executor.Execute(context.Background(), substitute, permit, plan); err == nil {
		t.Fatal("executor accepted a different valid Evidence Packet")
	}
	if patchCalls != 0 {
		t.Fatalf("mutation occurred despite packet/permit mismatch: %d PATCH call(s)", patchCalls)
	}
	if verification := j.Verify(context.Background()); !verification.Valid || verification.EntryCount != 0 {
		t.Fatalf("journal should remain empty before rejected mutation, got %+v", verification)
	}
}

func e2eCRMPacket(t *testing.T, eventID, ticket string) evidencepipeline.Packet {
	t.Helper()
	packet, err := evidencepipeline.Compile(evidencepipeline.CompileRequest{
		Event: evidencepipeline.RuntimeEvent{
			IntentID:   "intent-crm-binding",
			EventID:    eventID,
			WorkflowID: "wf-crm",
			RunID:      "run-crm",
			Actor: evidencepipeline.Actor{
				PrincipalID: "spiffe://test/operator",
			},
			Action: evidencepipeline.Action{
				Kind:       "crm.customer_update",
				Tool:       "crm.http-json",
				Operation:  "update_customer",
				Target:     "customer/c-17",
				SideEffect: true,
			},
			ObservedAt: time.Date(2026, 9, 28, 4, 39, 58, 0, time.UTC),
			Data:       map[string]any{"ticket": ticket},
		},
		Source: evidencepipeline.Source{
			Name:        "n8n.http-request",
			TrustDomain: "n8n-workflow-runtime",
		},
		Context: evidencepipeline.BootstrapContext{
			AuthorityRef:        "authority://crm/customer-update/v3",
			PolicyRef:           "policy://agent-actions/v8",
			RedactionProfileRef: "redaction://crm/pii/v4",
			ConsequenceClass:    "customer-record-write",
		},
		SensitivePaths: []string{},
		CapturedAt:     time.Date(2026, 9, 28, 4, 39, 59, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
