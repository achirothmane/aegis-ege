package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	const (
		destinationID = "crm-test-1"
		accountID     = "acct-1"
		initialETag   = "rv-1"
	)

	var (
		mu         sync.Mutex
		patchCalls int
		etag       = initialETag
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
			w.Header().Set("ETag", etag)
			w.Header().Set("X-Aegis-Destination-ID", destinationID)
			w.Header().Set("X-Aegis-Account-ID", accountID)
			_ = json.NewEncoder(w).Encode(customer)
		case http.MethodPatch:
			if r.Header.Get("If-Match") != etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if r.Header.Get("X-Aegis-Destination-ID") != destinationID ||
				r.Header.Get("X-Aegis-Account-ID") != accountID {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for key, value := range patch {
				customer[key] = value
			}
			patchCalls++
			etag = "rv-2"
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer crm.Close()

	aegis, err := New(&fakeController{}, nil, Config{
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		EnableN8NEEPAdapter:   true,
		Clock:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	compileBody, err := json.Marshal(map[string]any{
		"intent_id":    "intent-crm-e2e-1",
		"event_id":     "evt-crm-e2e-1",
		"workflow_id":  "wf-customer-upgrade",
		"execution_id": "exec-101",
		"agent_id":     "agent-customer-ops",
		"observed_at":  "2026-09-28T04:29:58Z",
		"action": map[string]any{
			"kind":        "crm.customer_update",
			"tool":        "crm.http-json",
			"operation":   "update_customer",
			"target":      "customer/c-17",
			"side_effect": true,
		},
		"data": map[string]any{
			"customer":       map[string]any{"id": "c-17", "email": "alice@example.com", "current_tier": "standard"},
			"requested_tier": "gold",
			"ticket":         "T-42",
		},
		"authority_ref":         "authority://crm/customer-update/v3",
		"policy_ref":            "policy://agent-actions/v8",
		"redaction_profile_ref": "redaction://crm/pii/v4",
		"consequence_class":     "customer-record-write",
		"execution_binding": map[string]any{
			"destination_id":            destinationID,
			"account_id":                accountID,
			"endpoint":                  crm.URL,
			"adapter_profile":           eepcrm.CRMAdapterProfileVersion,
			"expected_resource_version": initialETag,
		},
		"control_refs":    []string{"soc2:CC6.1"},
		"approval_refs":   []string{"approval://ticket/T-42"},
		"sensitive_paths": []string{"/customer/email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	compileRequest := httptest.NewRequest(http.MethodPost, "/v1/eep/n8n/compile", bytes.NewReader(compileBody))
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
			ResourceVersion: initialETag,
			EvidenceDigest:  compiled.Packet.Provenance.InputDigest,
			PlanDigest:      planDigest,
			ExecutionBinding: &egeproto.ExecutionBindingClaims{
				DestinationID:           destinationID,
				AccountID:               accountID,
				Endpoint:                crm.URL,
				AdapterProfile:          eepcrm.CRMAdapterProfileVersion,
				ExpectedResourceVersion: initialETag,
			},
			ValidUntil: now.Add(time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, journalPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	j, err := journal.NewFileJournal(
		filepath.Join(dir, "eep-crm.jsonl"),
		filepath.Join(dir, "eep-crm.anchor.json"),
		journalPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := eepcrm.NewFileAttemptStore(filepath.Join(dir, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := eepcrm.NewExecutor(
		eepcrm.DestinationConfig{
			BaseURL:        crm.URL,
			DestinationID:  destinationID,
			AccountID:      accountID,
			AdapterProfile: eepcrm.CRMAdapterProfileVersion,
		},
		crm.Client(),
		permitAuthority,
		j,
		attempts,
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
	if outcome.Result != eepcrm.PostconditionVerified {
		t.Fatalf("outcome = %q, want VERIFIED", outcome.Result)
	}
	if outcome.RequestAcceptance != eepcrm.RequestAccepted ||
		outcome.ObservationStatus != eepcrm.ObservationStable {
		t.Fatalf("outcome evidence is not a stable accepted verification: %+v", outcome)
	}

	mu.Lock()
	gotTier := customer["tier"]
	gotPatchCalls := patchCalls
	mu.Unlock()
	if gotTier != "gold" || gotPatchCalls != 1 {
		t.Fatalf("customer=%v patch_calls=%d", gotTier, gotPatchCalls)
	}

	verification := j.Verify(context.Background())
	if !verification.Valid || verification.EntryCount != 3 {
		t.Fatalf("expected authorization + execution + outcome journal entries, got %+v", verification)
	}
	permitDigest, err := journal.DigestPayload(permit)
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := eepcrm.MutationAttemptID(permitDigest, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	record, err := attempts.Load(context.Background(), attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != eepcrm.AttemptCompleted {
		t.Fatalf("attempt state = %s, want COMPLETED", record.State)
	}
}

func TestCRMExecutorRejectsDifferentValidEvidencePacketBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 28, 4, 40, 0, 0, time.UTC)
	const (
		destinationID = "crm-test-binding"
		accountID     = "acct-binding"
		etag          = "rv-1"
	)
	var patchCalls int
	crm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", etag)
			w.Header().Set("X-Aegis-Destination-ID", destinationID)
			w.Header().Set("X-Aegis-Account-ID", accountID)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "c-17", "tier": "standard"})
		case http.MethodPatch:
			patchCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer crm.Close()

	original := e2eCRMPacket(t, "evt-original", "T-1", crm.URL, destinationID, accountID, etag)
	substitute := e2eCRMPacket(t, "evt-substitute", "T-2", crm.URL, destinationID, accountID, etag)

	plan := eepcrm.CustomerUpdatePlan{CustomerID: "c-17", Patch: map[string]any{"tier": "gold"}}
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
			ResourceVersion: etag,
			EvidenceDigest:  original.Provenance.InputDigest,
			PlanDigest:      planDigest,
			ExecutionBinding: &egeproto.ExecutionBindingClaims{
				DestinationID:           destinationID,
				AccountID:               accountID,
				Endpoint:                crm.URL,
				AdapterProfile:          eepcrm.CRMAdapterProfileVersion,
				ExpectedResourceVersion: etag,
			},
			ValidUntil: now.Add(time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	j, err := journal.NewFileJournal(filepath.Join(dir, "journal.jsonl"), filepath.Join(dir, "journal.anchor.json"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := eepcrm.NewFileAttemptStore(filepath.Join(dir, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := eepcrm.NewExecutor(
		eepcrm.DestinationConfig{BaseURL: crm.URL, DestinationID: destinationID, AccountID: accountID, AdapterProfile: eepcrm.CRMAdapterProfileVersion},
		crm.Client(),
		permitAuthority,
		j,
		attempts,
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

func e2eCRMPacket(
	t *testing.T,
	eventID string,
	ticket string,
	endpoint string,
	destinationID string,
	accountID string,
	resourceVersion string,
) evidencepipeline.Packet {
	t.Helper()
	packet, err := evidencepipeline.Compile(evidencepipeline.CompileRequest{
		Event: evidencepipeline.RuntimeEvent{
			IntentID: "intent-crm-binding",
			EventID:  eventID,
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
		Source: evidencepipeline.Source{Name: "n8n.http-request", TrustDomain: "n8n-workflow-runtime"},
		Context: evidencepipeline.BootstrapContext{
			AuthorityRef:        "authority://crm/customer-update/v3",
			PolicyRef:           "policy://agent-actions/v8",
			RedactionProfileRef: "redaction://crm/pii/v4",
			ConsequenceClass:    "customer-record-write",
			ExecutionBinding: &evidencepipeline.ExecutionBinding{
				DestinationID:           destinationID,
				AccountID:               accountID,
				Endpoint:                endpoint,
				AdapterProfile:          eepcrm.CRMAdapterProfileVersion,
				ExpectedResourceVersion: resourceVersion,
			},
		},
		SensitivePaths: []string{},
		CapturedAt:     time.Date(2026, 9, 28, 4, 39, 59, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

