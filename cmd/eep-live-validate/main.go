package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/eepcrm"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

type actionEnvelope struct {
	Kind       string `json:"kind"`
	Tool       string `json:"tool"`
	Operation  string `json:"operation"`
	Target     string `json:"target"`
	SideEffect bool   `json:"side_effect"`
}

type n8nEnvelope struct {
	IntentID             string         `json:"intent_id"`
	EventID              string         `json:"event_id"`
	WorkflowID           string         `json:"workflow_id"`
	ExecutionID          string         `json:"execution_id"`
	AgentID              string         `json:"agent_id,omitempty"`
	ObservedAt           time.Time      `json:"observed_at"`
	Action               actionEnvelope `json:"action"`
	Data                 map[string]any `json:"data"`
	AuthorityRef         string         `json:"authority_ref"`
	PolicyRef            string         `json:"policy_ref"`
	RedactionProfileRef  string         `json:"redaction_profile_ref"`
	ConsequenceClass     string         `json:"consequence_class"`
	ControlRefs          []string       `json:"control_refs,omitempty"`
	ApprovalRefs         []string       `json:"approval_refs,omitempty"`
	SensitivePaths       []string       `json:"sensitive_paths"`
	SourceAttestationRef string         `json:"source_attestation_ref,omitempty"`
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(clone)
}

type result struct {
	Status               string `json:"status"`
	Target               string `json:"target"`
	PacketDigest         string `json:"packet_digest"`
	PermitDigest         string `json:"permit_digest"`
	OutcomeDigest        string `json:"outcome_digest"`
	Outcome              string `json:"outcome"`
	JournalEntries       uint64 `json:"journal_entries"`
	N8NWorkflowID        string `json:"n8n_workflow_id"`
	N8NExecutionID       string `json:"n8n_execution_id"`
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "EEP live validation failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	n8nURL := mustEnv("EEP_N8N_WEBHOOK_URL")
	n8nToken := mustEnv("EEP_N8N_AUTH_TOKEN")
	sourcePrincipal := mustEnv("EEP_SOURCE_PRINCIPAL")
	crmBaseURL := mustEnv("EEP_CRM_BASE_URL")
	crmDestinationID := mustEnv("EEP_CRM_DESTINATION_ID")
	crmAccountID := mustEnv("EEP_CRM_ACCOUNT_ID")
	expectedResourceVersion := mustEnv("EEP_CRM_EXPECTED_RESOURCE_VERSION")
	crmToken := strings.TrimSpace(os.Getenv("EEP_CRM_BEARER_TOKEN"))
	patchJSON := mustEnv("EEP_PATCH_JSON")
	triggerJSON := strings.TrimSpace(os.Getenv("EEP_N8N_TRIGGER_JSON"))
	if triggerJSON == "" {
		triggerJSON = "{}"
	}

	if err := requireHTTPS(n8nURL); err != nil {
		return fmt.Errorf("n8n webhook: %w", err)
	}
	if err := requireHTTPS(crmBaseURL); err != nil {
		return fmt.Errorf("CRM endpoint: %w", err)
	}

	var trigger any
	if err := json.Unmarshal([]byte(triggerJSON), &trigger); err != nil {
		return fmt.Errorf("decode EEP_N8N_TRIGGER_JSON: %w", err)
	}
	var patch map[string]any
	if err := json.Unmarshal([]byte(patchJSON), &patch); err != nil {
		return fmt.Errorf("decode EEP_PATCH_JSON: %w", err)
	}
	if len(patch) == 0 {
		return errors.New("EEP_PATCH_JSON must contain at least one field")
	}

	n8nClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: bearerTransport{token: n8nToken, base: http.DefaultTransport},
	}
	envelope, err := fetchEnvelope(ctx, n8nClient, n8nURL, trigger)
	if err != nil {
		return err
	}

	packet, err := evidencepipeline.Compile(evidencepipeline.CompileRequest{
		Event: evidencepipeline.RuntimeEvent{
			IntentID:   strings.TrimSpace(envelope.IntentID),
			EventID:    strings.TrimSpace(envelope.EventID),
			WorkflowID: strings.TrimSpace(envelope.WorkflowID),
			RunID:      strings.TrimSpace(envelope.ExecutionID),
			Actor: evidencepipeline.Actor{
				PrincipalID: sourcePrincipal,
				AgentID:     strings.TrimSpace(envelope.AgentID),
			},
			Action: evidencepipeline.Action{
				Kind:       strings.TrimSpace(envelope.Action.Kind),
				Tool:       strings.TrimSpace(envelope.Action.Tool),
				Operation:  strings.TrimSpace(envelope.Action.Operation),
				Target:     strings.TrimSpace(envelope.Action.Target),
				SideEffect: envelope.Action.SideEffect,
			},
			ObservedAt: envelope.ObservedAt,
			Data:       envelope.Data,
		},
		Source: evidencepipeline.Source{
			Name:           "n8n.live-webhook",
			TrustDomain:    "n8n-workflow-runtime",
			AttestationRef: strings.TrimSpace(envelope.SourceAttestationRef),
		},
		Context: evidencepipeline.BootstrapContext{
			AuthorityRef:        strings.TrimSpace(envelope.AuthorityRef),
			PolicyRef:           strings.TrimSpace(envelope.PolicyRef),
			RedactionProfileRef: strings.TrimSpace(envelope.RedactionProfileRef),
			ConsequenceClass:    strings.TrimSpace(envelope.ConsequenceClass),
			ExecutionBinding: &evidencepipeline.ExecutionBinding{
				DestinationID:           crmDestinationID,
				AccountID:               crmAccountID,
				Endpoint:                strings.TrimRight(strings.TrimSpace(crmBaseURL), "/"),
				AdapterProfile:          eepcrm.CRMAdapterProfileVersion,
				ExpectedResourceVersion: expectedResourceVersion,
			},
			ControlRefs:         append([]string(nil), envelope.ControlRefs...),
			ApprovalRefs:        append([]string(nil), envelope.ApprovalRefs...),
		},
		SensitivePaths: append([]string(nil), envelope.SensitivePaths...),
		CapturedAt:     time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("compile n8n envelope: %w", err)
	}

	customerID, err := customerIDFromTarget(packet.Action.Target)
	if err != nil {
		return err
	}
	plan := eepcrm.CustomerUpdatePlan{CustomerID: customerID, Patch: patch}
	planDigest, err := eepcrm.DigestCustomerUpdatePlan(plan)
	if err != nil {
		return err
	}

	permitAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		return err
	}
	permit, err := evidencepipeline.SignEvidenceBoundPermit(ctx, permitAuthority, packet, egeproto.PermitClaims{
		IntentID:        packet.IntentID,
		Kind:            packet.Action.Kind,
		Target:          egeproto.Target{Type: "customer", Name: customerID},
		Action:          packet.Action.Operation,
		ResourceVersion: expectedResourceVersion,
		EvidenceDigest:  packet.Provenance.InputDigest,
		PlanDigest:      planDigest,
		ExecutionBinding: &egeproto.ExecutionBindingClaims{
			DestinationID:           crmDestinationID,
			AccountID:               crmAccountID,
			Endpoint:                strings.TrimRight(strings.TrimSpace(crmBaseURL), "/"),
			AdapterProfile:          eepcrm.CRMAdapterProfileVersion,
			ExpectedResourceVersion: expectedResourceVersion,
		},
		ValidUntil: time.Now().UTC().Add(2 * time.Minute),
	})
	if err != nil {
		return fmt.Errorf("sign evidence-bound permit: %w", err)
	}

	_, journalPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp("", "aegis-eep-live-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	j, err := journal.NewFileJournal(
		filepath.Join(tempDir, "journal.jsonl"),
		filepath.Join(tempDir, "journal.anchor.json"),
		journalPrivateKey,
	)
	if err != nil {
		return err
	}
	attemptStore, err := eepcrm.NewFileAttemptStore(filepath.Join(tempDir, "attempts"))
	if err != nil {
		return err
	}

	crmClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: bearerTransport{token: crmToken, base: http.DefaultTransport},
	}
	executor, err := eepcrm.NewExecutor(
		eepcrm.DestinationConfig{
			BaseURL:        crmBaseURL,
			DestinationID:  crmDestinationID,
			AccountID:      crmAccountID,
			AdapterProfile: eepcrm.CRMAdapterProfileVersion,
		},
		crmClient,
		permitAuthority,
		j,
		attemptStore,
		time.Now,
	)
	if err != nil {
		return err
	}
	outcome, err := executor.Execute(ctx, packet, permit, plan)
	if err != nil {
		return err
	}
	if err := eepcrm.VerifyOutcome(outcome); err != nil {
		return fmt.Errorf("verify outcome evidence: %w", err)
	}
	verification := j.Verify(ctx)
	if !verification.Valid {
		return fmt.Errorf("verify live journal: %s", verification.Error)
	}
	expectedJournalEntries := uint64(3)
	if outcome.Result == eepcrm.PostconditionAlreadySatisfied {
		expectedJournalEntries = 2
	}
	if verification.EntryCount != expectedJournalEntries {
		return fmt.Errorf(
			"expected %d journal entries for outcome %s, got %d",
			expectedJournalEntries,
			outcome.Result,
			verification.EntryCount,
		)
	}
	permitDigest, err := journal.DigestPayload(permit)
	if err != nil {
		return err
	}

	summary := result{
		Status:         "PASS",
		Target:         outcome.Target,
		PacketDigest:   packet.Integrity.Digest,
		PermitDigest:   permitDigest,
		OutcomeDigest:  outcome.IntegrityDigest,
		Outcome:        string(outcome.Result),
		JournalEntries: verification.EntryCount,
		N8NWorkflowID:  envelope.WorkflowID,
		N8NExecutionID: envelope.ExecutionID,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func fetchEnvelope(ctx context.Context, client *http.Client, endpoint string, trigger any) (n8nEnvelope, error) {
	body, err := json.Marshal(trigger)
	if err != nil {
		return n8nEnvelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return n8nEnvelope{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return n8nEnvelope{}, fmt.Errorf("call n8n webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return n8nEnvelope{}, fmt.Errorf("n8n webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope n8nEnvelope
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return n8nEnvelope{}, fmt.Errorf("decode n8n evidence envelope: %w", err)
	}
	return envelope, nil
}

func customerIDFromTarget(target string) (string, error) {
	const prefix = "customer/"
	if !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("live validation requires customer target, got %q", target)
	}
	id := strings.TrimSpace(strings.TrimPrefix(target, prefix))
	if id == "" || strings.Contains(id, "/") {
		return "", fmt.Errorf("invalid customer target %q", target)
	}
	return id, nil
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("HTTPS URL is required for live validation")
	}
	if u.User != nil {
		return errors.New("credentials must not be embedded in URLs")
	}
	return nil
}

func mustEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		fmt.Fprintln(os.Stderr, name+" is required")
		os.Exit(2)
	}
	return value
}
