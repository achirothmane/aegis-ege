package eepcrm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

const OutcomeVersion = "aegis.eep/crm-outcome/v0alpha1"

type JournalAppender interface {
	Append(context.Context, journal.Event) (journal.Entry, error)
}

type CustomerUpdatePlan struct {
	CustomerID string         `json:"customer_id"`
	Patch      map[string]any `json:"patch"`
}

type OutcomeEvidence struct {
	APIVersion           string    `json:"api_version"`
	IntentID             string    `json:"intent_id"`
	Target               string    `json:"target"`
	EvidencePacketDigest string    `json:"evidence_packet_digest"`
	PermitDigest         string    `json:"permit_digest"`
	PlanDigest           string    `json:"plan_digest"`
	BeforeDigest         string    `json:"before_digest"`
	AfterDigest          string    `json:"after_digest"`
	Result               string    `json:"result"`
	HTTPStatus           int       `json:"http_status"`
	ObservedAt           time.Time `json:"observed_at"`
	IntegrityDigest      string    `json:"integrity_digest"`
}

type Executor struct {
	baseURL        *url.URL
	client         *http.Client
	permitVerifier egeproto.SignatureVerifier
	journal        JournalAppender
	clock          func() time.Time
}

func NewExecutor(
	baseURL string,
	client *http.Client,
	permitVerifier egeproto.SignatureVerifier,
	journalAppender JournalAppender,
	clock func() time.Time,
) (*Executor, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New("CRM base URL is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse CRM base URL: %w", err)
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return nil, errors.New("CRM base URL must use HTTPS except for loopback tests")
	}
	if parsed.Host == "" {
		return nil, errors.New("CRM base URL host is required")
	}
	if parsed.User != nil {
		return nil, errors.New("CRM base URL must not embed credentials")
	}
	if client == nil {
		client = http.DefaultClient
	}
	if permitVerifier == nil {
		return nil, errors.New("permit verifier is required")
	}
	if journalAppender == nil {
		return nil, errors.New("tamper-evident journal is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Executor{
		baseURL:        parsed,
		client:         client,
		permitVerifier: permitVerifier,
		journal:        journalAppender,
		clock:          clock,
	}, nil
}

func DigestCustomerUpdatePlan(plan CustomerUpdatePlan) (string, error) {
	if strings.TrimSpace(plan.CustomerID) == "" {
		return "", errors.New("customer_id is required")
	}
	if len(plan.Patch) == 0 {
		return "", errors.New("customer patch is required")
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("marshal customer update plan: %w", err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (e *Executor) Execute(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	plan CustomerUpdatePlan,
) (OutcomeEvidence, error) {
	if err := evidencepipeline.Verify(packet); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("verify evidence packet: %w", err)
	}
	if err := egeproto.VerifyPermit(ctx, e.permitVerifier, permit); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("verify execution permit: %w", err)
	}
	if err := evidencepipeline.VerifyPermitPacketBinding(packet, permit.Claims); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("verify permit/evidence binding: %w", err)
	}
	now := e.clock().UTC()
	if permit.Claims.ValidUntil.IsZero() || now.After(permit.Claims.ValidUntil.UTC()) {
		return OutcomeEvidence{}, errors.New("execution permit expired")
	}
	if packet.Action.Kind != "crm.customer_update" ||
		packet.Action.Operation != "update_customer" ||
		packet.Action.Tool != "crm.http-json" {
		return OutcomeEvidence{}, errors.New("unsupported CRM EEP action")
	}
	if permit.Claims.Target.Type != "customer" {
		return OutcomeEvidence{}, errors.New("CRM permit target type must be customer")
	}
	if strings.TrimSpace(plan.CustomerID) != permit.Claims.Target.Name {
		return OutcomeEvidence{}, errors.New("customer update plan target mismatch")
	}
	planDigest, err := DigestCustomerUpdatePlan(plan)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	if permit.Claims.PlanDigest != planDigest {
		return OutcomeEvidence{}, errors.New("customer update plan digest mismatch")
	}

	authEvent, err := journal.AuthorizationEventFromEvidenceBoundPermit(
		ctx,
		e.permitVerifier,
		permit,
		now,
	)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	if _, err := e.journal.Append(ctx, authEvent); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("journal authorization before mutation: %w", err)
	}

	before, err := e.getCustomer(ctx, plan.CustomerID)
	if err != nil {
		return OutcomeEvidence{}, fmt.Errorf("read customer before mutation: %w", err)
	}
	beforeDigest, err := journal.DigestPayload(before)
	if err != nil {
		return OutcomeEvidence{}, err
	}

	status, err := e.patchCustomer(ctx, plan.CustomerID, plan.Patch)
	if err != nil {
		return OutcomeEvidence{}, fmt.Errorf("apply customer mutation: %w", err)
	}

	after, err := e.getCustomer(ctx, plan.CustomerID)
	if err != nil {
		return OutcomeEvidence{}, fmt.Errorf("read customer after mutation: %w", err)
	}
	afterDigest, err := journal.DigestPayload(after)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	permitDigest, err := journal.DigestPayload(permit)
	if err != nil {
		return OutcomeEvidence{}, err
	}

	result := "APPLIED"
	if beforeDigest == afterDigest {
		result = "NO_STATE_CHANGE"
	}
	outcome := OutcomeEvidence{
		APIVersion:           OutcomeVersion,
		IntentID:             permit.Claims.IntentID,
		Target:               permit.Claims.Target.Type + "/" + permit.Claims.Target.Name,
		EvidencePacketDigest: packet.Integrity.Digest,
		PermitDigest:         permitDigest,
		PlanDigest:           planDigest,
		BeforeDigest:         beforeDigest,
		AfterDigest:          afterDigest,
		Result:               result,
		HTTPStatus:           status,
		ObservedAt:           e.clock().UTC(),
	}
	outcomeDigest, err := digestOutcome(outcome)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	outcome.IntegrityDigest = outcomeDigest

	if _, err := e.journal.Append(ctx, journal.Event{
		Type:                 journal.EventOutcome,
		ActionID:             permit.Claims.IntentID,
		Target:               outcome.Target,
		EvidenceDigest:       permit.Claims.EvidenceDigest,
		EvidencePacketDigest: packet.Integrity.Digest,
		PlanDigest:           planDigest,
		OutcomeVerdict:       outcome.Result,
		PayloadDigest:        outcome.IntegrityDigest,
		OccurredAt:           outcome.ObservedAt,
	}); err != nil {
		return outcome, fmt.Errorf("mutation completed but outcome journal append failed: %w", err)
	}
	return outcome, nil
}

func VerifyOutcome(outcome OutcomeEvidence) error {
	if outcome.APIVersion != OutcomeVersion {
		return fmt.Errorf("unsupported outcome version %q", outcome.APIVersion)
	}
	if outcome.IntegrityDigest == "" {
		return errors.New("outcome integrity digest is required")
	}
	actual, err := digestOutcome(outcome)
	if err != nil {
		return err
	}
	if actual != outcome.IntegrityDigest {
		return errors.New("outcome integrity mismatch")
	}
	return nil
}

func digestOutcome(outcome OutcomeEvidence) (string, error) {
	unsigned := outcome
	unsigned.IntegrityDigest = ""
	return journal.DigestPayload(unsigned)
}

func (e *Executor) getCustomer(ctx context.Context, customerID string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.customerURL(customerID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("CRM GET returned HTTP %d", resp.StatusCode)
	}
	var state map[string]any
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode CRM customer: %w", err)
	}
	return state, nil
}

func (e *Executor) patchCustomer(ctx context.Context, customerID string, patch map[string]any) (int, error) {
	body, err := json.Marshal(patch)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, e.customerURL(customerID), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("CRM PATCH returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (e *Executor) customerURL(customerID string) string {
	u := *e.baseURL
	basePath := strings.TrimSuffix(u.Path, "/")
	u.Path = basePath + "/customers/" + url.PathEscape(customerID)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func isLoopbackHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
