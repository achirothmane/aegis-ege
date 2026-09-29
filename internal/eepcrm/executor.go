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

const (
	OutcomeVersion           = "aegis.eep/crm-outcome/v0alpha2"
	CRMAdapterProfileVersion = "aegis.eep/crm-http-json/v1"

	headerDestinationID = "X-Aegis-Destination-ID"
	headerAccountID     = "X-Aegis-Account-ID"
)

var (
	ErrMutationOutcomeUnknown   = errors.New("CRM mutation outcome is unknown")
	ErrPostconditionNotVerified = errors.New("CRM intended postcondition not verified")
)

type JournalAppender interface {
	Append(context.Context, journal.Event) (journal.Entry, error)
}

type DestinationConfig struct {
	BaseURL        string
	DestinationID  string
	AccountID      string
	AdapterProfile string
}

type CustomerUpdatePlan struct {
	CustomerID string         `json:"customer_id"`
	Patch      map[string]any `json:"patch"`
}

type OutcomeEvidence struct {
	APIVersion            string                   `json:"api_version"`
	PostconditionProfile  string                   `json:"postcondition_profile"`
	IntentID              string                   `json:"intent_id"`
	Target                string                   `json:"target"`
	EvidencePacketDigest  string                   `json:"evidence_packet_digest"`
	PermitDigest          string                   `json:"permit_digest"`
	PlanDigest            string                   `json:"plan_digest"`
	BeforeDigest          string                   `json:"before_digest"`
	AfterDigest           string                   `json:"after_digest,omitempty"`
	Result                PostconditionResult      `json:"result"`
	RequestAcceptance     RequestAcceptance        `json:"request_acceptance"`
	ObservationStatus     ObservationStatus        `json:"observation_status"`
	ObservationCount      int                      `json:"observation_count"`
	Postcondition         *PostconditionEvaluation `json:"postcondition,omitempty"`
	HTTPStatus            int                      `json:"http_status,omitempty"`
	ObservedAt            time.Time                `json:"observed_at"`
	IntegrityDigest       string                   `json:"integrity_digest"`
}

type customerSnapshot struct {
	State           map[string]any
	ResourceVersion string
	DestinationID   string
	AccountID       string
}

type Executor struct {
	baseURL        *url.URL
	destinationID  string
	accountID      string
	adapterProfile string
	client         *http.Client
	permitVerifier egeproto.SignatureVerifier
	journal        JournalAppender
	attempts       AttemptStore
	clock          func() time.Time
}

func NewExecutor(
	destination DestinationConfig,
	client *http.Client,
	permitVerifier egeproto.SignatureVerifier,
	journalAppender JournalAppender,
	attemptStore AttemptStore,
	clock func() time.Time,
) (*Executor, error) {
	baseURL := strings.TrimSpace(destination.BaseURL)
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
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("CRM base URL must not contain query or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")

	destinationID := strings.TrimSpace(destination.DestinationID)
	accountID := strings.TrimSpace(destination.AccountID)
	adapterProfile := strings.TrimSpace(destination.AdapterProfile)
	if destinationID == "" {
		return nil, errors.New("CRM destination id is required")
	}
	if accountID == "" {
		return nil, errors.New("CRM account id is required")
	}
	if adapterProfile != CRMAdapterProfileVersion {
		return nil, fmt.Errorf("unsupported CRM adapter profile %q", adapterProfile)
	}
	if permitVerifier == nil {
		return nil, errors.New("permit verifier is required")
	}
	if journalAppender == nil {
		return nil, errors.New("tamper-evident journal is required")
	}
	if attemptStore == nil {
		return nil, errors.New("durable CRM attempt store is required")
	}
	if clock == nil {
		clock = time.Now
	}
	if client == nil {
		client = http.DefaultClient
	}
	isolatedClient := *client
	isolatedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Executor{
		baseURL:        parsed,
		destinationID:  destinationID,
		accountID:      accountID,
		adapterProfile: adapterProfile,
		client:         &isolatedClient,
		permitVerifier: permitVerifier,
		journal:        journalAppender,
		attempts:       attemptStore,
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
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("marshal customer update plan: %w", err)
	}
	body, err := egeproto.CanonicalJSON(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize customer update plan: %w", err)
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
	if permit.Claims.ValidUntil.IsZero() || !now.Before(permit.Claims.ValidUntil.UTC()) {
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
	if err := e.validateExecutionBinding(packet, permit.Claims); err != nil {
		return OutcomeEvidence{}, err
	}

	planDigest, err := DigestCustomerUpdatePlan(plan)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	if permit.Claims.PlanDigest != planDigest {
		return OutcomeEvidence{}, errors.New("customer update plan digest mismatch")
	}
	permitDigest, err := journal.DigestPayload(permit)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	attemptID, err := MutationAttemptID(permitDigest, planDigest)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	binding := permit.Claims.ExecutionBinding
	observationHandle := e.customerURL(plan.CustomerID)
	attempt := AttemptRecord{
		Version:                 AttemptRecordVersion,
		AttemptID:               attemptID,
		State:                   AttemptClaimed,
		IntentID:                permit.Claims.IntentID,
		PermitDigest:            permitDigest,
		PlanDigest:              planDigest,
		DestinationID:           binding.DestinationID,
		AccountID:               binding.AccountID,
		Endpoint:                binding.Endpoint,
		AdapterProfile:          binding.AdapterProfile,
		CustomerID:              plan.CustomerID,
		Operation:               permit.Claims.Action,
		ExpectedResourceVersion: binding.ExpectedResourceVersion,
		ObservationHandle:       observationHandle,
		ClaimedAt:               now,
		UpdatedAt:               now,
	}
	if err := e.attempts.Claim(ctx, attempt); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("claim CRM mutation attempt: %w", err)
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
	authEvent.AttemptID = attemptID
	authEvent.DestinationID = binding.DestinationID
	authEvent.AccountID = binding.AccountID
	authEvent.ObservationHandle = observationHandle
	authEvent.AttemptState = string(AttemptClaimed)
	if _, err := e.journal.Append(ctx, authEvent); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("journal authorization before mutation: %w", err)
	}

	before, err := e.getCustomer(ctx, plan.CustomerID)
	if err != nil {
		_, _ = e.attempts.Transition(
			context.Background(), attemptID, AttemptClaimed, AttemptBlocked,
			0, "precondition read failed: "+err.Error(), e.clock().UTC(),
		)
		return OutcomeEvidence{}, fmt.Errorf("read customer before mutation: %w", err)
	}
	if err := e.validateSnapshotBinding(before, binding, plan.CustomerID); err != nil {
		_, _ = e.attempts.Transition(
			context.Background(), attemptID, AttemptClaimed, AttemptBlocked,
			0, err.Error(), e.clock().UTC(),
		)
		return OutcomeEvidence{}, err
	}
	beforeDigest, err := journal.DigestPayload(before.State)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	precondition, err := EvaluateCustomerUpdatePostcondition(plan, before.State)
	if err != nil {
		return OutcomeEvidence{}, fmt.Errorf("evaluate pre-mutation postcondition: %w", err)
	}
	if precondition.Result == PostconditionVerified {
		preconditionCopy := precondition
		outcome, err := newOutcomeEvidence(
			permit.Claims.IntentID,
			permit.Claims.Target,
			packet.Integrity.Digest,
			permitDigest,
			planDigest,
			beforeDigest,
			beforeDigest,
			PostconditionAlreadySatisfied,
			RequestNotDispatched,
			ObservationPreMutation,
			1,
			&preconditionCopy,
			0,
			e.clock().UTC(),
		)
		if err != nil {
			return OutcomeEvidence{}, err
		}
		if err := e.appendOutcomeEvent(
			ctx,
			packet,
			permit,
			attemptID,
			binding,
			observationHandle,
			AttemptCompleted,
			outcome,
		); err != nil {
			return outcome, fmt.Errorf("already-satisfied outcome journal append failed: %w", err)
		}
		if _, err := e.attempts.Transition(
			context.Background(), attemptID, AttemptClaimed, AttemptCompleted,
			0, string(outcome.Result), e.clock().UTC(),
		); err != nil {
			return outcome, fmt.Errorf("already-satisfied attempt finalization failed: %w", err)
		}
		return outcome, nil
	}

	executionEvent := journal.Event{
		Type:                 journal.EventExecution,
		ActionID:             permit.Claims.IntentID,
		Target:               permit.Claims.Target.Type + "/" + permit.Claims.Target.Name,
		EvidenceDigest:       permit.Claims.EvidenceDigest,
		EvidencePacketDigest: packet.Integrity.Digest,
		PlanDigest:           planDigest,
		AttemptID:            attemptID,
		DestinationID:        binding.DestinationID,
		AccountID:            binding.AccountID,
		ObservationHandle:    observationHandle,
		AttemptState:         string(AttemptPossibleEffect),
		OccurredAt:           e.clock().UTC(),
	}
	if _, err := e.journal.Append(ctx, executionEvent); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("journal dispatch intent before mutation: %w", err)
	}
	if _, err := e.attempts.Transition(
		ctx, attemptID, AttemptClaimed, AttemptPossibleEffect, 0,
		"dispatch boundary entered", e.clock().UTC(),
	); err != nil {
		return OutcomeEvidence{}, fmt.Errorf("persist possible CRM effect before dispatch: %w", err)
	}

	status, dispatchErr := e.patchCustomer(
		ctx,
		plan.CustomerID,
		plan.Patch,
		binding.ExpectedResourceVersion,
	)
	if dispatchErr != nil && status == http.StatusPreconditionFailed {
		_, transitionErr := e.attempts.Transition(
			context.Background(), attemptID, AttemptPossibleEffect, AttemptBlocked,
			status, "destination rejected stale precondition", e.clock().UTC(),
		)
		if transitionErr != nil {
			return OutcomeEvidence{}, fmt.Errorf("CRM precondition failed and attempt finalization failed: %w", transitionErr)
		}
		return OutcomeEvidence{}, errors.New("CRM destination rejected stale precondition")
	}

	acceptance := RequestAcceptanceUnknown
	attemptState := AttemptPossibleEffect
	if dispatchErr == nil {
		acceptance = RequestAccepted
		if _, err := e.attempts.Transition(
			ctx, attemptID, AttemptPossibleEffect, AttemptAccepted,
			status, "destination returned successful mutation response", e.clock().UTC(),
		); err != nil {
			return OutcomeEvidence{}, fmt.Errorf("persist accepted CRM effect: %w", err)
		}
		attemptState = AttemptAccepted
	}

	observation := e.observePostcondition(ctx, plan)
	if observation.Err != nil {
		outcome, err := newOutcomeEvidence(
			permit.Claims.IntentID,
			permit.Claims.Target,
			packet.Integrity.Digest,
			permitDigest,
			planDigest,
			beforeDigest,
			observation.AfterDigest,
			PostconditionUnknown,
			acceptance,
			observation.Status,
			observation.Count,
			observation.Evaluation,
			status,
			e.clock().UTC(),
		)
		if err != nil {
			return OutcomeEvidence{}, err
		}
		if err := e.appendOutcomeEvent(
			context.Background(),
			packet,
			permit,
			attemptID,
			binding,
			observationHandle,
			attemptState,
			outcome,
		); err != nil {
			return outcome, fmt.Errorf("%w: observation failed and outcome journal append failed: %v", ErrMutationOutcomeUnknown, err)
		}
		if dispatchErr != nil {
			return outcome, fmt.Errorf("%w: dispatch=%v; observation=%v", ErrMutationOutcomeUnknown, dispatchErr, observation.Err)
		}
		return outcome, fmt.Errorf("%w: accepted request observation=%v", ErrMutationOutcomeUnknown, observation.Err)
	}

	result := observation.Evaluation.Result
	outcome, err := newOutcomeEvidence(
		permit.Claims.IntentID,
		permit.Claims.Target,
		packet.Integrity.Digest,
		permitDigest,
		planDigest,
		beforeDigest,
		observation.AfterDigest,
		result,
		acceptance,
		observation.Status,
		observation.Count,
		observation.Evaluation,
		status,
		e.clock().UTC(),
	)
	if err != nil {
		return OutcomeEvidence{}, err
	}

	if acceptance == RequestAcceptanceUnknown && result != PostconditionVerified {
		if err := e.appendOutcomeEvent(
			context.Background(),
			packet,
			permit,
			attemptID,
			binding,
			observationHandle,
			AttemptPossibleEffect,
			outcome,
		); err != nil {
			return outcome, fmt.Errorf("%w: unresolved dispatch and outcome journal append failed: %v", ErrMutationOutcomeUnknown, err)
		}
		return outcome, fmt.Errorf(
			"%w: dispatch=%v; observed postcondition=%s",
			ErrMutationOutcomeUnknown,
			dispatchErr,
			result,
		)
	}

	if err := e.appendOutcomeEvent(
		ctx,
		packet,
		permit,
		attemptID,
		binding,
		observationHandle,
		AttemptCompleted,
		outcome,
	); err != nil {
		return outcome, fmt.Errorf("postcondition outcome journal append failed: %w", err)
	}
	if _, err := e.attempts.Transition(
		context.Background(), attemptID, attemptState, AttemptCompleted,
		status, string(outcome.Result), e.clock().UTC(),
	); err != nil {
		return outcome, fmt.Errorf("postcondition attempt finalization failed: %w", err)
	}
	if result != PostconditionVerified {
		return outcome, fmt.Errorf("%w: %s", ErrPostconditionNotVerified, result)
	}
	return outcome, nil
}

type postconditionObservation struct {
	Evaluation *PostconditionEvaluation
	AfterDigest string
	Status      ObservationStatus
	Count       int
	Err         error
}

func (e *Executor) observePostcondition(
	ctx context.Context,
	plan CustomerUpdatePlan,
) postconditionObservation {
	const observationReads = 3
	evaluations := make([]PostconditionEvaluation, 0, observationReads)
	snapshots := make([]customerSnapshot, 0, observationReads)
	for i := 0; i < observationReads; i++ {
		snapshot, err := e.getCustomer(ctx, plan.CustomerID)
		if err != nil {
			return postconditionObservation{
				Status: ObservationUnavailable,
				Count:  len(evaluations),
				Err:    fmt.Errorf("post-mutation read %d failed: %w", i+1, err),
			}
		}
		if err := e.validateDestinationIdentity(snapshot); err != nil {
			return postconditionObservation{
				Status: ObservationUnavailable,
				Count:  len(evaluations) + 1,
				Err:    fmt.Errorf("post-mutation destination binding failed: %w", err),
			}
		}
		if err := validateObservedCustomerTarget(snapshot.State, plan.CustomerID); err != nil {
			return postconditionObservation{
				Status: ObservationWrongTarget,
				Count:  len(evaluations) + 1,
				Err:    err,
			}
		}
		evaluation, err := EvaluateCustomerUpdatePostcondition(plan, snapshot.State)
		if err != nil {
			return postconditionObservation{
				Status: ObservationUnavailable,
				Count:  len(evaluations) + 1,
				Err:    err,
			}
		}
		evaluations = append(evaluations, evaluation)
		snapshots = append(snapshots, snapshot)
	}
	last := evaluations[len(evaluations)-1]
	previous := evaluations[len(evaluations)-2]
	lastSnapshot := snapshots[len(snapshots)-1]
	afterDigest, err := journal.DigestPayload(lastSnapshot.State)
	if err != nil {
		return postconditionObservation{
			Status: ObservationUnavailable,
			Count:  len(evaluations),
			Err:    err,
		}
	}
	if !EquivalentPostconditionObservation(previous, last) {
		lastCopy := last
		return postconditionObservation{
			Evaluation:  &lastCopy,
			AfterDigest: afterDigest,
			Status:      ObservationContradictory,
			Count:       len(evaluations),
			Err:         errors.New("postcondition observations did not stabilize"),
		}
	}
	lastCopy := last
	return postconditionObservation{
		Evaluation:  &lastCopy,
		AfterDigest: afterDigest,
		Status:      ObservationStable,
		Count:       len(evaluations),
	}
}

func newOutcomeEvidence(
	intentID string,
	target egeproto.Target,
	evidencePacketDigest string,
	permitDigest string,
	planDigest string,
	beforeDigest string,
	afterDigest string,
	result PostconditionResult,
	acceptance RequestAcceptance,
	observation ObservationStatus,
	observationCount int,
	evaluation *PostconditionEvaluation,
	httpStatus int,
	observedAt time.Time,
) (OutcomeEvidence, error) {
	outcome := OutcomeEvidence{
		APIVersion:           OutcomeVersion,
		PostconditionProfile: PostconditionProfileVersion,
		IntentID:             intentID,
		Target:               target.Type + "/" + target.Name,
		EvidencePacketDigest: evidencePacketDigest,
		PermitDigest:         permitDigest,
		PlanDigest:           planDigest,
		BeforeDigest:         beforeDigest,
		AfterDigest:          afterDigest,
		Result:               result,
		RequestAcceptance:    acceptance,
		ObservationStatus:    observation,
		ObservationCount:     observationCount,
		Postcondition:        evaluation,
		HTTPStatus:           httpStatus,
		ObservedAt:           observedAt.UTC(),
	}
	if err := validateOutcomeSemantics(outcome); err != nil {
		return OutcomeEvidence{}, err
	}
	digest, err := digestOutcome(outcome)
	if err != nil {
		return OutcomeEvidence{}, err
	}
	outcome.IntegrityDigest = digest
	return outcome, nil
}

func (e *Executor) appendOutcomeEvent(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	attemptID string,
	binding *egeproto.ExecutionBindingClaims,
	observationHandle string,
	attemptState AttemptState,
	outcome OutcomeEvidence,
) error {
	_, err := e.journal.Append(ctx, journal.Event{
		Type:                 journal.EventOutcome,
		ActionID:             permit.Claims.IntentID,
		Target:               outcome.Target,
		EvidenceDigest:       permit.Claims.EvidenceDigest,
		EvidencePacketDigest: packet.Integrity.Digest,
		PlanDigest:           outcome.PlanDigest,
		AttemptID:            attemptID,
		DestinationID:        binding.DestinationID,
		AccountID:            binding.AccountID,
		ObservationHandle:    observationHandle,
		AttemptState:         string(attemptState),
		OutcomeVerdict:       string(outcome.Result),
		PayloadDigest:        outcome.IntegrityDigest,
		OccurredAt:           outcome.ObservedAt,
	})
	return err
}

func (e *Executor) validateExecutionBinding(
	packet evidencepipeline.Packet,
	claims egeproto.PermitClaims,
) error {
	binding := claims.ExecutionBinding
	if binding == nil {
		return errors.New("CRM execution permit is missing destination binding")
	}
	if packet.Context.ExecutionBinding == nil {
		return errors.New("CRM evidence packet is missing destination binding")
	}
	if binding.DestinationID != e.destinationID {
		return errors.New("CRM destination identity mismatch")
	}
	if binding.AccountID != e.accountID {
		return errors.New("CRM account identity mismatch")
	}
	if binding.Endpoint != e.baseURL.String() {
		return errors.New("CRM endpoint binding mismatch")
	}
	if binding.AdapterProfile != e.adapterProfile {
		return errors.New("CRM adapter profile mismatch")
	}
	if strings.TrimSpace(binding.ExpectedResourceVersion) == "" {
		return errors.New("CRM expected resource version is required")
	}
	if claims.ResourceVersion != binding.ExpectedResourceVersion {
		return errors.New("CRM permit resource version mismatch")
	}
	return nil
}

func (e *Executor) validateSnapshotBinding(
	snapshot customerSnapshot,
	binding *egeproto.ExecutionBindingClaims,
	customerID string,
) error {
	if err := e.validateDestinationIdentity(snapshot); err != nil {
		return err
	}
	if err := validateObservedCustomerTarget(snapshot.State, customerID); err != nil {
		return err
	}
	if strings.TrimSpace(snapshot.ResourceVersion) == "" {
		return errors.New("CRM destination does not expose required conditional-write resource version")
	}
	if snapshot.ResourceVersion != binding.ExpectedResourceVersion {
		return errors.New("CRM precondition is stale")
	}
	return nil
}

func validateObservedCustomerTarget(state map[string]any, expectedCustomerID string) error {
	rawID, ok := state["id"]
	if !ok {
		return errors.New("CRM customer observation is missing id")
	}
	customerID, ok := rawID.(string)
	if !ok || strings.TrimSpace(customerID) == "" {
		return errors.New("CRM customer observation id is invalid")
	}
	if customerID != expectedCustomerID {
		return fmt.Errorf(
			"CRM customer observation target mismatch: got %q want %q",
			customerID,
			expectedCustomerID,
		)
	}
	return nil
}

func (e *Executor) validateDestinationIdentity(snapshot customerSnapshot) error {
	if snapshot.DestinationID != e.destinationID {
		return errors.New("CRM destination response identity mismatch")
	}
	if snapshot.AccountID != e.accountID {
		return errors.New("CRM destination response account mismatch")
	}
	return nil
}

func VerifyOutcome(outcome OutcomeEvidence) error {
	if outcome.APIVersion != OutcomeVersion {
		return fmt.Errorf("unsupported outcome version %q", outcome.APIVersion)
	}
	if err := validateOutcomeSemantics(outcome); err != nil {
		return err
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

func validateOutcomeSemantics(outcome OutcomeEvidence) error {
	if outcome.PostconditionProfile != PostconditionProfileVersion {
		return fmt.Errorf("unsupported postcondition profile %q", outcome.PostconditionProfile)
	}
	if strings.TrimSpace(outcome.IntentID) == "" ||
		strings.TrimSpace(outcome.Target) == "" ||
		strings.TrimSpace(outcome.EvidencePacketDigest) == "" ||
		strings.TrimSpace(outcome.PermitDigest) == "" ||
		strings.TrimSpace(outcome.PlanDigest) == "" ||
		strings.TrimSpace(outcome.BeforeDigest) == "" {
		return errors.New("outcome identity/evidence binding is incomplete")
	}
	if outcome.ObservationCount < 0 {
		return errors.New("outcome observation count is invalid")
	}
	if outcome.Postcondition != nil {
		if err := ValidatePostconditionEvaluation(*outcome.Postcondition); err != nil {
			return fmt.Errorf("postcondition evidence invalid: %w", err)
		}
	}
	switch outcome.Result {
	case PostconditionAlreadySatisfied:
		if outcome.RequestAcceptance != RequestNotDispatched ||
			outcome.ObservationStatus != ObservationPreMutation ||
			outcome.ObservationCount != 1 ||
			outcome.HTTPStatus != 0 ||
			outcome.AfterDigest == "" ||
			outcome.AfterDigest != outcome.BeforeDigest ||
			outcome.Postcondition == nil ||
			outcome.Postcondition.Result != PostconditionVerified {
			return errors.New("ALREADY_SATISFIED outcome is inconsistent")
		}
	case PostconditionVerified:
		if outcome.RequestAcceptance != RequestAccepted &&
			outcome.RequestAcceptance != RequestAcceptanceUnknown {
			return errors.New("VERIFIED outcome has invalid request acceptance")
		}
		if outcome.ObservationStatus != ObservationStable ||
			outcome.ObservationCount < 2 ||
			outcome.AfterDigest == "" ||
			outcome.Postcondition == nil ||
			outcome.Postcondition.Result != PostconditionVerified {
			return errors.New("VERIFIED outcome lacks stable intended-postcondition evidence")
		}
	case PostconditionPartial:
		if outcome.RequestAcceptance != RequestAccepted ||
			outcome.ObservationStatus != ObservationStable ||
			outcome.ObservationCount < 2 ||
			outcome.AfterDigest == "" ||
			outcome.Postcondition == nil ||
			outcome.Postcondition.Result != PostconditionPartial {
			return errors.New("PARTIAL outcome is inconsistent")
		}
	case PostconditionUnsatisfied:
		if outcome.RequestAcceptance != RequestAccepted ||
			outcome.ObservationStatus != ObservationStable ||
			outcome.ObservationCount < 2 ||
			outcome.AfterDigest == "" ||
			outcome.Postcondition == nil ||
			outcome.Postcondition.Result != PostconditionUnsatisfied {
			return errors.New("UNSATISFIED outcome is inconsistent")
		}
	case PostconditionUnknown:
		if outcome.RequestAcceptance != RequestAccepted &&
			outcome.RequestAcceptance != RequestAcceptanceUnknown {
			return errors.New("UNKNOWN outcome has invalid request acceptance")
		}
		switch outcome.ObservationStatus {
		case ObservationUnavailable, ObservationContradictory, ObservationWrongTarget:
		default:
			return errors.New("UNKNOWN outcome requires unavailable, contradictory, or wrong-target observation")
		}
	default:
		return fmt.Errorf("unsupported outcome result %q", outcome.Result)
	}
	return nil
}

func digestOutcome(outcome OutcomeEvidence) (string, error) {
	unsigned := outcome
	unsigned.IntegrityDigest = ""
	return journal.DigestPayload(unsigned)
}

func (e *Executor) getCustomer(ctx context.Context, customerID string) (customerSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.customerURL(customerID), nil)
	if err != nil {
		return customerSnapshot{}, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return customerSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return customerSnapshot{}, fmt.Errorf("CRM GET returned HTTP %d", resp.StatusCode)
	}
	var state map[string]any
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&state); err != nil {
		return customerSnapshot{}, fmt.Errorf("decode CRM customer: %w", err)
	}
	return customerSnapshot{
		State:           state,
		ResourceVersion: strings.TrimSpace(resp.Header.Get("ETag")),
		DestinationID:   strings.TrimSpace(resp.Header.Get(headerDestinationID)),
		AccountID:       strings.TrimSpace(resp.Header.Get(headerAccountID)),
	}, nil
}

func (e *Executor) patchCustomer(
	ctx context.Context,
	customerID string,
	patch map[string]any,
	expectedResourceVersion string,
) (int, error) {
	body, err := json.Marshal(patch)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, e.customerURL(customerID), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", expectedResourceVersion)
	req.Header.Set(headerDestinationID, e.destinationID)
	req.Header.Set(headerAccountID, e.accountID)
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
