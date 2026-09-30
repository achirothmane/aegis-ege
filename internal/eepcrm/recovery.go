package eepcrm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

const ClosureEvidenceVersion = "aegis.eep/crm-closure/v1"

var (
	ErrAttemptClosureState = errors.New("CRM attempt is not eligible for closure reconciliation")
	ErrAttemptRetiredUnknown = errors.New("CRM attempt was administratively retired UNKNOWN")
)

type ClosureDisposition string

const (
	ClosureObservationPending ClosureDisposition = "OBSERVATION_PENDING"
	ClosureObservedCompleted  ClosureDisposition = "OBSERVED_COMPLETED"
	ClosureRetiredUnknown     ClosureDisposition = "RETIRED_UNKNOWN"
)

type ClosureEvidence struct {
	APIVersion            string                   `json:"api_version"`
	AttemptID             string                   `json:"attempt_id"`
	IntentID              string                   `json:"intent_id"`
	Target                string                   `json:"target"`
	PermitDigest          string                   `json:"permit_digest"`
	PlanDigest            string                   `json:"plan_digest"`
	DestinationID         string                   `json:"destination_id"`
	AccountID             string                   `json:"account_id"`
	ObservationHandle     string                   `json:"observation_handle"`
	StateBefore           AttemptState             `json:"state_before"`
	StateAfter            AttemptState             `json:"state_after"`
	Disposition           ClosureDisposition       `json:"disposition"`
	Result                PostconditionResult      `json:"result"`
	RequestAcceptance     RequestAcceptance        `json:"request_acceptance"`
	ObservationStatus     ObservationStatus        `json:"observation_status"`
	ObservationCount      int                      `json:"observation_count"`
	Postcondition         *PostconditionEvaluation `json:"postcondition,omitempty"`
	ResidualCustody       bool                     `json:"residual_custody"`
	NewMutationDispatched bool                     `json:"new_mutation_dispatched"`
	Detail                string                   `json:"detail,omitempty"`
	ObservedAt            time.Time                `json:"observed_at"`
	IntegrityDigest       string                   `json:"integrity_digest"`
}

// ReconcileAttempt performs observation-only recovery for a durable unresolved
// CRM attempt. It never dispatches PATCH. A signed original permit establishes
// the exact historical action/binding identity; permit expiry is intentionally
// not treated as new mutation authority because this path creates no new effect.
func (e *Executor) ReconcileAttempt(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	plan CustomerUpdatePlan,
) (ClosureEvidence, error) {
	record, attemptID, binding, err := e.loadRecoveryAttempt(ctx, packet, permit, plan)
	if err != nil {
		return ClosureEvidence{}, err
	}
	switch record.State {
	case AttemptCompleted:
		return ClosureEvidence{}, fmt.Errorf("%w: state=%s", ErrAttemptClosureState, record.State)
	case AttemptRetiredUnknown:
		return ClosureEvidence{}, ErrAttemptRetiredUnknown
	case AttemptPossibleEffect, AttemptAccepted:
	default:
		return ClosureEvidence{}, fmt.Errorf("%w: state=%s", ErrAttemptClosureState, record.State)
	}

	observation := e.observePostcondition(ctx, plan)
	acceptance := acceptanceForAttemptState(record.State)
	if observation.Err != nil {
		evidence, buildErr := newClosureEvidence(
			record,
			record.State,
			ClosureObservationPending,
			PostconditionUnknown,
			acceptance,
			observation.Status,
			observation.Count,
			observation.Evaluation,
			true,
			"observation remains unresolved: "+observation.Err.Error(),
			e.clock().UTC(),
		)
		if buildErr != nil {
			return ClosureEvidence{}, buildErr
		}
		if err := e.appendClosureEvent(
			context.Background(),
			packet,
			permit,
			attemptID,
			binding,
			evidence,
		); err != nil {
			return evidence, fmt.Errorf("%w: recovery observation journal append failed: %v", ErrMutationOutcomeUnknown, err)
		}
		return evidence, fmt.Errorf("%w: recovery observation=%v", ErrMutationOutcomeUnknown, observation.Err)
	}

	if observation.Evaluation == nil {
		return ClosureEvidence{}, errors.New("recovery observation is missing postcondition evaluation")
	}
	result := observation.Evaluation.Result

	// Unknown request acceptance plus a stable non-verified state still cannot
	// prove whether the prior possible effect happened. Retain custody.
	if record.State == AttemptPossibleEffect && result != PostconditionVerified {
		evidence, buildErr := newClosureEvidence(
			record,
			record.State,
			ClosureObservationPending,
			result,
			RequestAcceptanceUnknown,
			observation.Status,
			observation.Count,
			observation.Evaluation,
			true,
			"stable observation does not discharge ambiguous request acceptance",
			e.clock().UTC(),
		)
		if buildErr != nil {
			return ClosureEvidence{}, buildErr
		}
		if err := e.appendClosureEvent(
			context.Background(),
			packet,
			permit,
			attemptID,
			binding,
			evidence,
		); err != nil {
			return evidence, fmt.Errorf("%w: recovery observation journal append failed: %v", ErrMutationOutcomeUnknown, err)
		}
		return evidence, fmt.Errorf(
			"%w: request acceptance UNKNOWN and observed postcondition=%s",
			ErrMutationOutcomeUnknown,
			result,
		)
	}

	evidence, err := newClosureEvidence(
		record,
		AttemptCompleted,
		ClosureObservedCompleted,
		result,
		acceptance,
		observation.Status,
		observation.Count,
		observation.Evaluation,
		false,
		"stable observation closed the retained attempt without a new mutation",
		e.clock().UTC(),
	)
	if err != nil {
		return ClosureEvidence{}, err
	}
	if err := e.appendClosureEvent(ctx, packet, permit, attemptID, binding, evidence); err != nil {
		return evidence, fmt.Errorf("recovery closure journal append failed: %w", err)
	}
	if _, err := e.attempts.Transition(
		context.Background(),
		attemptID,
		record.State,
		AttemptCompleted,
		record.HTTPStatus,
		string(result),
		e.clock().UTC(),
	); err != nil {
		return evidence, fmt.Errorf("recovery attempt finalization failed: %w", err)
	}
	if result != PostconditionVerified {
		return evidence, fmt.Errorf("%w: %s", ErrPostconditionNotVerified, result)
	}
	return evidence, nil
}

// RetireAttemptUnknown performs an explicit administrative UNKNOWN disposition
// for an unresolved fixed attempt. The durable attempt record remains in the
// store as residual custody and replay stays blocked.
func (e *Executor) RetireAttemptUnknown(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	plan CustomerUpdatePlan,
	reason string,
) (ClosureEvidence, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ClosureEvidence{}, errors.New("UNKNOWN retirement reason is required")
	}
	record, attemptID, binding, err := e.loadRecoveryAttempt(ctx, packet, permit, plan)
	if err != nil {
		return ClosureEvidence{}, err
	}
	switch record.State {
	case AttemptPossibleEffect, AttemptAccepted:
	case AttemptRetiredUnknown:
		return ClosureEvidence{}, ErrAttemptRetiredUnknown
	default:
		return ClosureEvidence{}, fmt.Errorf("%w: state=%s", ErrAttemptClosureState, record.State)
	}

	evidence, err := newClosureEvidence(
		record,
		AttemptRetiredUnknown,
		ClosureRetiredUnknown,
		PostconditionUnknown,
		acceptanceForAttemptState(record.State),
		ObservationUnavailable,
		0,
		nil,
		true,
		reason,
		e.clock().UTC(),
	)
	if err != nil {
		return ClosureEvidence{}, err
	}
	if err := e.appendClosureEvent(ctx, packet, permit, attemptID, binding, evidence); err != nil {
		return evidence, fmt.Errorf("UNKNOWN retirement journal append failed: %w", err)
	}
	if _, err := e.attempts.Transition(
		context.Background(),
		attemptID,
		record.State,
		AttemptRetiredUnknown,
		record.HTTPStatus,
		"RETIRED_UNKNOWN: "+reason,
		e.clock().UTC(),
	); err != nil {
		return evidence, fmt.Errorf("UNKNOWN retirement persistence failed: %w", err)
	}
	return evidence, nil
}

func (e *Executor) loadRecoveryAttempt(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	plan CustomerUpdatePlan,
) (AttemptRecord, string, *egeproto.ExecutionBindingClaims, error) {
	if err := evidencepipeline.Verify(packet); err != nil {
		return AttemptRecord{}, "", nil, fmt.Errorf("verify recovery evidence packet: %w", err)
	}
	if err := egeproto.VerifyPermit(ctx, e.permitVerifier, permit); err != nil {
		return AttemptRecord{}, "", nil, fmt.Errorf("verify recovery permit identity: %w", err)
	}
	if err := evidencepipeline.VerifyPermitPacketBinding(packet, permit.Claims); err != nil {
		return AttemptRecord{}, "", nil, fmt.Errorf("verify recovery permit/evidence binding: %w", err)
	}
	if packet.Action.Kind != "crm.customer_update" ||
		packet.Action.Operation != "update_customer" ||
		packet.Action.Tool != "crm.http-json" {
		return AttemptRecord{}, "", nil, errors.New("unsupported CRM EEP recovery action")
	}
	if permit.Claims.Target.Type != "customer" ||
		strings.TrimSpace(plan.CustomerID) != permit.Claims.Target.Name {
		return AttemptRecord{}, "", nil, errors.New("CRM recovery target mismatch")
	}
	if err := e.validateExecutionBinding(packet, permit.Claims); err != nil {
		return AttemptRecord{}, "", nil, err
	}

	planDigest, err := DigestCustomerUpdatePlan(plan)
	if err != nil {
		return AttemptRecord{}, "", nil, err
	}
	if permit.Claims.PlanDigest != planDigest {
		return AttemptRecord{}, "", nil, errors.New("CRM recovery plan digest mismatch")
	}
	permitDigest, err := journal.DigestPayload(permit)
	if err != nil {
		return AttemptRecord{}, "", nil, err
	}
	attemptID, err := MutationAttemptID(permitDigest, planDigest)
	if err != nil {
		return AttemptRecord{}, "", nil, err
	}
	record, err := e.attempts.Load(ctx, attemptID)
	if err != nil {
		return AttemptRecord{}, "", nil, err
	}
	binding := permit.Claims.ExecutionBinding
	if binding == nil {
		return AttemptRecord{}, "", nil, errors.New("CRM recovery binding is missing")
	}
	if record.IntentID != permit.Claims.IntentID ||
		record.PermitDigest != permitDigest ||
		record.PlanDigest != planDigest ||
		record.DestinationID != binding.DestinationID ||
		record.AccountID != binding.AccountID ||
		record.Endpoint != binding.Endpoint ||
		record.AdapterProfile != binding.AdapterProfile ||
		record.CustomerID != plan.CustomerID ||
		record.Operation != permit.Claims.Action ||
		record.ExpectedResourceVersion != binding.ExpectedResourceVersion ||
		record.ObservationHandle != e.customerURL(plan.CustomerID) {
		return AttemptRecord{}, "", nil, errors.New("CRM recovery attempt binding mismatch")
	}
	return record, attemptID, binding, nil
}

func acceptanceForAttemptState(state AttemptState) RequestAcceptance {
	if state == AttemptAccepted {
		return RequestAccepted
	}
	return RequestAcceptanceUnknown
}

func newClosureEvidence(
	record AttemptRecord,
	stateAfter AttemptState,
	disposition ClosureDisposition,
	result PostconditionResult,
	acceptance RequestAcceptance,
	observation ObservationStatus,
	observationCount int,
	evaluation *PostconditionEvaluation,
	residualCustody bool,
	detail string,
	at time.Time,
) (ClosureEvidence, error) {
	evidence := ClosureEvidence{
		APIVersion:            ClosureEvidenceVersion,
		AttemptID:             record.AttemptID,
		IntentID:              record.IntentID,
		Target:                "customer/" + record.CustomerID,
		PermitDigest:          record.PermitDigest,
		PlanDigest:            record.PlanDigest,
		DestinationID:         record.DestinationID,
		AccountID:             record.AccountID,
		ObservationHandle:     record.ObservationHandle,
		StateBefore:           record.State,
		StateAfter:            stateAfter,
		Disposition:           disposition,
		Result:                result,
		RequestAcceptance:     acceptance,
		ObservationStatus:     observation,
		ObservationCount:      observationCount,
		Postcondition:         evaluation,
		ResidualCustody:       residualCustody,
		NewMutationDispatched: false,
		Detail:                strings.TrimSpace(detail),
		ObservedAt:            at.UTC(),
	}
	if err := validateClosureEvidence(evidence); err != nil {
		return ClosureEvidence{}, err
	}
	digest, err := digestClosureEvidence(evidence)
	if err != nil {
		return ClosureEvidence{}, err
	}
	evidence.IntegrityDigest = digest
	return evidence, nil
}

func VerifyClosureEvidence(evidence ClosureEvidence) error {
	if evidence.APIVersion != ClosureEvidenceVersion {
		return fmt.Errorf("unsupported CRM closure evidence version %q", evidence.APIVersion)
	}
	if err := validateClosureEvidence(evidence); err != nil {
		return err
	}
	if strings.TrimSpace(evidence.IntegrityDigest) == "" {
		return errors.New("CRM closure evidence integrity digest is required")
	}
	actual, err := digestClosureEvidence(evidence)
	if err != nil {
		return err
	}
	if actual != evidence.IntegrityDigest {
		return errors.New("CRM closure evidence integrity mismatch")
	}
	return nil
}

func validateClosureEvidence(evidence ClosureEvidence) error {
	if evidence.APIVersion != ClosureEvidenceVersion {
		return fmt.Errorf("unsupported CRM closure evidence version %q", evidence.APIVersion)
	}
	if strings.TrimSpace(evidence.AttemptID) == "" ||
		strings.TrimSpace(evidence.IntentID) == "" ||
		strings.TrimSpace(evidence.Target) == "" ||
		strings.TrimSpace(evidence.PermitDigest) == "" ||
		strings.TrimSpace(evidence.PlanDigest) == "" ||
		strings.TrimSpace(evidence.DestinationID) == "" ||
		strings.TrimSpace(evidence.AccountID) == "" ||
		strings.TrimSpace(evidence.ObservationHandle) == "" ||
		evidence.ObservedAt.IsZero() {
		return errors.New("CRM closure evidence identity/custody binding is incomplete")
	}
	if evidence.NewMutationDispatched {
		return errors.New("CRM recovery closure evidence cannot report a new mutation")
	}
	if evidence.ObservationCount < 0 {
		return errors.New("CRM closure evidence observation count is invalid")
	}
	if evidence.Postcondition != nil {
		if err := ValidatePostconditionEvaluation(*evidence.Postcondition); err != nil {
			return fmt.Errorf("CRM closure postcondition invalid: %w", err)
		}
	}
	switch evidence.Disposition {
	case ClosureObservedCompleted:
		if evidence.StateAfter != AttemptCompleted || evidence.ResidualCustody {
			return errors.New("observed completion must discharge residual custody")
		}
		if evidence.ObservationStatus != ObservationStable ||
			evidence.ObservationCount != 3 ||
			evidence.Postcondition == nil ||
			evidence.Result == PostconditionUnknown {
			return errors.New("observed completion requires stable typed postcondition evidence")
		}
	case ClosureObservationPending:
		if evidence.StateAfter != evidence.StateBefore || !evidence.ResidualCustody {
			return errors.New("pending observation must retain the unresolved attempt state and custody")
		}
	case ClosureRetiredUnknown:
		if evidence.StateAfter != AttemptRetiredUnknown ||
			evidence.Result != PostconditionUnknown ||
			!evidence.ResidualCustody ||
			evidence.ObservationStatus != ObservationUnavailable {
			return errors.New("UNKNOWN retirement must preserve durable residual custody")
		}
	default:
		return fmt.Errorf("unsupported CRM closure disposition %q", evidence.Disposition)
	}
	return nil
}

func digestClosureEvidence(evidence ClosureEvidence) (string, error) {
	unsigned := evidence
	unsigned.IntegrityDigest = ""
	return journal.DigestPayload(unsigned)
}

func (e *Executor) appendClosureEvent(
	ctx context.Context,
	packet evidencepipeline.Packet,
	permit egeproto.Permit,
	attemptID string,
	binding *egeproto.ExecutionBindingClaims,
	evidence ClosureEvidence,
) error {
	_, err := e.journal.Append(ctx, journal.Event{
		Type:                 journal.EventOutcome,
		ActionID:             permit.Claims.IntentID,
		Target:               evidence.Target,
		EvidenceDigest:       permit.Claims.EvidenceDigest,
		EvidencePacketDigest: packet.Integrity.Digest,
		PlanDigest:           evidence.PlanDigest,
		AttemptID:            attemptID,
		DestinationID:        binding.DestinationID,
		AccountID:            binding.AccountID,
		ObservationHandle:    evidence.ObservationHandle,
		AttemptState:         string(evidence.StateAfter),
		OutcomeVerdict:       string(evidence.Result),
		PayloadDigest:        evidence.IntegrityDigest,
		OccurredAt:           evidence.ObservedAt,
	})
	return err
}
