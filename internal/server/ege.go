package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const egeAPIVersion = "aegis.ege/v0alpha1"

type egeTargetDTO struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type egePrepareRequest struct {
	IntentID string       `json:"intent_id"`
	Kind     string       `json:"kind"`
	Target   egeTargetDTO `json:"target"`
}

type egePrepareResponse struct {
	APIVersion       string                     `json:"api_version"`
	IntentID         string                     `json:"intent_id"`
	Kind             string                     `json:"kind"`
	Target           egeTargetDTO               `json:"target"`
	Decision         decision.Decision          `json:"decision"`
	ReasonCodes      []decision.ReasonCode      `json:"reason_codes,omitempty"`
	PlanDigest       string                     `json:"plan_digest,omitempty"`
	EvidenceManifest *egeproto.EvidenceManifest `json:"evidence_manifest,omitempty"`
	Permit           *egeproto.Permit           `json:"permit,omitempty"`
	Snapshot         *snapshotDTO               `json:"snapshot,omitempty"`
	Plan             *planDTO                   `json:"plan,omitempty"`
}

type egeExecutionEBABundle struct {
	EvidenceManifest    *egeproto.EvidenceManifest     `json:"evidence_manifest,omitempty"`
	AssumptionArtifacts []json.RawMessage               `json:"assumption_artifacts,omitempty"`
	AuthorityArtifact   json.RawMessage                 `json:"authority_artifact,omitempty"`
	BudgetArtifact      json.RawMessage                 `json:"budget_artifact,omitempty"`
	Approvals           []egeproto.ApprovalAttestation `json:"approvals,omitempty"`
}

type egeExecuteRequest struct {
	IntentID string                 `json:"intent_id"`
	Kind     string                 `json:"kind"`
	Target   egeTargetDTO           `json:"target"`
	Permit   egeproto.Permit        `json:"permit"`
	EBA      *egeExecutionEBABundle `json:"eba,omitempty"`
}

type egeExecuteResponse struct {
	APIVersion           string                         `json:"api_version"`
	IntentID             string                         `json:"intent_id"`
	Kind                 string                         `json:"kind"`
	Target               egeTargetDTO                   `json:"target"`
	Decision             decision.Decision              `json:"decision"`
	ReasonCodes          []decision.ReasonCode          `json:"reason_codes,omitempty"`
	PlanDigest           string                         `json:"plan_digest,omitempty"`
	Steps                []mutationStepDTO              `json:"steps,omitempty"`
	ConsequenceAdmission *egeproto.ConsequenceAdmission `json:"consequence_admission,omitempty"`
	ExecutionReceipt     *egeproto.ExecutionReceipt     `json:"execution_receipt,omitempty"`
	ProducedEvidence     *egeproto.ReceiptEvidence      `json:"produced_evidence,omitempty"`
	FeedbackError        string                         `json:"feedback_error,omitempty"`
	CapabilityClaimState ExecutionClaimState            `json:"capability_claim_state,omitempty"`
	CapabilityClaimError string                         `json:"capability_claim_error,omitempty"`
}

func normalizeEGEIntent(intentID, kind string, target egeTargetDTO) (string, string, egeTargetDTO, error) {
	intentID = strings.TrimSpace(intentID)
	kind = strings.TrimSpace(kind)
	target.Type = strings.TrimSpace(target.Type)
	target.Name = strings.TrimSpace(target.Name)

	if intentID == "" || kind == "" || target.Type == "" || target.Name == "" {
		return "", "", egeTargetDTO{}, errors.New("intent_id, kind, target.type, and target.name are required")
	}
	return intentID, kind, target, nil
}

func writeEGEAdapterResolutionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnsupportedEGEIntentKind):
		writeError(w, http.StatusUnprocessableEntity, "UNSUPPORTED_INTENT_KIND", err)
	case errors.Is(err, errEGETargetTypeMismatch):
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_TYPE", err)
	default:
		writeError(w, http.StatusInternalServerError, "ADAPTER_REGISTRY_UNAVAILABLE", err)
	}
}

func (s *Server) handleEGEPrepare(w http.ResponseWriter, r *http.Request) {
	var req egePrepareRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}

	intentID, kind, target, err := normalizeEGEIntent(req.IntentID, req.Kind, req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}

	adapter, err := s.egeAdapters.Resolve(kind, target.Type)
	if err != nil {
		writeEGEAdapterResolutionError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	preparation, err := s.egeEvidenceComposer.Compose(ctx, intentID, kind, target)
	if err != nil {
		if errors.Is(err, errUnsupportedEGEIntentKind) || errors.Is(err, errEGETargetTypeMismatch) {
			writeEGEAdapterResolutionError(w, err)
			return
		}
		writeError(w, http.StatusBadGateway, "EVIDENCE_COMPOSITION_FAILED", err)
		return
	}

	response := egePrepareResponse{
		APIVersion:  egeAPIVersion,
		IntentID:    intentID,
		Kind:        kind,
		Target:      target,
		Decision:    preparation.Decision,
		ReasonCodes: append([]decision.ReasonCode(nil), preparation.ReasonCodes...),
		PlanDigest:  preparation.PlanDigest,
		Snapshot:    preparation.Snapshot,
		Plan:        preparation.Plan,
	}

	if preparation.PermitBinding != nil {
		binding := *preparation.PermitBinding
		manifest := egeproto.EvidenceManifest{
			APIVersion:      egeproto.EvidenceManifestVersion,
			IntentID:        intentID,
			Kind:            kind,
			Target:          egeproto.Target{Type: target.Type, Name: target.Name},
			ResourceVersion: binding.ResourceVersion,
			EvidenceDigest:  binding.EvidenceDigest,
			PlanDigest:      binding.PlanDigest,
			ObservedAt:      preparation.ObservedAt,
			EvidenceClasses: append([]string(nil), preparation.EvidenceClasses...),
			Sources:         append([]egeproto.EvidenceSource(nil), preparation.EvidenceSources...),
			Composition:     preparation.EvidenceComposition,
		}
		manifestDigest, err := egeproto.DigestEvidenceManifest(manifest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "EVIDENCE_MANIFEST_FAILED", err)
			return
		}
		permitClaims := egeproto.PermitClaims{
			IntentID:               intentID,
			Kind:                   kind,
			Target:                 egeproto.Target{Type: target.Type, Name: target.Name},
			Action:                 binding.Action,
			ResourceVersion:        binding.ResourceVersion,
			EvidenceDigest:         binding.EvidenceDigest,
			EvidenceManifestDigest: manifestDigest,
			PlanDigest:             binding.PlanDigest,
			ValidUntil:             binding.ValidUntil,
		}
		capabilityFence, err := s.issueExecutionCapabilityFence(
			ctx,
			intentID,
			kind,
			target,
			preparation,
		)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "CAPABILITY_FENCE_ISSUANCE_FAILED", err)
			return
		}
		permitClaims.CapabilityFence = capabilityFence

		permit, err := egeproto.SignPermit(ctx, s.permitAuthority, permitClaims)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "PERMIT_SIGNING_FAILED", err)
			return
		}
		if err := s.issueCapabilityClaim(ctx, adapter, intentID, target, permit.Claims); err != nil {
			if errors.Is(err, ErrExecutionReplay) {
				writeError(w, http.StatusConflict, "CAPABILITY_ALREADY_ISSUED", err)
				return
			}
			writeError(w, http.StatusServiceUnavailable, "CAPABILITY_CLAIM_ISSUANCE_FAILED", err)
			return
		}
		response.EvidenceManifest = &manifest
		response.Permit = &permit
	}

	s.auditDecision(r, PermissionPrepare, string(preparation.Decision), intentID, target.Name, preparation.ReasonCodes)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleEGEExecute(w http.ResponseWriter, r *http.Request) {
	if !s.config.MutationsEnabled {
		writeError(w, http.StatusServiceUnavailable, "MUTATIONS_DISABLED", errors.New("real mutations are disabled on this daemon"))
		return
	}

	var req egeExecuteRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}

	intentID, kind, target, err := normalizeEGEIntent(req.IntentID, req.Kind, req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}

	adapter, err := s.egeAdapters.Resolve(kind, target.Type)
	if err != nil {
		writeEGEAdapterResolutionError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	if err := egeproto.VerifyPermit(ctx, s.permitAuthority, req.Permit); err != nil {
		writeError(w, http.StatusForbidden, "INVALID_EXECUTION_PERMIT", err)
		return
	}

	claims := req.Permit.Claims
	if claims.IntentID != intentID ||
		claims.Kind != kind ||
		claims.Target.Type != target.Type ||
		claims.Target.Name != target.Name {
		writeError(w, http.StatusBadRequest, "PERMIT_INTENT_MISMATCH", errors.New("signed permit does not match execution intent"))
		return
	}

	var consequenceAdmission *egeproto.ConsequenceAdmission
	if s.config.RequireEBAConformance {
		if req.EBA == nil || req.EBA.EvidenceManifest == nil {
			s.auditDecision(
				r,
				PermissionExecute,
				string(decision.Block),
				intentID,
				target.Name,
				[]decision.ReasonCode{"EBA_CONFORMANCE_REQUIRED"},
			)
			writeError(
				w,
				http.StatusForbidden,
				"EBA_CONFORMANCE_REQUIRED",
				errors.New("EBA execution bundle with evidence_manifest is required"),
			)
			return
		}
		if err := egeproto.ValidateKubernetesDrainConformance(
			ctx,
			s.permitAuthority,
			s.approvalAuthority,
			egeproto.KubernetesDrainConformanceInput{
				PrincipalID:         s.config.EBAExecutionPrincipal,
				Audience:            s.config.EBAAudience,
				Namespace:           s.config.EBANamespace,
				AssumptionArtifacts: req.EBA.AssumptionArtifacts,
				AuthorityArtifact:   req.EBA.AuthorityArtifact,
				BudgetArtifact:      req.EBA.BudgetArtifact,
				Approvals:           req.EBA.Approvals,
				EvidenceManifest:    *req.EBA.EvidenceManifest,
				Permit:              req.Permit,
			},
			s.config.Clock().UTC(),
		); err != nil {
			s.auditDecision(
				r,
				PermissionExecute,
				string(decision.Block),
				intentID,
				target.Name,
				[]decision.ReasonCode{"EBA_CONFORMANCE_BLOCKED"},
			)
			writeError(w, http.StatusForbidden, "EBA_CONFORMANCE_BLOCKED", err)
			return
		}

		admission, err := egeproto.EvaluateConsequenceAdmission(
			*s.consequencePolicy,
			req.Permit.Claims,
			*req.EBA.EvidenceManifest,
			s.config.Clock().UTC(),
		)
		if err != nil {
			s.auditDecision(
				r,
				PermissionExecute,
				string(decision.Block),
				intentID,
				target.Name,
				[]decision.ReasonCode{"CONSEQUENCE_ADMISSIBILITY_BLOCKED"},
			)
			writeError(w, http.StatusForbidden, "CONSEQUENCE_ADMISSIBILITY_BLOCKED", err)
			return
		}
		consequenceAdmission = &admission
	}

	if s.config.RequireCapabilityFencing && claims.CapabilityFence == nil {
		s.auditDecision(
			r,
			PermissionExecute,
			string(decision.Block),
			intentID,
			target.Name,
			[]decision.ReasonCode{"CAPABILITY_FENCE_REQUIRED"},
		)
		writeError(
			w,
			http.StatusForbidden,
			"CAPABILITY_FENCE_REQUIRED",
			errors.New("signed permit does not contain an execution capability fence"),
		)
		return
	}
	if err := s.revalidateExecutionCapabilityFence(
		ctx,
		intentID,
		kind,
		target,
		claims.CapabilityFence,
	); err != nil {
		status := http.StatusServiceUnavailable
		code := "CAPABILITY_FENCE_UNAVAILABLE"
		reason := decision.ReasonCode("CAPABILITY_FENCE_UNAVAILABLE")

		switch {
		case errors.Is(err, egeproto.ErrCapabilityAuthorityChanged):
			status = http.StatusConflict
			code = "CAPABILITY_AUTHORITY_CHANGED"
			reason = "CAPABILITY_AUTHORITY_CHANGED"
		case errors.Is(err, egeproto.ErrCapabilityDecisionSuperseded):
			status = http.StatusConflict
			code = "CAPABILITY_DECISION_SUPERSEDED"
			reason = "CAPABILITY_DECISION_SUPERSEDED"
		case errors.Is(err, egeproto.ErrCapabilityRevoked):
			status = http.StatusConflict
			code = "CAPABILITY_REVOKED"
			reason = "CAPABILITY_REVOKED"
		case errors.Is(err, egeproto.ErrCapabilityTargetChanged):
			status = http.StatusConflict
			code = "CAPABILITY_TARGET_CHANGED"
			reason = "CAPABILITY_TARGET_CHANGED"
		case errors.Is(err, egeproto.ErrCapabilityStateChanged):
			status = http.StatusConflict
			code = "CAPABILITY_STATE_CHANGED"
			reason = "CAPABILITY_STATE_CHANGED"
		case errors.Is(err, egeproto.ErrCapabilityFenceInvalid):
			status = http.StatusForbidden
			code = "CAPABILITY_FENCE_INVALID"
			reason = "CAPABILITY_FENCE_INVALID"
		}

		s.auditDecision(
			r,
			PermissionExecute,
			string(decision.Block),
			intentID,
			target.Name,
			[]decision.ReasonCode{reason},
		)
		writeError(w, status, code, err)
		return
	}

	auth, err := adapter.AuthorizationFromPermit(intentID, target, claims)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PERMIT_INTENT_MISMATCH", err)
		return
	}

	if err := s.config.ReplayGuard.Claim(ctx, auth); err != nil {
		if errors.Is(err, ErrExecutionReplay) {
			s.auditDecision(r, PermissionExecute, "", auth.ActionID, target.Name, []decision.ReasonCode{"EXECUTION_REPLAY_REJECTED"})
			writeError(w, http.StatusConflict, "EXECUTION_REPLAY_REJECTED", err)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "REPLAY_GUARD_UNAVAILABLE", err)
		return
	}

	if err := ctx.Err(); err != nil {
		abortErr := s.abortCapabilityClaim(auth, "request context ended before mutation controller")
		if abortErr != nil {
			writeError(w, http.StatusServiceUnavailable, "CAPABILITY_CLAIM_FINALIZATION_FAILED", abortErr)
			return
		}
		writeError(w, http.StatusRequestTimeout, "EXECUTION_ABORTED_BEFORE_MUTATION", err)
		return
	}

	executionStartedAt := s.config.Clock().UTC()
	execution, err := adapter.Execute(ctx, auth, target)
	if err != nil {
		// Once the mutation controller has been entered, an error may represent
		// an ambiguous external write. Keep the capability CLAIMED and require
		// reconciliation rather than making it reusable.
		s.auditDecision(
			r,
			PermissionExecute,
			string(decision.Escalate),
			intentID,
			target.Name,
			[]decision.ReasonCode{"EXECUTION_OUTCOME_UNCONFIRMED"},
		)
		writeError(w, http.StatusBadGateway, "EXECUTION_FAILED", err)
		return
	}
	executionFinishedAt := s.config.Clock().UTC()

	response := egeExecuteResponse{
		APIVersion:           egeAPIVersion,
		IntentID:             intentID,
		Kind:                 kind,
		Target:               target,
		Decision:             execution.Decision,
		ReasonCodes:          append([]decision.ReasonCode(nil), execution.ReasonCodes...),
		PlanDigest:           execution.PlanDigest,
		Steps:                append([]mutationStepDTO(nil), execution.Steps...),
		ConsequenceAdmission: consequenceAdmission,
	}

	if s.capabilityClaims != nil {
		if err := s.consumeCapabilityClaim(auth, string(execution.Decision)); err != nil {
			response.CapabilityClaimError = err.Error()
			if state, stateErr := s.capabilityClaimState(auth); stateErr == nil {
				response.CapabilityClaimState = state
			}
			s.auditSecurity(r.Context(), SecurityAuditRecord{
				OccurredAt: s.config.Clock().UTC(),
				Principal:  principalFromContext(r.Context()).ID,
				Permission: PermissionExecute,
				Method:     r.Method,
				Path:       r.URL.Path,
				Allowed:    true,
				Decision:   string(execution.Decision),
				ActionID:   intentID,
				NodeName:   target.Name,
				Reason:     "CAPABILITY_CLAIM_FINALIZATION_ERROR:" + err.Error(),
			})
		} else {
			response.CapabilityClaimState = ExecutionClaimConsumed
		}
	}

	reasonStrings := make([]string, 0, len(execution.ReasonCodes))
	for _, reason := range execution.ReasonCodes {
		reasonStrings = append(reasonStrings, string(reason))
	}
	resourceChanges := make([]egeproto.ReceiptResourceChange, 0, len(execution.Steps))
	for _, step := range execution.Steps {
		result := "NOT_APPLIED"
		if step.Applied {
			result = "APPLIED"
		} else if step.Error != "" {
			result = "FAILED"
		}
		resourceChanges = append(resourceChanges, egeproto.ReceiptResourceChange{
			Resource:  "kubernetes://node/" + target.Name,
			Operation: string(step.Kind),
			Result:    result,
			Error:     step.Error,
		})
	}

	receipt, producedEvidence, feedbackErr := egeproto.BuildExecutionReceiptFeedback(
		egeproto.ExecutionReceiptInput{
			Permit:          req.Permit,
			Decision:        string(execution.Decision),
			ReasonCodes:     reasonStrings,
			PlanDigest:      execution.PlanDigest,
			StartedAt:       executionStartedAt,
			FinishedAt:      executionFinishedAt,
			ResourceChanges:      resourceChanges,
			ConsequenceAdmission: consequenceAdmission,
		},
	)
	if feedbackErr != nil {
		response.FeedbackError = feedbackErr.Error()
		s.auditDecision(r, PermissionExecute, string(execution.Decision), intentID, target.Name, execution.ReasonCodes)
		s.auditSecurity(r.Context(), SecurityAuditRecord{
			OccurredAt: s.config.Clock().UTC(),
			Principal:  principalFromContext(r.Context()).ID,
			Permission: PermissionExecute,
			Method:     r.Method,
			Path:       r.URL.Path,
			Allowed:    true,
			Decision:   string(execution.Decision),
			ActionID:   intentID,
			NodeName:   target.Name,
			Reason:     "EXECUTION_FEEDBACK_ERROR:" + feedbackErr.Error(),
		})
	} else {
		response.ExecutionReceipt = &receipt
		response.ProducedEvidence = &producedEvidence
		s.auditDecision(
			r,
			PermissionExecute,
			string(execution.Decision),
			intentID,
			target.Name,
			execution.ReasonCodes,
			receipt.ID,
			producedEvidence.ID,
		)
	}

	writeJSON(w, http.StatusOK, response)
}
