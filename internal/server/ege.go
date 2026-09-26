package server

import (
	"context"
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

type egeExecuteRequest struct {
	IntentID string          `json:"intent_id"`
	Kind     string          `json:"kind"`
	Target   egeTargetDTO    `json:"target"`
	Permit   egeproto.Permit `json:"permit"`
}

type egeExecuteResponse struct {
	APIVersion  string                `json:"api_version"`
	IntentID    string                `json:"intent_id"`
	Kind        string                `json:"kind"`
	Target      egeTargetDTO          `json:"target"`
	Decision    decision.Decision     `json:"decision"`
	ReasonCodes []decision.ReasonCode `json:"reason_codes,omitempty"`
	PlanDigest  string                `json:"plan_digest,omitempty"`
	Steps       []mutationStepDTO     `json:"steps,omitempty"`
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
		}
		manifestDigest, err := egeproto.DigestEvidenceManifest(manifest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "EVIDENCE_MANIFEST_FAILED", err)
			return
		}
		permit, err := egeproto.SignPermit(ctx, s.permitAuthority, egeproto.PermitClaims{
			IntentID:               intentID,
			Kind:                   kind,
			Target:                 egeproto.Target{Type: target.Type, Name: target.Name},
			Action:                 binding.Action,
			ResourceVersion:        binding.ResourceVersion,
			EvidenceDigest:         binding.EvidenceDigest,
			EvidenceManifestDigest: manifestDigest,
			PlanDigest:             binding.PlanDigest,
			ValidUntil:             binding.ValidUntil,
		})
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "PERMIT_SIGNING_FAILED", err)
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

	execution, err := adapter.Execute(ctx, auth, target)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXECUTION_FAILED", err)
		return
	}

	response := egeExecuteResponse{
		APIVersion:  egeAPIVersion,
		IntentID:    intentID,
		Kind:        kind,
		Target:      target,
		Decision:    execution.Decision,
		ReasonCodes: append([]decision.ReasonCode(nil), execution.ReasonCodes...),
		PlanDigest:  execution.PlanDigest,
		Steps:       append([]mutationStepDTO(nil), execution.Steps...),
	}

	s.auditDecision(r, PermissionExecute, string(execution.Decision), intentID, target.Name, execution.ReasonCodes)
	writeJSON(w, http.StatusOK, response)
}
