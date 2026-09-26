package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const (
	egeAPIVersion    = "aegis.ege/v0alpha1"
	egeNodeDrainKind = "kubernetes.node_drain"
	egeNodeTarget    = "kubernetes.node"
)

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
	if kind != egeNodeDrainKind {
		return "", "", egeTargetDTO{}, errors.New("unsupported intent kind")
	}
	if target.Type != egeNodeTarget {
		return "", "", egeTargetDTO{}, errors.New("target.type must be kubernetes.node for kubernetes.node_drain")
	}
	return intentID, kind, target, nil
}

func (s *Server) handleEGEPrepare(w http.ResponseWriter, r *http.Request) {
	var req egePrepareRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}

	intentID, kind, target, err := normalizeEGEIntent(req.IntentID, req.Kind, req.Target)
	if err != nil {
		code := "INVALID_REQUEST"
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "unsupported intent kind") {
			code = "UNSUPPORTED_INTENT_KIND"
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, code, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	preparation, err := s.controller.PrepareNodeDrainExecution(ctx, intentID, target.Name, s.config.Policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, "PREPARE_FAILED", err)
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
	}
	if preparation.Snapshot.NodeName != "" {
		response.Snapshot = &snapshotDTO{
			NodeUID:         preparation.Snapshot.NodeUID,
			ResourceVersion: preparation.Snapshot.ResourceVersion,
			NodeHealth:      preparation.Snapshot.NodeHealth,
			Unschedulable:   preparation.Snapshot.Unschedulable,
			ActivePods:      preparation.Snapshot.ActivePods,
			ObservedAt:      preparation.Snapshot.ObservedAt,
		}
	}
	if preparation.Plan != nil {
		response.Plan = planToDTO(*preparation.Plan)
	}
	if preparation.Authorization != nil {
		auth := *preparation.Authorization
		manifest := egeproto.EvidenceManifest{
			APIVersion:      egeproto.EvidenceManifestVersion,
			IntentID:        intentID,
			Kind:            kind,
			Target:          egeproto.Target{Type: target.Type, Name: target.Name},
			ResourceVersion: auth.ResourceVersion,
			EvidenceDigest:  auth.EvidenceDigest,
			PlanDigest:      auth.PlanDigest,
			ObservedAt:      preparation.Snapshot.ObservedAt,
			EvidenceClasses: []string{
				"kubernetes.authoritative-state",
				"kubernetes.pdb-preflight",
				"kubernetes.server-dry-run",
			},
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
			Action:                 auth.Action,
			ResourceVersion:        auth.ResourceVersion,
			EvidenceDigest:         auth.EvidenceDigest,
			EvidenceManifestDigest: manifestDigest,
			PlanDigest:             auth.PlanDigest,
			ValidUntil:             auth.ValidUntil,
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
		code := "INVALID_REQUEST"
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "unsupported intent kind") {
			code = "UNSUPPORTED_INTENT_KIND"
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, code, err)
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
		claims.Target.Name != target.Name ||
		claims.Action != "drain" ||
		claims.ResourceVersion == "" ||
		claims.EvidenceDigest == "" ||
		claims.EvidenceManifestDigest == "" ||
		claims.PlanDigest == "" {
		writeError(w, http.StatusBadRequest, "PERMIT_INTENT_MISMATCH", errors.New("signed permit does not match execution intent or is missing required state bindings"))
		return
	}

	auth := decision.Authorization{
		ActionID:        claims.IntentID,
		Action:          claims.Action,
		Target:          "node/" + claims.Target.Name,
		ResourceVersion: claims.ResourceVersion,
		EvidenceDigest:  claims.EvidenceDigest,
		PlanDigest:      claims.PlanDigest,
		ValidUntil:      claims.ValidUntil,
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

	report, err := s.controller.ExecuteAuthorizedNodeDrainWithCheckpointStore(
		ctx,
		auth,
		target.Name,
		s.config.Policy,
		s.store,
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXECUTION_FAILED", err)
		return
	}

	response := egeExecuteResponse{
		APIVersion:  egeAPIVersion,
		IntentID:    intentID,
		Kind:        kind,
		Target:      target,
		Decision:    report.Decision,
		ReasonCodes: append([]decision.ReasonCode(nil), report.ReasonCodes...),
		PlanDigest:  report.PlanDigest,
		Steps:       make([]mutationStepDTO, 0, len(report.Steps)),
	}
	for _, step := range report.Steps {
		response.Steps = append(response.Steps, mutationStepDTO{
			Kind:    step.Step.Kind,
			Applied: step.Applied,
			Error:   step.Error,
		})
	}

	s.auditDecision(r, PermissionExecute, string(report.Decision), intentID, target.Name, report.ReasonCodes)
	writeJSON(w, http.StatusOK, response)
}
