package server

import (
    "errors"
    "net/http"
    "strings"
    "time"

    "github.com/achirothmane/aegis-ege/internal/evidencepipeline"
)

const n8nEEPAPIVersion = "aegis.eep/n8n/v0alpha1"

type n8nEEPActionDTO struct {
    Kind       string `json:"kind"`
    Tool       string `json:"tool"`
    Operation  string `json:"operation"`
    Target     string `json:"target"`
    SideEffect bool   `json:"side_effect"`
}

type n8nEEPCompileRequest struct {
    IntentID             string          `json:"intent_id"`
    EventID              string          `json:"event_id"`
    WorkflowID           string          `json:"workflow_id"`
    ExecutionID          string          `json:"execution_id"`
    AgentID              string          `json:"agent_id,omitempty"`
    ObservedAt           time.Time       `json:"observed_at"`
    Action               n8nEEPActionDTO `json:"action"`
    Data                 map[string]any  `json:"data"`
    AuthorityRef         string          `json:"authority_ref"`
    PolicyRef            string          `json:"policy_ref"`
    RedactionProfileRef  string          `json:"redaction_profile_ref"`
    ConsequenceClass     string          `json:"consequence_class"`
    ControlRefs          []string        `json:"control_refs,omitempty"`
    ApprovalRefs         []string        `json:"approval_refs,omitempty"`
    SensitivePaths       []string        `json:"sensitive_paths"`
    SourceAttestationRef string          `json:"source_attestation_ref,omitempty"`
}

type n8nEEPCompileResponse struct {
    APIVersion string                  `json:"api_version"`
    Packet     evidencepipeline.Packet `json:"packet"`
}

func (s *Server) handleN8NEEPCompile(w http.ResponseWriter, r *http.Request) {
    principal := principalFromContext(r.Context())
    if strings.TrimSpace(principal.ID) == "" {
        writeError(
            w,
            http.StatusUnauthorized,
            "EEP_AUTHENTICATED_SOURCE_REQUIRED",
            errors.New("n8n EEP ingestion requires an authenticated source identity"),
        )
        return
    }

    var req n8nEEPCompileRequest
    if err := s.decodeJSON(w, r, &req); err != nil {
        writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
        return
    }

    req.IntentID = strings.TrimSpace(req.IntentID)
    req.EventID = strings.TrimSpace(req.EventID)
    req.WorkflowID = strings.TrimSpace(req.WorkflowID)
    req.ExecutionID = strings.TrimSpace(req.ExecutionID)
    req.AgentID = strings.TrimSpace(req.AgentID)
    req.AuthorityRef = strings.TrimSpace(req.AuthorityRef)
    req.PolicyRef = strings.TrimSpace(req.PolicyRef)
    req.RedactionProfileRef = strings.TrimSpace(req.RedactionProfileRef)
    req.ConsequenceClass = strings.TrimSpace(req.ConsequenceClass)
    req.SourceAttestationRef = strings.TrimSpace(req.SourceAttestationRef)

    packet, err := evidencepipeline.Compile(evidencepipeline.CompileRequest{
        Event: evidencepipeline.RuntimeEvent{
            IntentID:   req.IntentID,
            EventID:    req.EventID,
            WorkflowID: req.WorkflowID,
            RunID:      req.ExecutionID,
            Actor: evidencepipeline.Actor{
                PrincipalID: principal.ID,
                AgentID:     req.AgentID,
            },
            Action: evidencepipeline.Action{
                Kind:       strings.TrimSpace(req.Action.Kind),
                Tool:       strings.TrimSpace(req.Action.Tool),
                Operation:  strings.TrimSpace(req.Action.Operation),
                Target:     strings.TrimSpace(req.Action.Target),
                SideEffect: req.Action.SideEffect,
            },
            ObservedAt: req.ObservedAt,
            Data:       req.Data,
        },
        Source: evidencepipeline.Source{
            Name:           "n8n.http-request",
            TrustDomain:    "n8n-workflow-runtime",
            AttestationRef: req.SourceAttestationRef,
        },
        Context: evidencepipeline.BootstrapContext{
            AuthorityRef:        req.AuthorityRef,
            PolicyRef:           req.PolicyRef,
            RedactionProfileRef: req.RedactionProfileRef,
            ConsequenceClass:    req.ConsequenceClass,
            ControlRefs:         append([]string(nil), req.ControlRefs...),
            ApprovalRefs:        append([]string(nil), req.ApprovalRefs...),
        },
        SensitivePaths: append([]string(nil), req.SensitivePaths...),
        CapturedAt:     s.config.Clock().UTC(),
    })
    if err != nil {
        writeError(w, http.StatusUnprocessableEntity, "EEP_COMPILE_REJECTED", err)
        return
    }

    s.auditDecision(
        r,
        PermissionPrepare,
        "EEP_COMPILED",
        req.IntentID,
        req.Action.Target,
        nil,
        "",
        packet.Integrity.Digest,
    )
    writeJSON(w, http.StatusOK, n8nEEPCompileResponse{
        APIVersion: n8nEEPAPIVersion,
        Packet:     packet,
    })
}
