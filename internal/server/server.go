package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

type NodeDrainController interface {
	PrepareNodeDrainExecution(context.Context, string, string, kubeadapter.NodeDrainPolicy) (kubeadapter.NodeDrainPreparation, error)
	ExecuteAuthorizedNodeDrainWithCheckpointStore(context.Context, decision.Authorization, string, kubeadapter.NodeDrainPolicy, kubeadapter.DrainCheckpointStore) (kubeadapter.GuardedDrainExecutionReport, error)
}

type Config struct {
	Policy                kubeadapter.NodeDrainPolicy
	MutationsEnabled      bool
	RequestTimeout        time.Duration
	MaxBodyBytes          int64
	RequireAuthentication bool
	Authorizer            Authorizer
	ReplayGuard           ReplayGuard
	AuditSink             AuditSink
	Clock                 func() time.Time
	EGEPermitAuthority    egeproto.PermitAuthority
}

type Server struct {
	controller      NodeDrainController
	store           kubeadapter.DrainCheckpointStore
	config          Config
	mux             *http.ServeMux
	permitAuthority egeproto.PermitAuthority
	egeAdapters     *egeAdapterRegistry
}

func New(controller NodeDrainController, store kubeadapter.DrainCheckpointStore, config Config) (*Server, error) {
	if controller == nil {
		return nil, fmt.Errorf("node drain controller is required")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.RequireAuthentication && config.Authorizer == nil {
		return nil, fmt.Errorf("authorizer is required when authentication is enabled")
	}
	if config.MutationsEnabled && store == nil {
		return nil, fmt.Errorf("checkpoint store is required when mutations are enabled")
	}
	if config.MutationsEnabled && (!config.RequireAuthentication || config.Authorizer == nil) {
		return nil, fmt.Errorf("authenticated authorization is required when mutations are enabled")
	}
	if config.MutationsEnabled && config.ReplayGuard == nil {
		return nil, fmt.Errorf("replay guard is required when mutations are enabled")
	}
	permitAuthority := config.EGEPermitAuthority
	if permitAuthority == nil {
		var err error
		permitAuthority, err = egeproto.NewEphemeralEd25519Authority()
		if err != nil {
			return nil, fmt.Errorf("create EGE permit authority: %w", err)
		}
	}
	egeAdapters, err := newEGEAdapterRegistry(
		newKubernetesNodeDrainEGEAdapter(controller, config.Policy, store),
	)
	if err != nil {
		return nil, fmt.Errorf("create EGE adapter registry: %w", err)
	}

	s := &Server{
		controller:      controller,
		store:           store,
		config:          config,
		mux:             http.NewServeMux(),
		permitAuthority: permitAuthority,
		egeAdapters:     egeAdapters,
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	prepare := http.Handler(http.HandlerFunc(s.handlePrepare))
	execute := http.Handler(http.HandlerFunc(s.handleExecute))
	if s.config.RequireAuthentication {
		prepare = s.authenticated(PermissionPrepare, prepare)
		execute = s.authenticated(PermissionExecute, execute)
	}
	s.mux.Handle("POST /v1/node-drains/prepare", prepare)
	s.mux.Handle("POST /v1/node-drains/execute", execute)

	egePrepare := http.Handler(http.HandlerFunc(s.handleEGEPrepare))
	egeExecute := http.Handler(http.HandlerFunc(s.handleEGEExecute))
	if s.config.RequireAuthentication {
		egePrepare = s.authenticated(PermissionPrepare, egePrepare)
		egeExecute = s.authenticated(PermissionExecute, egeExecute)
	}
	s.mux.Handle("POST /v1/ege/prepare", egePrepare)
	s.mux.Handle("POST /v1/ege/execute", egeExecute)
}

type prepareRequest struct {
	ActionID string `json:"action_id"`
	NodeName string `json:"node_name"`
}

type executeRequest struct {
	NodeName       string           `json:"node_name"`
	Authorization authorizationDTO `json:"authorization"`
}

type authorizationDTO struct {
	ActionID        string    `json:"action_id"`
	Action          string    `json:"action"`
	Target          string    `json:"target"`
	ResourceVersion string    `json:"resource_version"`
	EvidenceDigest  string    `json:"evidence_digest"`
	PlanDigest      string    `json:"plan_digest"`
	ValidUntil      time.Time `json:"valid_until"`
}

type prepareResponse struct {
	Decision      decision.Decision     `json:"decision"`
	ReasonCodes   []decision.ReasonCode `json:"reason_codes,omitempty"`
	ActionID      string                `json:"action_id"`
	NodeName      string                `json:"node_name"`
	PlanDigest    string                `json:"plan_digest,omitempty"`
	Authorization *authorizationDTO     `json:"authorization,omitempty"`
	Snapshot      *snapshotDTO          `json:"snapshot,omitempty"`
	Plan          *planDTO              `json:"plan,omitempty"`
}

type snapshotDTO struct {
	NodeUID         string    `json:"node_uid"`
	ResourceVersion string    `json:"resource_version"`
	NodeHealth      string    `json:"node_health"`
	Unschedulable   bool      `json:"unschedulable"`
	ActivePods      int       `json:"active_pods"`
	ObservedAt      time.Time `json:"observed_at"`
}

type planDTO struct {
	NodeUID             string    `json:"node_uid"`
	NodeHealth          string    `json:"node_health"`
	NodeResourceVersion string    `json:"node_resource_version"`
	Steps               []stepDTO `json:"steps"`
}

type stepDTO struct {
	Kind            kubeadapter.DrainExecutionStepKind `json:"kind"`
	NodeName        string                             `json:"node_name,omitempty"`
	ResourceVersion string                             `json:"resource_version,omitempty"`
	Pod             *podDTO                            `json:"pod,omitempty"`
}

type podDTO struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	StateDigest string `json:"state_digest"`
}

type executeResponse struct {
	Decision    decision.Decision     `json:"decision"`
	ReasonCodes []decision.ReasonCode `json:"reason_codes,omitempty"`
	PlanDigest  string                `json:"plan_digest,omitempty"`
	Steps       []mutationStepDTO     `json:"steps,omitempty"`
}

type mutationStepDTO struct {
	Kind    kubeadapter.DrainExecutionStepKind `json:"kind"`
	Applied bool                               `json:"applied"`
	Error   string                             `json:"error,omitempty"`
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	var req prepareRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}
	req.ActionID = strings.TrimSpace(req.ActionID)
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.ActionID == "" || req.NodeName == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", errors.New("action_id and node_name are required"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	preparation, err := s.controller.PrepareNodeDrainExecution(ctx, req.ActionID, req.NodeName, s.config.Policy)
	if err != nil {
		writeError(w, http.StatusBadGateway, "PREPARE_FAILED", err)
		return
	}

	response := prepareResponse{
		Decision: preparation.Decision, ReasonCodes: append([]decision.ReasonCode(nil), preparation.ReasonCodes...),
		ActionID: req.ActionID, NodeName: req.NodeName, PlanDigest: preparation.PlanDigest,
	}
	if preparation.Authorization != nil {
		dto := authorizationToDTO(*preparation.Authorization)
		response.Authorization = &dto
	}
	if preparation.Snapshot.NodeName != "" {
		response.Snapshot = &snapshotDTO{
			NodeUID: preparation.Snapshot.NodeUID, ResourceVersion: preparation.Snapshot.ResourceVersion,
			NodeHealth: preparation.Snapshot.NodeHealth, Unschedulable: preparation.Snapshot.Unschedulable,
			ActivePods: preparation.Snapshot.ActivePods, ObservedAt: preparation.Snapshot.ObservedAt,
		}
	}
	if preparation.Plan != nil {
		response.Plan = planToDTO(*preparation.Plan)
	}
	s.auditDecision(r, PermissionPrepare, string(preparation.Decision), req.ActionID, req.NodeName, preparation.ReasonCodes)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if !s.config.MutationsEnabled {
		writeError(w, http.StatusServiceUnavailable, "MUTATIONS_DISABLED", errors.New("real mutations are disabled on this daemon"))
		return
	}

	var req executeRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err)
		return
	}
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.NodeName == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", errors.New("node_name is required"))
		return
	}
	auth := authorizationFromDTO(req.Authorization)
	if auth.ActionID == "" || auth.Action != "drain" || auth.Target != "node/"+req.NodeName {
		writeError(w, http.StatusBadRequest, "AUTHORIZATION_MISMATCH", errors.New("authorization does not match requested node drain"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	if err := s.config.ReplayGuard.Claim(ctx, auth); err != nil {
		if errors.Is(err, ErrExecutionReplay) {
			s.auditDecision(r, PermissionExecute, "", auth.ActionID, req.NodeName, []decision.ReasonCode{"EXECUTION_REPLAY_REJECTED"})
			writeError(w, http.StatusConflict, "EXECUTION_REPLAY_REJECTED", err)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "REPLAY_GUARD_UNAVAILABLE", err)
		return
	}
	report, err := s.controller.ExecuteAuthorizedNodeDrainWithCheckpointStore(ctx, auth, req.NodeName, s.config.Policy, s.store)
	if err != nil {
		writeError(w, http.StatusBadGateway, "EXECUTION_FAILED", err)
		return
	}

	response := executeResponse{
		Decision: report.Decision, ReasonCodes: append([]decision.ReasonCode(nil), report.ReasonCodes...),
		PlanDigest: report.PlanDigest, Steps: make([]mutationStepDTO, 0, len(report.Steps)),
	}
	for _, step := range report.Steps {
		response.Steps = append(response.Steps, mutationStepDTO{Kind: step.Step.Kind, Applied: step.Applied, Error: step.Error})
	}
	s.auditDecision(r, PermissionExecute, string(report.Decision), auth.ActionID, req.NodeName, report.ReasonCodes)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) authenticated(permission Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.config.Authorizer.Authorize(r, permission)
		if err != nil {
			status := http.StatusForbidden
			code := "FORBIDDEN"
			if errors.Is(err, ErrUnauthenticated) {
				status = http.StatusUnauthorized
				code = "UNAUTHENTICATED"
			}
			s.auditSecurity(r.Context(), SecurityAuditRecord{
				OccurredAt: s.config.Clock().UTC(),
				Permission: permission,
				Method: r.Method,
				Path: r.URL.Path,
				Allowed: false,
				Reason: err.Error(),
			})
			writeError(w, status, code, err)
			return
		}
		s.auditSecurity(r.Context(), SecurityAuditRecord{
			OccurredAt: s.config.Clock().UTC(),
			Principal: principal.ID,
			Permission: permission,
			Method: r.Method,
			Path: r.URL.Path,
			Allowed: true,
		})
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type principalContextKey struct{}

func principalFromContext(ctx context.Context) Principal {
	principal, _ := ctx.Value(principalContextKey{}).(Principal)
	return principal
}

func (s *Server) auditDecision(
	r *http.Request,
	permission Permission,
	decisionValue string,
	actionID string,
	nodeName string,
	reasons []decision.ReasonCode,
) {
	reasonStrings := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reasonStrings = append(reasonStrings, string(reason))
	}
	s.auditSecurity(r.Context(), SecurityAuditRecord{
		OccurredAt: s.config.Clock().UTC(),
		Principal: principalFromContext(r.Context()).ID,
		Permission: permission,
		Method: r.Method,
		Path: r.URL.Path,
		Allowed: true,
		Decision: decisionValue,
		ActionID: actionID,
		NodeName: nodeName,
		Reason: strings.Join(reasonStrings, ","),
	})
}

func (s *Server) auditSecurity(ctx context.Context, record SecurityAuditRecord) {
	if s.config.AuditSink != nil {
		s.config.AuditSink.Record(ctx, record)
	}
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	body := http.MaxBytesReader(w, r.Body, s.config.MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON object")
		}
		return err
	}
	return nil
}

func authorizationToDTO(auth decision.Authorization) authorizationDTO {
	return authorizationDTO{
		ActionID: auth.ActionID, Action: auth.Action, Target: auth.Target, ResourceVersion: auth.ResourceVersion,
		EvidenceDigest: auth.EvidenceDigest, PlanDigest: auth.PlanDigest, ValidUntil: auth.ValidUntil.UTC(),
	}
}

func authorizationFromDTO(dto authorizationDTO) decision.Authorization {
	return decision.Authorization{
		ActionID: dto.ActionID, Action: dto.Action, Target: dto.Target, ResourceVersion: dto.ResourceVersion,
		EvidenceDigest: dto.EvidenceDigest, PlanDigest: dto.PlanDigest, ValidUntil: dto.ValidUntil.UTC(),
	}
}

func planToDTO(plan kubeadapter.DrainExecutionPlan) *planDTO {
	out := &planDTO{NodeUID: plan.NodeUID, NodeHealth: plan.NodeHealth, NodeResourceVersion: plan.NodeResourceVersion, Steps: make([]stepDTO, 0, len(plan.Steps))}
	for _, step := range plan.Steps {
		item := stepDTO{Kind: step.Kind, NodeName: step.NodeName, ResourceVersion: step.ResourceVersion}
		if step.Pod != nil {
			item.Pod = &podDTO{Namespace: step.Pod.Namespace, Name: step.Pod.Name, UID: step.Pod.UID, StateDigest: step.Pod.StateDigest}
		}
		out.Steps = append(out.Steps, item)
	}
	return out
}

func writeError(w http.ResponseWriter, status int, code string, err error) {
	writeJSON(w, status, errorResponse{Code: code, Message: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
