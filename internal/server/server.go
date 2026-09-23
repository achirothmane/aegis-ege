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

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/kubeadapter"
)

type NodeDrainController interface {
	PrepareNodeDrainExecution(context.Context, string, string, kubeadapter.NodeDrainPolicy) (kubeadapter.NodeDrainPreparation, error)
	ExecuteAuthorizedNodeDrainWithCheckpointStore(context.Context, decision.Authorization, string, kubeadapter.NodeDrainPolicy, kubeadapter.DrainCheckpointStore) (kubeadapter.GuardedDrainExecutionReport, error)
}

type Config struct {
	Policy           kubeadapter.NodeDrainPolicy
	MutationsEnabled bool
	RequestTimeout   time.Duration
	MaxBodyBytes     int64
}

type Server struct {
	controller NodeDrainController
	store      kubeadapter.DrainCheckpointStore
	config     Config
	mux        *http.ServeMux
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
	if config.MutationsEnabled && store == nil {
		return nil, fmt.Errorf("checkpoint store is required when mutations are enabled")
	}
	s := &Server{controller: controller, store: store, config: config, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /v1/node-drains/prepare", s.handlePrepare)
	s.mux.HandleFunc("POST /v1/node-drains/execute", s.handleExecute)
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
	writeJSON(w, http.StatusOK, response)
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
