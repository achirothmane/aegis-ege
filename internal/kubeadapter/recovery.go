package kubeadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

var (
	ErrDrainCheckpointNotFound = errors.New("drain execution checkpoint not found")
	ErrDrainCheckpointConflict = errors.New("drain execution checkpoint write conflict")
)

const (
	ReasonExecutionCheckpointUnavailable decision.ReasonCode = "EXECUTION_CHECKPOINT_UNAVAILABLE"
	ReasonRecoveryReauthorizationRequired decision.ReasonCode = "RECOVERY_REAUTHORIZATION_REQUIRED"
	ReasonRecoveryStateDiverged            decision.ReasonCode = "RECOVERY_STATE_DIVERGED"
	ReasonRecoveryCheckpointNotFound       decision.ReasonCode = "RECOVERY_CHECKPOINT_NOT_FOUND"
)

type DrainExecutionStatus string

const (
	DrainExecutionRunning   DrainExecutionStatus = "RUNNING"
	DrainExecutionPaused    DrainExecutionStatus = "PAUSED"
	DrainExecutionCompleted DrainExecutionStatus = "COMPLETED"
)

type DrainExecutionCheckpoint struct {
	ActionID           string                `json:"action_id"`
	NodeName           string                `json:"node_name"`
	NodeUID            string                `json:"node_uid"`
	NodeHealth         string                `json:"node_health"`
	OriginalPlanDigest string                `json:"original_plan_digest"`
	ActivePlanDigest   string                `json:"active_plan_digest"`
	AuthorizedPods     []PodStateRef         `json:"authorized_pods"`
	CompletedPodUIDs   []string              `json:"completed_pod_uids"`
	Cordoned           bool                  `json:"cordoned"`
	Status             DrainExecutionStatus  `json:"status"`
	LastDecision       decision.Decision     `json:"last_decision"`
	LastReasonCodes    []decision.ReasonCode `json:"last_reason_codes,omitempty"`
	UpdatedAt          time.Time             `json:"updated_at"`
	StoreVersion       string                `json:"-"`
}

type DrainCheckpointStore interface {
	Load(ctx context.Context, actionID string) (DrainExecutionCheckpoint, error)
	Save(ctx context.Context, checkpoint DrainExecutionCheckpoint) error
}

type VersionedDrainCheckpointStore interface {
	DrainCheckpointStore
	SaveVersioned(ctx context.Context, checkpoint DrainExecutionCheckpoint) (DrainExecutionCheckpoint, error)
}

func saveDrainCheckpoint(
	ctx context.Context,
	store DrainCheckpointStore,
	checkpoint *DrainExecutionCheckpoint,
) error {
	if store == nil || checkpoint == nil {
		return fmt.Errorf("checkpoint store and checkpoint are required")
	}
	if versioned, ok := store.(VersionedDrainCheckpointStore); ok {
		saved, err := versioned.SaveVersioned(ctx, *checkpoint)
		if err != nil {
			return err
		}
		*checkpoint = saved
		return nil
	}
	return store.Save(ctx, *checkpoint)
}

type MemoryDrainCheckpointStore struct {
	mu          sync.Mutex
	checkpoints map[string]DrainExecutionCheckpoint
}

func NewMemoryDrainCheckpointStore() *MemoryDrainCheckpointStore {
	return &MemoryDrainCheckpointStore{
		checkpoints: make(map[string]DrainExecutionCheckpoint),
	}
}

func (s *MemoryDrainCheckpointStore) Load(_ context.Context, actionID string) (DrainExecutionCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	checkpoint, ok := s.checkpoints[actionID]
	if !ok {
		return DrainExecutionCheckpoint{}, ErrDrainCheckpointNotFound
	}
	return cloneDrainCheckpoint(checkpoint), nil
}

func (s *MemoryDrainCheckpointStore) Save(_ context.Context, checkpoint DrainExecutionCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if checkpoint.ActionID == "" {
		return fmt.Errorf("checkpoint action id is required")
	}
	s.checkpoints[checkpoint.ActionID] = cloneDrainCheckpoint(checkpoint)
	return nil
}

type FileDrainCheckpointStore struct {
	dir string
}

func NewFileDrainCheckpointStore(dir string) (*FileDrainCheckpointStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("checkpoint directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create checkpoint directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure checkpoint directory: %w", err)
	}
	return &FileDrainCheckpointStore{dir: dir}, nil
}

func (s *FileDrainCheckpointStore) Load(ctx context.Context, actionID string) (DrainExecutionCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return DrainExecutionCheckpoint{}, err
	}

	payload, err := os.ReadFile(s.path(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return DrainExecutionCheckpoint{}, ErrDrainCheckpointNotFound
	}
	if err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("read drain checkpoint: %w", err)
	}

	var checkpoint DrainExecutionCheckpoint
	if err := json.Unmarshal(payload, &checkpoint); err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("decode drain checkpoint: %w", err)
	}
	if checkpoint.ActionID != actionID {
		return DrainExecutionCheckpoint{}, fmt.Errorf(
			"checkpoint action id mismatch: expected %q got %q",
			actionID,
			checkpoint.ActionID,
		)
	}
	return checkpoint, nil
}

func (s *FileDrainCheckpointStore) Save(ctx context.Context, checkpoint DrainExecutionCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if checkpoint.ActionID == "" {
		return fmt.Errorf("checkpoint action id is required")
	}

	payload, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("encode drain checkpoint: %w", err)
	}
	payload = append(payload, '\n')

	finalPath := s.path(checkpoint.ActionID)
	temp, err := os.CreateTemp(s.dir, ".state-latch-checkpoint-*")
	if err != nil {
		return fmt.Errorf("create checkpoint temp file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("secure checkpoint temp file: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return fmt.Errorf("write drain checkpoint: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync drain checkpoint: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close drain checkpoint: %w", err)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return fmt.Errorf("commit drain checkpoint: %w", err)
	}
	return nil
}

func (s *FileDrainCheckpointStore) path(actionID string) string {
	hash := sha256.Sum256([]byte(actionID))
	return filepath.Join(s.dir, hex.EncodeToString(hash[:])+".json")
}

type DrainRecoveryState string

const (
	DrainRecoveryCompleted              DrainRecoveryState = "COMPLETED"
	DrainRecoveryReauthorizationNeeded  DrainRecoveryState = "REAUTHORIZATION_REQUIRED"
	DrainRecoveryBlocked                DrainRecoveryState = "BLOCKED"
	DrainRecoveryDiverged               DrainRecoveryState = "DIVERGED"
)

type DrainRecoveryAssessment struct {
	State             DrainRecoveryState
	Decision          decision.Decision
	ReasonCodes       []decision.ReasonCode
	Checkpoint        DrainExecutionCheckpoint
	RemainingPods     []PodStateRef
	ReconciledPodUIDs []string
}

func (a *Adapter) InspectDrainRecovery(
	ctx context.Context,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
) (DrainRecoveryAssessment, error) {
	if store == nil {
		return DrainRecoveryAssessment{
			State:       DrainRecoveryDiverged,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
		}, nil
	}

	checkpoint, err := store.Load(ctx, actionID)
	if errors.Is(err, ErrDrainCheckpointNotFound) {
		return DrainRecoveryAssessment{
			State:       DrainRecoveryDiverged,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRecoveryCheckpointNotFound},
		}, nil
	}
	if err != nil {
		return DrainRecoveryAssessment{}, err
	}
	if checkpoint.NodeName != nodeName || checkpoint.ActionID != actionID {
		return DrainRecoveryAssessment{
			State:       DrainRecoveryDiverged,
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{ReasonRecoveryStateDiverged},
			Checkpoint:  checkpoint,
		}, nil
	}

	snapshot, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return DrainRecoveryAssessment{}, err
	}
	if snapshot.NodeUID != checkpoint.NodeUID || snapshot.NodeHealth != checkpoint.NodeHealth {
		return DrainRecoveryAssessment{
			State:       DrainRecoveryDiverged,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRecoveryStateDiverged},
			Checkpoint:  checkpoint,
		}, nil
	}

	if snapshot.Unschedulable && !checkpoint.Cordoned {
		checkpoint.Cordoned = true
	}
	if checkpoint.Cordoned && !snapshot.Unschedulable {
		return DrainRecoveryAssessment{
			State:       DrainRecoveryDiverged,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCordonStateChanged},
			Checkpoint:  checkpoint,
		}, nil
	}

	liveUIDs := make(map[string]struct{}, len(pods))
	for _, pod := range pods {
		liveUIDs[string(pod.UID)] = struct{}{}
	}

	completed := make(map[string]struct{}, len(checkpoint.CompletedPodUIDs))
	for _, uid := range checkpoint.CompletedPodUIDs {
		completed[uid] = struct{}{}
	}

	reconciled := make([]string, 0)
	for _, pod := range checkpoint.AuthorizedPods {
		if _, already := completed[pod.UID]; already {
			continue
		}
		if _, present := liveUIDs[pod.UID]; !present {
			completed[pod.UID] = struct{}{}
			reconciled = append(reconciled, pod.UID)
		}
	}

	checkpoint.CompletedPodUIDs = orderedCompletedUIDs(checkpoint.AuthorizedPods, completed)
	checkpoint.UpdatedAt = a.now().UTC()

	preflight := a.preflightNodeDrain(ctx, pods, policy)
	if preflight.Decision != decision.Allow {
		checkpoint.Status = DrainExecutionPaused
		checkpoint.LastDecision = preflight.Decision
		checkpoint.LastReasonCodes = preflightDecisionReasons(preflight)
		_ = saveDrainCheckpoint(ctx, store, &checkpoint)
		state := DrainRecoveryDiverged
		if preflight.Decision == decision.Block {
			state = DrainRecoveryBlocked
		}
		return DrainRecoveryAssessment{
			State:             state,
			Decision:          preflight.Decision,
			ReasonCodes:       append([]decision.ReasonCode(nil), checkpoint.LastReasonCodes...),
			Checkpoint:        checkpoint,
			ReconciledPodUIDs: reconciled,
		}, nil
	}

	expectedRemaining := remainingAuthorizedPods(checkpoint)
	if !samePodExecutionSet(preflight.EvictionCandidates, expectedRemaining) {
		checkpoint.Status = DrainExecutionPaused
		checkpoint.LastDecision = decision.Escalate
		checkpoint.LastReasonCodes = []decision.ReasonCode{ReasonRecoveryStateDiverged}
		_ = saveDrainCheckpoint(ctx, store, &checkpoint)
		return DrainRecoveryAssessment{
			State:             DrainRecoveryDiverged,
			Decision:          decision.Escalate,
			ReasonCodes:       []decision.ReasonCode{ReasonRecoveryStateDiverged},
			Checkpoint:        checkpoint,
			RemainingPods:     expectedRemaining,
			ReconciledPodUIDs: reconciled,
		}, nil
	}

	if len(expectedRemaining) == 0 {
		checkpoint.Status = DrainExecutionCompleted
		checkpoint.LastDecision = decision.Allow
		checkpoint.LastReasonCodes = nil
		if err := saveDrainCheckpoint(ctx, store, &checkpoint); err != nil {
			return DrainRecoveryAssessment{}, err
		}
		return DrainRecoveryAssessment{
			State:             DrainRecoveryCompleted,
			Decision:          decision.Allow,
			Checkpoint:        checkpoint,
			ReconciledPodUIDs: reconciled,
		}, nil
	}

	checkpoint.Status = DrainExecutionPaused
	checkpoint.LastDecision = decision.Escalate
	checkpoint.LastReasonCodes = []decision.ReasonCode{ReasonRecoveryReauthorizationRequired}
	if err := saveDrainCheckpoint(ctx, store, &checkpoint); err != nil {
		return DrainRecoveryAssessment{}, err
	}

	return DrainRecoveryAssessment{
		State:             DrainRecoveryReauthorizationNeeded,
		Decision:          decision.Escalate,
		ReasonCodes:       []decision.ReasonCode{ReasonRecoveryReauthorizationRequired},
		Checkpoint:        checkpoint,
		RemainingPods:     expectedRemaining,
		ReconciledPodUIDs: reconciled,
	}, nil
}

func cloneDrainCheckpoint(checkpoint DrainExecutionCheckpoint) DrainExecutionCheckpoint {
	checkpoint.AuthorizedPods = append([]PodStateRef(nil), checkpoint.AuthorizedPods...)
	checkpoint.CompletedPodUIDs = append([]string(nil), checkpoint.CompletedPodUIDs...)
	checkpoint.LastReasonCodes = append([]decision.ReasonCode(nil), checkpoint.LastReasonCodes...)
	return checkpoint
}

func remainingAuthorizedPods(checkpoint DrainExecutionCheckpoint) []PodStateRef {
	completed := make(map[string]struct{}, len(checkpoint.CompletedPodUIDs))
	for _, uid := range checkpoint.CompletedPodUIDs {
		completed[uid] = struct{}{}
	}

	remaining := make([]PodStateRef, 0, len(checkpoint.AuthorizedPods))
	for _, pod := range checkpoint.AuthorizedPods {
		if _, ok := completed[pod.UID]; ok {
			continue
		}
		remaining = append(remaining, pod)
	}
	return remaining
}

func orderedCompletedUIDs(authorized []PodStateRef, completed map[string]struct{}) []string {
	out := make([]string, 0, len(completed))
	for _, pod := range authorized {
		if _, ok := completed[pod.UID]; ok {
			out = append(out, pod.UID)
		}
	}
	return out
}

func markCheckpointPaused(
	checkpoint *DrainExecutionCheckpoint,
	decisionValue decision.Decision,
	reasons []decision.ReasonCode,
	now time.Time,
) {
	checkpoint.Status = DrainExecutionPaused
	checkpoint.LastDecision = decisionValue
	checkpoint.LastReasonCodes = append([]decision.ReasonCode(nil), reasons...)
	checkpoint.UpdatedAt = now
}
