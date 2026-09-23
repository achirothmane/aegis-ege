package kubeadapter

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/achirothmane/state-latch/internal/decision"
)

const (
	ReasonCompensationNotOwned          decision.ReasonCode = "COMPENSATION_CORDON_NOT_OWNED"
	ReasonCompensationCompletedDrain    decision.ReasonCode = "COMPENSATION_DRAIN_ALREADY_COMPLETED"
	ReasonCompensationStateDiverged     decision.ReasonCode = "COMPENSATION_STATE_DIVERGED"
	ReasonCompensationUnexpectedWorkload decision.ReasonCode = "COMPENSATION_UNEXPECTED_WORKLOAD"
	ReasonCompensationUnavailable       decision.ReasonCode = "COMPENSATION_UNAVAILABLE"
	ReasonCompensationUncordonRejected  decision.ReasonCode = "COMPENSATION_UNCORDON_REJECTED"
)

type DrainCompensationState string

const (
	DrainCompensationReady         DrainCompensationState = "READY"
	DrainCompensationNotApplicable DrainCompensationState = "NOT_APPLICABLE"
	DrainCompensationBlocked       DrainCompensationState = "BLOCKED"
	DrainCompensationApplied       DrainCompensationState = "APPLIED"
)

type DrainCompensationAssessment struct {
	State       DrainCompensationState
	Decision    decision.Decision
	ReasonCodes []decision.ReasonCode
	Checkpoint DrainExecutionCheckpoint
	Snapshot    NodeDrainSnapshot
}

type CompensationExecutor interface {
	UncordonNode(ctx context.Context, nodeName, resourceVersion string) error
}

func (a *Adapter) InspectDrainCompensation(
	ctx context.Context,
	actionID string,
	nodeName string,
	store DrainCheckpointStore,
) (DrainCompensationAssessment, error) {
	if store == nil {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
		}, nil
	}

	checkpoint, err := store.Load(ctx, actionID)
	if errors.Is(err, ErrDrainCheckpointNotFound) {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRecoveryCheckpointNotFound},
		}, nil
	}
	if err != nil {
		return DrainCompensationAssessment{}, err
	}
	if checkpoint.ActionID != actionID || checkpoint.NodeName != nodeName {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationStateDiverged},
			Checkpoint:  checkpoint,
		}, nil
	}

	if checkpoint.Status == DrainExecutionCompensated {
		return DrainCompensationAssessment{
			State:      DrainCompensationApplied,
			Decision:   decision.Allow,
			Checkpoint: checkpoint,
		}, nil
	}
	if checkpoint.Status == DrainExecutionCompleted {
		return DrainCompensationAssessment{
			State:       DrainCompensationNotApplicable,
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationCompletedDrain},
			Checkpoint:  checkpoint,
		}, nil
	}
	if checkpoint.OriginallyUnschedulable || !checkpoint.CordonOwned {
		return DrainCompensationAssessment{
			State:       DrainCompensationNotApplicable,
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationNotOwned},
			Checkpoint:  checkpoint,
		}, nil
	}

	snapshot, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return DrainCompensationAssessment{}, err
	}
	if snapshot.NodeUID != checkpoint.NodeUID ||
		snapshot.NodeHealth != checkpoint.NodeHealth ||
		!snapshot.Unschedulable {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationStateDiverged},
			Checkpoint:  checkpoint,
			Snapshot:    snapshot,
		}, nil
	}

	authorized := make(map[string]struct{}, len(checkpoint.AuthorizedPods))
	for _, pod := range checkpoint.AuthorizedPods {
		authorized[pod.UID] = struct{}{}
	}
	if countUnexpectedDrainWorkloads(pods, authorized) != 0 {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationUnexpectedWorkload},
			Checkpoint:  checkpoint,
			Snapshot:    snapshot,
		}, nil
	}

	return DrainCompensationAssessment{
		State:      DrainCompensationReady,
		Decision:   decision.Allow,
		Checkpoint: checkpoint,
		Snapshot:   snapshot,
	}, nil
}

func (a *Adapter) CompensateNodeDrain(
	ctx context.Context,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
) (DrainCompensationAssessment, error) {
	if !a.mutationsEnabled {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRealExecutionUnavailable},
		}, nil
	}
	compensator, ok := a.executor.(CompensationExecutor)
	if !ok || a.lockManager == nil {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationUnavailable},
		}, nil
	}

	initial, err := a.InspectDrainCompensation(ctx, actionID, nodeName, store)
	if err != nil || initial.State != DrainCompensationReady {
		return initial, err
	}

	lockGuard, err := acquireExecutionLeaseGuard(
		ctx,
		a.lockManager,
		executionLockNamespace(policy),
		"node/"+nodeName,
		executionLockDuration(policy),
	)
	if err != nil {
		reason := ReasonExecutionLockUnavailable
		if errors.Is(err, ErrExecutionLockHeld) {
			reason = ReasonExecutionLockHeld
		}
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{reason},
			Checkpoint:  initial.Checkpoint,
		}, nil
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lockGuard.Close(releaseCtx)
	}()

	if err := lockGuard.EnsureHeld(ctx); err != nil {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionLockLost},
			Checkpoint:  initial.Checkpoint,
		}, nil
	}

	fresh, err := a.InspectDrainCompensation(ctx, actionID, nodeName, store)
	if err != nil || fresh.State != DrainCompensationReady {
		return fresh, err
	}

	if err := compensator.UncordonNode(ctx, nodeName, fresh.Snapshot.ResourceVersion); err != nil {
		reason := ReasonCompensationUncordonRejected
		if apierrors.IsConflict(err) {
			reason = decision.ResourceVersionChanged
		}
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{reason},
			Checkpoint:  fresh.Checkpoint,
			Snapshot:    fresh.Snapshot,
		}, nil
	}

	after, err := a.reader.GetNode(ctx, nodeName)
	if err != nil {
		return DrainCompensationAssessment{}, err
	}
	if string(after.UID) != fresh.Checkpoint.NodeUID || after.Spec.Unschedulable {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonCompensationStateDiverged},
			Checkpoint:  fresh.Checkpoint,
		}, nil
	}

	checkpoint := fresh.Checkpoint
	checkpoint.Cordoned = false
	checkpoint.Status = DrainExecutionCompensated
	checkpoint.LastDecision = decision.Allow
	checkpoint.LastReasonCodes = nil
	checkpoint.UpdatedAt = a.now().UTC()
	if err := saveDrainCheckpoint(ctx, store, &checkpoint); err != nil {
		return DrainCompensationAssessment{
			State:       DrainCompensationBlocked,
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
			Checkpoint:  checkpoint,
		}, nil
	}

	return DrainCompensationAssessment{
		State:      DrainCompensationApplied,
		Decision:   decision.Allow,
		Checkpoint: checkpoint,
		Snapshot: NodeDrainSnapshot{
			NodeName:        after.Name,
			NodeUID:         string(after.UID),
			ResourceVersion: after.ResourceVersion,
			NodeHealth:      nodeHealth(after),
			Unschedulable:   after.Spec.Unschedulable,
			ObservedAt:      a.now().UTC(),
		},
	}, nil
}

func (a DrainCompensationAssessment) String() string {
	return fmt.Sprintf("%s/%s", a.State, a.Decision)
}
