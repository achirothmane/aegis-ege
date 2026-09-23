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
	ReasonRealExecutionUnavailable     decision.ReasonCode = "REAL_EXECUTION_UNAVAILABLE"
	ReasonExecutionCordonRejected      decision.ReasonCode = "EXECUTION_CORDON_REJECTED"
	ReasonExecutionEvictionRejected    decision.ReasonCode = "EXECUTION_EVICTION_REJECTED"
	ReasonExecutionEvictionNotObserved decision.ReasonCode = "EXECUTION_EVICTION_NOT_OBSERVED"
	ReasonExecutionCordonStateChanged  decision.ReasonCode = "EXECUTION_CORDON_STATE_CHANGED"
)

type MutationExecutor interface {
	CordonNode(ctx context.Context, nodeName, resourceVersion string) error
	EvictPod(ctx context.Context, pod PodStateRef) error
}

type DrainMutationStepResult struct {
	Step    DrainExecutionStep
	Applied bool
	Error   string
}

type GuardedDrainExecutionReport struct {
	Decision    decision.Decision
	ReasonCodes []decision.ReasonCode
	PlanDigest  string
	Steps       []DrainMutationStepResult
}

func (a *Adapter) ExecuteAuthorizedNodeDrain(
	ctx context.Context,
	auth decision.Authorization,
	nodeName string,
	policy NodeDrainPolicy,
) (GuardedDrainExecutionReport, error) {
	return a.executeAuthorizedNodeDrain(ctx, auth, nodeName, policy, nil, nil)
}

func (a *Adapter) ExecuteAuthorizedNodeDrainWithCheckpointStore(
	ctx context.Context,
	auth decision.Authorization,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
) (GuardedDrainExecutionReport, error) {
	if store == nil {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
		}, nil
	}
	return a.executeAuthorizedNodeDrain(ctx, auth, nodeName, policy, store, nil)
}

func (a *Adapter) ResumeAuthorizedNodeDrain(
	ctx context.Context,
	auth decision.Authorization,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
) (GuardedDrainExecutionReport, error) {
	assessment, err := a.InspectDrainRecovery(ctx, auth.ActionID, nodeName, policy, store)
	if err != nil {
		return GuardedDrainExecutionReport{}, err
	}

	switch assessment.State {
	case DrainRecoveryCompleted:
		return GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: assessment.Checkpoint.ActivePlanDigest,
		}, nil
	case DrainRecoveryReauthorizationNeeded:
		// Continue below with a fresh authorization.
	default:
		return GuardedDrainExecutionReport{
			Decision:    assessment.Decision,
			ReasonCodes: append([]decision.ReasonCode(nil), assessment.ReasonCodes...),
			PlanDigest:  assessment.Checkpoint.ActivePlanDigest,
		}, nil
	}

	initial, err := a.RevalidateNodeDrainAuthorization(ctx, auth, nodeName, policy)
	if err != nil {
		return GuardedDrainExecutionReport{}, err
	}
	if initial.Decision != decision.Allow || initial.CurrentPlan == nil {
		return GuardedDrainExecutionReport{
			Decision:    initial.Decision,
			ReasonCodes: append([]decision.ReasonCode(nil), initial.ReasonCodes...),
		}, nil
	}

	if !samePodExecutionSet(initial.Preflight.EvictionCandidates, assessment.RemainingPods) {
		checkpoint := assessment.Checkpoint
		markCheckpointPaused(
			&checkpoint,
			decision.Escalate,
			[]decision.ReasonCode{ReasonRecoveryStateDiverged},
			a.now().UTC(),
		)
		_ = store.Save(ctx, checkpoint)
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRecoveryStateDiverged},
			PlanDigest:  initial.CurrentPlanDigest,
		}, nil
	}

	checkpoint := assessment.Checkpoint
	checkpoint.ActivePlanDigest = initial.CurrentPlanDigest
	checkpoint.Status = DrainExecutionRunning
	checkpoint.LastDecision = decision.Allow
	checkpoint.LastReasonCodes = nil
	checkpoint.UpdatedAt = a.now().UTC()
	if err := store.Save(ctx, checkpoint); err != nil {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
			PlanDigest:  initial.CurrentPlanDigest,
		}, nil
	}

	return a.executeAuthorizedNodeDrain(
		ctx,
		auth,
		nodeName,
		policy,
		store,
		&checkpoint,
	)
}

func (a *Adapter) executeAuthorizedNodeDrain(
	ctx context.Context,
	auth decision.Authorization,
	nodeName string,
	policy NodeDrainPolicy,
	store DrainCheckpointStore,
	resumeCheckpoint *DrainExecutionCheckpoint,
) (GuardedDrainExecutionReport, error) {
	if !a.mutationsEnabled {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRealExecutionUnavailable},
		}, nil
	}

	mutator, ok := a.executor.(MutationExecutor)
	if !ok {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRealExecutionUnavailable},
		}, nil
	}
	if a.lockManager == nil {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionLockUnavailable},
		}, nil
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
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{reason},
		}, nil
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lockGuard.Close(releaseCtx)
	}()

	if err := lockGuard.EnsureHeld(); err != nil {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonExecutionLockLost},
		}, nil
	}

	initial, err := a.RevalidateNodeDrainAuthorization(ctx, auth, nodeName, policy)
	if err != nil {
		return GuardedDrainExecutionReport{}, err
	}
	if initial.Decision != decision.Allow || initial.CurrentPlan == nil {
		return GuardedDrainExecutionReport{
			Decision:    initial.Decision,
			ReasonCodes: append([]decision.ReasonCode(nil), initial.ReasonCodes...),
		}, nil
	}

	plan := *initial.CurrentPlan
	report := GuardedDrainExecutionReport{
		Decision:   decision.Allow,
		PlanDigest: initial.CurrentPlanDigest,
		Steps:      make([]DrainMutationStepResult, 0, len(plan.Steps)),
	}

	if len(plan.Steps) == 0 || plan.Steps[0].Kind != DrainStepCordonNode {
		return GuardedDrainExecutionReport{}, fmt.Errorf("drain execution plan is missing initial cordon step")
	}

	var checkpoint *DrainExecutionCheckpoint
	if store != nil {
		if resumeCheckpoint != nil {
			copyValue := cloneDrainCheckpoint(*resumeCheckpoint)
			copyValue.ActivePlanDigest = initial.CurrentPlanDigest
			checkpoint = &copyValue
		} else {
			copyValue := DrainExecutionCheckpoint{
				ActionID:           auth.ActionID,
				NodeName:           plan.NodeName,
				NodeUID:            plan.NodeUID,
				NodeHealth:         plan.NodeHealth,
				OriginalPlanDigest: initial.CurrentPlanDigest,
				ActivePlanDigest:   initial.CurrentPlanDigest,
				AuthorizedPods:     append([]PodStateRef(nil), evictionCandidatesFromPlan(plan)...),
				Status:             DrainExecutionRunning,
				LastDecision:       decision.Allow,
				UpdatedAt:          a.now().UTC(),
			}
			checkpoint = &copyValue
			if err := store.Save(ctx, *checkpoint); err != nil {
				return GuardedDrainExecutionReport{
					Decision:    decision.Escalate,
					ReasonCodes: []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
					PlanDigest:  initial.CurrentPlanDigest,
				}, nil
			}
		}
	}

	cordonStep := plan.Steps[0]
	alreadyCordoned := checkpoint != nil && checkpoint.Cordoned
	if !alreadyCordoned {
		if err := lockGuard.EnsureHeld(); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionLockLost}
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}
		if err := mutator.CordonNode(ctx, cordonStep.NodeName, cordonStep.ResourceVersion); err != nil {
			reason := ReasonExecutionCordonRejected
			if apierrors.IsConflict(err) {
				reason = decision.ResourceVersionChanged
			}
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{reason}
			report.Steps = append(report.Steps, DrainMutationStepResult{
				Step:  cordonStep,
				Error: err.Error(),
			})
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}
		report.Steps = append(report.Steps, DrainMutationStepResult{
			Step:    cordonStep,
			Applied: true,
		})

		if checkpoint != nil {
			checkpoint.Cordoned = true
			checkpoint.UpdatedAt = a.now().UTC()
			if err := store.Save(ctx, *checkpoint); err != nil {
				report.Decision = decision.Escalate
				report.ReasonCodes = []decision.ReasonCode{ReasonExecutionCheckpointUnavailable}
				return report, nil
			}
		}
	}

	remaining := evictionCandidatesFromPlan(plan)
	for len(remaining) > 0 {
		if err := lockGuard.EnsureHeld(); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionLockLost}
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}

		currentDecision, currentReasons, err := a.revalidateRemainingDrainExecution(
			ctx,
			auth,
			plan,
			remaining,
			policy,
		)
		if err != nil {
			return GuardedDrainExecutionReport{}, err
		}
		if currentDecision != decision.Allow {
			report.Decision = currentDecision
			report.ReasonCodes = currentReasons
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}

		target := remaining[0]
		step := DrainExecutionStep{
			Kind: DrainStepEvictPod,
			Pod:  &target,
		}
		if err := lockGuard.EnsureHeld(); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionLockLost}
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}
		if err := mutator.EvictPod(ctx, target); err != nil {
			mutationDecision := decision.Escalate
			reason := ReasonExecutionEvictionRejected
			switch {
			case apierrors.IsConflict(err):
				reason = decision.ExecutionPlanChanged
			case apierrors.IsTooManyRequests(err):
				mutationDecision = decision.Block
				reason = decision.ReasonCode(FindingPDBDisruptionBlocked)
			}
			report.Decision = mutationDecision
			report.ReasonCodes = []decision.ReasonCode{reason}
			report.Steps = append(report.Steps, DrainMutationStepResult{
				Step:  step,
				Error: err.Error(),
			})
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}
		report.Steps = append(report.Steps, DrainMutationStepResult{
			Step:    step,
			Applied: true,
		})

		if err := a.waitForPodUIDAbsent(ctx, plan.NodeName, target.UID, evictionObservationTimeout(policy)); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionEvictionNotObserved}
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}
		if err := lockGuard.EnsureHeld(); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionLockLost}
			pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
			return report, nil
		}

		if checkpoint != nil {
			checkpoint.CompletedPodUIDs = appendCompletedUID(
				checkpoint.CompletedPodUIDs,
				target.UID,
			)
			checkpoint.Status = DrainExecutionRunning
			checkpoint.LastDecision = decision.Allow
			checkpoint.LastReasonCodes = nil
			checkpoint.UpdatedAt = a.now().UTC()
			if err := store.Save(ctx, *checkpoint); err != nil {
				report.Decision = decision.Escalate
				report.ReasonCodes = []decision.ReasonCode{ReasonExecutionCheckpointUnavailable}
				return report, nil
			}
		}

		remaining = remaining[1:]
	}

	if err := lockGuard.EnsureHeld(); err != nil {
		report.Decision = decision.Escalate
		report.ReasonCodes = []decision.ReasonCode{ReasonExecutionLockLost}
		pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
		return report, nil
	}

	finalDecision, finalReasons, err := a.revalidateRemainingDrainExecution(
		ctx,
		auth,
		plan,
		nil,
		policy,
	)
	if err != nil {
		return GuardedDrainExecutionReport{}, err
	}
	if finalDecision != decision.Allow {
		report.Decision = finalDecision
		report.ReasonCodes = finalReasons
		pauseCheckpointBestEffort(store, checkpoint, report.Decision, report.ReasonCodes, a.now().UTC())
		return report, nil
	}

	report.Decision = decision.Allow
	if checkpoint != nil {
		checkpoint.Status = DrainExecutionCompleted
		checkpoint.LastDecision = decision.Allow
		checkpoint.LastReasonCodes = nil
		checkpoint.UpdatedAt = a.now().UTC()
		if err := store.Save(ctx, *checkpoint); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionCheckpointUnavailable}
			return report, nil
		}
	}
	return report, nil
}

func (a *Adapter) revalidateRemainingDrainExecution(
	ctx context.Context,
	auth decision.Authorization,
	authorizedPlan DrainExecutionPlan,
	expectedRemaining []PodStateRef,
	policy NodeDrainPolicy,
) (decision.Decision, []decision.ReasonCode, error) {
	now := a.now().UTC()
	if !now.Before(auth.ValidUntil) {
		return decision.Escalate, []decision.ReasonCode{decision.AuthorizationExpired}, nil
	}
	if auth.ActionID != authorizedPlan.ActionID || auth.Action != "drain" {
		return decision.Block, []decision.ReasonCode{decision.ActionChanged}, nil
	}
	if auth.Target != "node/"+authorizedPlan.NodeName {
		return decision.Block, []decision.ReasonCode{decision.TargetChanged}, nil
	}

	snapshot, pods, err := a.inspectNodeDrainState(ctx, authorizedPlan.NodeName)
	if err != nil {
		return "", nil, err
	}

	if snapshot.NodeUID != authorizedPlan.NodeUID || snapshot.NodeHealth != authorizedPlan.NodeHealth {
		return decision.Escalate, []decision.ReasonCode{decision.ExecutionPlanChanged}, nil
	}
	if !snapshot.Unschedulable {
		return decision.Escalate, []decision.ReasonCode{ReasonExecutionCordonStateChanged}, nil
	}

	preflight := a.preflightNodeDrain(ctx, pods, policy)
	if preflight.Decision != decision.Allow {
		return preflight.Decision, preflightDecisionReasons(preflight), nil
	}

	if !samePodExecutionSet(preflight.EvictionCandidates, expectedRemaining) {
		return decision.Escalate, []decision.ReasonCode{decision.ExecutionPlanChanged}, nil
	}

	return decision.Allow, nil, nil
}

func evictionCandidatesFromPlan(plan DrainExecutionPlan) []PodStateRef {
	out := make([]PodStateRef, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		if step.Kind != DrainStepEvictPod || step.Pod == nil {
			continue
		}
		out = append(out, *step.Pod)
	}
	return out
}

func samePodExecutionSet(current, expected []PodStateRef) bool {
	if len(current) != len(expected) {
		return false
	}
	for i := range current {
		if current[i].Namespace != expected[i].Namespace ||
			current[i].Name != expected[i].Name ||
			current[i].UID != expected[i].UID ||
			current[i].StateDigest != expected[i].StateDigest {
			return false
		}
	}
	return true
}

func evictionObservationTimeout(policy NodeDrainPolicy) time.Duration {
	if policy.EvictionObservationTimeout > 0 {
		return policy.EvictionObservationTimeout
	}
	return 30 * time.Second
}

func (a *Adapter) waitForPodUIDAbsent(
	ctx context.Context,
	nodeName string,
	uid string,
	timeout time.Duration,
) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		pods, err := a.reader.ListPodsOnNode(waitCtx, nodeName)
		if err != nil {
			return fmt.Errorf("observe pod eviction: %w", err)
		}

		found := false
		for _, pod := range pods {
			if string(pod.UID) == uid {
				found = true
				break
			}
		}
		if !found {
			return nil
		}

		select {
		case <-waitCtx.Done():
			return fmt.Errorf("pod uid %q remained on node %q: %w", uid, nodeName, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func appendCompletedUID(completed []string, uid string) []string {
	for _, existing := range completed {
		if existing == uid {
			return completed
		}
	}
	return append(completed, uid)
}

func pauseCheckpointBestEffort(
	store DrainCheckpointStore,
	checkpoint *DrainExecutionCheckpoint,
	decisionValue decision.Decision,
	reasons []decision.ReasonCode,
	now time.Time,
) {
	if store == nil || checkpoint == nil {
		return
	}
	markCheckpointPaused(checkpoint, decisionValue, reasons, now)
	_ = store.Save(context.Background(), *checkpoint)
}
