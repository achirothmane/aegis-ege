package kubeadapter

import (
	"context"
	"fmt"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

const (
	ReasonRealExecutionUnavailable       decision.ReasonCode = "REAL_EXECUTION_UNAVAILABLE"
	ReasonExecutionCordonRejected        decision.ReasonCode = "EXECUTION_CORDON_REJECTED"
	ReasonExecutionEvictionRejected      decision.ReasonCode = "EXECUTION_EVICTION_REJECTED"
	ReasonExecutionEvictionNotObserved   decision.ReasonCode = "EXECUTION_EVICTION_NOT_OBSERVED"
	ReasonExecutionCordonStateChanged    decision.ReasonCode = "EXECUTION_CORDON_STATE_CHANGED"
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
	mutator, ok := a.executor.(MutationExecutor)
	if !ok {
		return GuardedDrainExecutionReport{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{ReasonRealExecutionUnavailable},
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

	cordonStep := plan.Steps[0]
	if err := mutator.CordonNode(ctx, cordonStep.NodeName, cordonStep.ResourceVersion); err != nil {
		report.Decision = decision.Escalate
		report.ReasonCodes = []decision.ReasonCode{ReasonExecutionCordonRejected}
		report.Steps = append(report.Steps, DrainMutationStepResult{
			Step:  cordonStep,
			Error: err.Error(),
		})
		return report, nil
	}
	report.Steps = append(report.Steps, DrainMutationStepResult{
		Step:    cordonStep,
		Applied: true,
	})

	remaining := evictionCandidatesFromPlan(plan)
	for len(remaining) > 0 {
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
			return report, nil
		}

		target := remaining[0]
		step := DrainExecutionStep{
			Kind: DrainStepEvictPod,
			Pod:  &target,
		}
		if err := mutator.EvictPod(ctx, target); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionEvictionRejected}
			report.Steps = append(report.Steps, DrainMutationStepResult{
				Step:  step,
				Error: err.Error(),
			})
			return report, nil
		}
		report.Steps = append(report.Steps, DrainMutationStepResult{
			Step:    step,
			Applied: true,
		})

		if err := a.waitForPodUIDAbsent(ctx, plan.NodeName, target.UID, evictionObservationTimeout(policy)); err != nil {
			report.Decision = decision.Escalate
			report.ReasonCodes = []decision.ReasonCode{ReasonExecutionEvictionNotObserved}
			return report, nil
		}

		remaining = remaining[1:]
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
		return report, nil
	}

	report.Decision = decision.Allow
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
