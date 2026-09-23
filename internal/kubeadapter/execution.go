package kubeadapter

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/achirothmane/state-latch/internal/decision"
)

const (
	ReasonServerDryRunUnavailable      decision.ReasonCode = "SERVER_DRY_RUN_UNAVAILABLE"
	ReasonServerDryRunCordonRejected   decision.ReasonCode = "SERVER_DRY_RUN_CORDON_REJECTED"
	ReasonServerDryRunEvictionRejected decision.ReasonCode = "SERVER_DRY_RUN_EVICTION_REJECTED"
)

type DrainExecutionStepKind string

const (
	DrainStepCordonNode DrainExecutionStepKind = "CORDON_NODE"
	DrainStepEvictPod   DrainExecutionStepKind = "EVICT_POD"
)

type DrainExecutionStep struct {
	Kind            DrainExecutionStepKind
	NodeName        string
	ResourceVersion string
	Pod             *PodStateRef
}

type DrainExecutionPlan struct {
	ActionID            string
	NodeName            string
	NodeUID             string
	NodeHealth          string
	NodeResourceVersion string
	Steps               []DrainExecutionStep
}

type DrainDryRunStepResult struct {
	Step       DrainExecutionStep
	Passed     bool
	ReasonCode decision.ReasonCode
	Error      string
}

type DrainDryRunReport struct {
	Passed bool
	Steps  []DrainDryRunStepResult
}

type NodeDrainPreparation struct {
	Decision      decision.Decision
	ReasonCodes   []decision.ReasonCode
	Snapshot      NodeDrainSnapshot
	Preflight     DrainPreflightReport
	Plan          *DrainExecutionPlan
	PlanDigest    string
	DryRun        *DrainDryRunReport
	Authorization *decision.Authorization
}

func BuildDrainExecutionPlan(
	actionID string,
	snapshot NodeDrainSnapshot,
	preflight DrainPreflightReport,
) DrainExecutionPlan {
	steps := make([]DrainExecutionStep, 0, len(preflight.EvictionCandidates)+1)
	steps = append(steps, DrainExecutionStep{
		Kind:            DrainStepCordonNode,
		NodeName:        snapshot.NodeName,
		ResourceVersion: snapshot.ResourceVersion,
	})

	for _, candidate := range preflight.EvictionCandidates {
		pod := candidate
		steps = append(steps, DrainExecutionStep{
			Kind: DrainStepEvictPod,
			Pod:  &pod,
		})
	}

	return DrainExecutionPlan{
		ActionID:            actionID,
		NodeName:            snapshot.NodeName,
		NodeUID:             snapshot.NodeUID,
		NodeHealth:          snapshot.NodeHealth,
		NodeResourceVersion: snapshot.ResourceVersion,
		Steps:               steps,
	}
}

func (a *Adapter) DryRunDrainExecutionPlan(
	ctx context.Context,
	plan DrainExecutionPlan,
) (DrainDryRunReport, error) {
	if a.executor == nil {
		return DrainDryRunReport{}, fmt.Errorf("server dry-run executor is not configured")
	}

	report := DrainDryRunReport{
		Passed: true,
		Steps:  make([]DrainDryRunStepResult, 0, len(plan.Steps)),
	}

	for _, step := range plan.Steps {
		stepResult := DrainDryRunStepResult{Step: step}

		switch step.Kind {
		case DrainStepCordonNode:
			err := a.executor.DryRunCordonNode(ctx, step.NodeName, step.ResourceVersion)
			if err != nil {
				stepResult.Error = err.Error()
				if apierrors.IsConflict(err) {
					stepResult.ReasonCode = decision.ResourceVersionChanged
				} else {
					stepResult.ReasonCode = ReasonServerDryRunCordonRejected
				}
				report.Passed = false
				report.Steps = append(report.Steps, stepResult)
				return report, nil
			}

		case DrainStepEvictPod:
			if step.Pod == nil {
				return DrainDryRunReport{}, fmt.Errorf("eviction step is missing pod state")
			}
			if err := a.executor.DryRunEvictPod(ctx, *step.Pod); err != nil {
				stepResult.Error = err.Error()
				switch {
				case apierrors.IsConflict(err):
					stepResult.ReasonCode = decision.ExecutionPlanChanged
				case apierrors.IsTooManyRequests(err):
					stepResult.ReasonCode = decision.ReasonCode(FindingPDBDisruptionBlocked)
				default:
					stepResult.ReasonCode = ReasonServerDryRunEvictionRejected
				}
				report.Passed = false
			}

		default:
			return DrainDryRunReport{}, fmt.Errorf("unsupported drain execution step %q", step.Kind)
		}

		stepResult.Passed = stepResult.Error == ""
		report.Steps = append(report.Steps, stepResult)
	}

	return report, nil
}

func (a *Adapter) PrepareNodeDrainExecution(
	ctx context.Context,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
) (NodeDrainPreparation, error) {
	snapshot, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return NodeDrainPreparation{}, err
	}

	preflight := a.preflightNodeDrain(ctx, pods, policy)
	preparation := NodeDrainPreparation{
		Decision:  preflight.Decision,
		Snapshot:  snapshot,
		Preflight: preflight,
	}

	if preflight.Decision != decision.Allow {
		preparation.ReasonCodes = preflightDecisionReasons(preflight)
		return preparation, nil
	}

	kernelResult := evaluateNodeDrainKernel(actionID, snapshot, preflight, policy)
	preparation.Decision = kernelResult.Decision
	preparation.ReasonCodes = kernelResult.ReasonCodes
	if kernelResult.Decision != decision.Allow || kernelResult.Authorization == nil {
		return preparation, nil
	}

	plan := BuildDrainExecutionPlan(actionID, snapshot, preflight)
	planDigest := DigestDrainExecutionPlan(plan)
	preparation.Plan = &plan
	preparation.PlanDigest = planDigest

	auth := *kernelResult.Authorization
	auth.PlanDigest = planDigest

	if a.executor == nil {
		preparation.Decision = decision.Escalate
		preparation.ReasonCodes = []decision.ReasonCode{ReasonServerDryRunUnavailable}
		return preparation, nil
	}

	dryRun, err := a.DryRunDrainExecutionPlan(ctx, plan)
	if err != nil {
		return NodeDrainPreparation{}, err
	}
	preparation.DryRun = &dryRun

	if !dryRun.Passed {
		failureDecision, failureReason := dryRunFailure(dryRun)
		preparation.Decision = failureDecision
		preparation.ReasonCodes = []decision.ReasonCode{failureReason}
		return preparation, nil
	}

	validation := decision.ValidateAuthorization(auth, decision.ExecutionAttempt{
		ActionID:        actionID,
		Action:          "drain",
		Target:          "node/" + snapshot.NodeName,
		ResourceVersion: snapshot.ResourceVersion,
		PlanDigest:      planDigest,
		Now:             a.now().UTC(),
	})
	if !validation.Valid {
		preparation.Decision = decision.Escalate
		preparation.ReasonCodes = validation.ReasonCodes
		return preparation, nil
	}

	preparation.Decision = decision.Allow
	preparation.Authorization = &auth
	return preparation, nil
}

func dryRunFailure(report DrainDryRunReport) (decision.Decision, decision.ReasonCode) {
	for _, step := range report.Steps {
		if step.Passed {
			continue
		}

		reason := step.ReasonCode
		if reason == "" {
			if step.Step.Kind == DrainStepCordonNode {
				reason = ReasonServerDryRunCordonRejected
			} else {
				reason = ReasonServerDryRunEvictionRejected
			}
		}

		switch reason {
		case decision.ResourceVersionChanged, decision.ExecutionPlanChanged:
			return decision.Escalate, reason
		default:
			return decision.Block, reason
		}
	}
	return decision.Block, ReasonServerDryRunEvictionRejected
}
