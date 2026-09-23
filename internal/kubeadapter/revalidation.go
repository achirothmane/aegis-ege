package kubeadapter

import (
	"context"

	"github.com/achirothmane/state-latch/internal/decision"
)

type NodeDrainRevalidation struct {
	Decision          decision.Decision
	ReasonCodes       []decision.ReasonCode
	Snapshot          NodeDrainSnapshot
	Preflight         DrainPreflightReport
	CurrentPlan       *DrainExecutionPlan
	CurrentPlanDigest string
}

func (a *Adapter) RevalidateNodeDrainAuthorization(
	ctx context.Context,
	auth decision.Authorization,
	nodeName string,
	policy NodeDrainPolicy,
) (NodeDrainRevalidation, error) {
	if auth.PlanDigest == "" {
		return NodeDrainRevalidation{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{decision.InsufficientStateBinding},
		}, nil
	}

	snapshot, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return NodeDrainRevalidation{}, err
	}

	preflight := a.preflightNodeDrain(ctx, pods, policy)
	result := NodeDrainRevalidation{
		Decision:  preflight.Decision,
		Snapshot:  snapshot,
		Preflight: preflight,
	}
	if preflight.Decision != decision.Allow {
		result.ReasonCodes = preflightDecisionReasons(preflight)
		return result, nil
	}

	plan := BuildDrainExecutionPlan(auth.ActionID, snapshot, preflight)
	planDigest := DigestDrainExecutionPlan(plan)
	result.CurrentPlan = &plan
	result.CurrentPlanDigest = planDigest

	validation := decision.ValidateAuthorization(auth, decision.ExecutionAttempt{
		ActionID:        auth.ActionID,
		Action:          "drain",
		Target:          "node/" + nodeName,
		ResourceVersion: snapshot.ResourceVersion,
		PlanDigest:      planDigest,
		Now:             a.now().UTC(),
	})
	if !validation.Valid {
		result.Decision = invalidRevalidationDecision(validation.ReasonCodes)
		result.ReasonCodes = validation.ReasonCodes
		return result, nil
	}

	result.Decision = decision.Allow
	return result, nil
}

func invalidRevalidationDecision(reasons []decision.ReasonCode) decision.Decision {
	for _, reason := range reasons {
		switch reason {
		case decision.ActionChanged, decision.TargetChanged:
			return decision.Block
		}
	}
	return decision.Escalate
}
