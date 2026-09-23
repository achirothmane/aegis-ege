package kubeadapter

import (
	"context"
	"strconv"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/outcome"
)

func (a *Adapter) ObserveDrainOutcome(
	ctx context.Context,
	auth decision.Authorization,
	plan DrainExecutionPlan,
	contributors []outcome.Contributor,
) (outcome.Record, error) {
	expected := make(map[string]string, len(plan.Steps)+1)
	expected["node_unschedulable"] = "true"

	evictedUIDs := make(map[string]struct{})
	for _, step := range plan.Steps {
		if step.Kind != DrainStepEvictPod || step.Pod == nil {
			continue
		}
		evictedUIDs[step.Pod.UID] = struct{}{}
		expected["pod_uid/"+step.Pod.UID+"_absent"] = "true"
	}

	observedAt := a.now().UTC()
	node, err := a.reader.GetNode(ctx, plan.NodeName)
	if err != nil {
		record := outcome.Compare(
			auth.ActionID,
			auth.EvidenceDigest,
			auth.PlanDigest,
			expected,
			map[string]string{},
			contributors,
			observedAt,
		)
		record.Verdict = outcome.Unknown
		record.Detail = "postflight node observation failed: " + err.Error()
		return record, nil
	}

	pods, err := a.reader.ListPodsOnNode(ctx, plan.NodeName)
	if err != nil {
		record := outcome.Compare(
			auth.ActionID,
			auth.EvidenceDigest,
			auth.PlanDigest,
			expected,
			map[string]string{
				"node_unschedulable": strconv.FormatBool(node.Spec.Unschedulable),
			},
			contributors,
			observedAt,
		)
		record.Verdict = outcome.Unknown
		record.Detail = "postflight pod observation failed: " + err.Error()
		return record, nil
	}

	present := make(map[string]struct{}, len(pods))
	for _, pod := range pods {
		present[string(pod.UID)] = struct{}{}
	}

	observed := make(map[string]string, len(expected))
	observed["node_unschedulable"] = strconv.FormatBool(node.Spec.Unschedulable)
	for uid := range evictedUIDs {
		_, exists := present[uid]
		observed["pod_uid/"+uid+"_absent"] = strconv.FormatBool(!exists)
	}

	return outcome.Compare(
		auth.ActionID,
		auth.EvidenceDigest,
		auth.PlanDigest,
		expected,
		observed,
		contributors,
		observedAt,
	), nil
}
