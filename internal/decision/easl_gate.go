package decision

import "github.com/achirothmane/easl"

// evaluateEASL maps EASL's domain-neutral epistemic state into Aegis-EGE's
// execution policy. EASL establishes what is justified; Aegis-EGE decides
// what that means for an execution request.
func evaluateEASL(snapshot easl.Snapshot) *Result {
	evaluation, err := easl.Evaluate(snapshot)
	if err != nil {
		return &Result{
			Decision:    Escalate,
			ReasonCodes: []ReasonCode{AssumptionValidityUnknown},
		}
	}

	if evaluation.State == easl.StateValid {
		return nil
	}

	if evaluation.EvidenceStatus == easl.EvidenceContradictory {
		return &Result{
			Decision:    Block,
			ReasonCodes: []ReasonCode{EvidenceContradicted},
		}
	}

	if hasEASLInvalidationReason(evaluation, easl.ReasonStaleEvidence) {
		return &Result{
			Decision:    Block,
			ReasonCodes: []ReasonCode{EvidenceStale},
		}
	}

	if hasEASLInvalidationReason(evaluation, easl.ReasonAssumptionExpired) {
		return &Result{
			Decision:    Block,
			ReasonCodes: []ReasonCode{AssumptionExpired},
		}
	}

	if hasEASLInvalidationReason(evaluation, easl.ReasonDependencyInvalid) {
		return &Result{
			Decision:    Block,
			ReasonCodes: []ReasonCode{AssumptionInvalidated},
		}
	}

	if hasEASLInvalidationReason(evaluation, easl.ReasonMissingEvidence) {
		return &Result{
			Decision:    Escalate,
			ReasonCodes: []ReasonCode{InsufficientEvidence},
		}
	}

	// DEGRADED currently means EASL surfaced stale evidence that is not required
	// by an assumption. Aegis-EGE treats that as uncertainty requiring review,
	// rather than silently minting an execution authorization.
	if evaluation.State == easl.StateDegraded {
		return &Result{
			Decision:    Escalate,
			ReasonCodes: []ReasonCode{EvidenceStale},
		}
	}

	return &Result{
		Decision:    Escalate,
		ReasonCodes: []ReasonCode{AssumptionValidityUnknown},
	}
}

func hasEASLInvalidationReason(evaluation easl.Evaluation, reason easl.InvalidationReason) bool {
	for _, invalidation := range evaluation.Invalidations {
		if invalidation.Reason == reason {
			return true
		}
	}
	return false
}
