package decision

// Evaluate applies hard evidence gates before any aggregate scoring.
//
// v0.1 currently enforces:
//  1. required evidence must still be fresh;
//  2. fresh observations of the same claim must not contradict;
//  3. action blast radius must stay within the configured hard limit;
//  4. the configured number of distinct evidence sources must be present.
func Evaluate(req Request) Result {
	for _, observation := range req.Evidence {
		age := req.RequestedAt.Sub(observation.ObservedAt)
		if age > req.MaxEvidenceAge {
			return Result{
				Decision:    Block,
				ReasonCodes: []ReasonCode{EvidenceStale},
			}
		}
	}

	valuesByClaim := make(map[string]string)
	for _, observation := range req.Evidence {
		expected, seen := valuesByClaim[observation.Claim]
		if !seen {
			valuesByClaim[observation.Claim] = observation.Value
			continue
		}
		if observation.Value != expected {
			return Result{
				Decision:    Block,
				ReasonCodes: []ReasonCode{EvidenceContradicted},
			}
		}
	}

	if req.MaxBlastRadius > 0 && req.BlastRadius > req.MaxBlastRadius {
		return Result{
			Decision:    Block,
			ReasonCodes: []ReasonCode{BlastRadiusExceeded},
		}
	}

	if req.RequiredSourceCount > 0 {
		sources := make(map[string]struct{}, len(req.Evidence))
		for _, observation := range req.Evidence {
			if observation.Source != "" {
				sources[observation.Source] = struct{}{}
			}
		}
		if len(sources) < req.RequiredSourceCount {
			return Result{
				Decision:    Escalate,
				ReasonCodes: []ReasonCode{InsufficientEvidence},
			}
		}
	}

	return Result{Decision: Allow}
}
