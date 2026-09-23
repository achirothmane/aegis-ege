package decision

// Evaluate applies hard evidence gates before any aggregate scoring.
//
// v0.1 currently enforces:
//  1. required evidence must still be fresh;
//  2. fresh observations about the same operational fact must not contradict;
//  3. the configured number of distinct evidence sources must be present.
//
// Later versions will make the observed claim explicit. In the current v0.1
// contract, all observations in Request.Evidence are treated as observations
// of the same required fact.
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

	if len(req.Evidence) > 1 {
		expected := req.Evidence[0].Value
		for _, observation := range req.Evidence[1:] {
			if observation.Value != expected {
				return Result{
					Decision:    Block,
					ReasonCodes: []ReasonCode{EvidenceContradicted},
				}
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
