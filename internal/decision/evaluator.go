package decision

// Evaluate applies hard evidence gates before any aggregate scoring.
//
// v0.1 begins with freshness as a non-compensable predicate: if any required
// observation is older than MaxEvidenceAge, the action cannot be ALLOW.
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

	return Result{Decision: Allow}
}
