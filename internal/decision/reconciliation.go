package decision

import "context"

// ReconcileContradiction starts a fresh evidence epoch when the current
// request is blocked by contradictory evidence. Historical conflicting
// observations remain available in Initial, but they are never "outvoted".
// Authorization is possible only if a bounded set of fresh READ_ONLY probes
// independently reacquire enough non-contradictory evidence.
func ReconcileContradiction(
	ctx context.Context,
	req Request,
	probes []EvidenceProbe,
	maxAttempts int,
) AcquisitionResult {
	initial := Evaluate(req)
	result := AcquisitionResult{
		Initial: initial,
		Final:   initial,
	}

	if !isContradicted(initial) || maxAttempts <= 0 {
		result.EffectiveRequest = cloneRequest(req)
		return result
	}

	fresh := cloneRequest(req)
	fresh.Evidence = nil
	result.EffectiveRequest = fresh
	result.Final = Evaluate(fresh)

	attempts := 0
	for _, probe := range probes {
		if probe == nil {
			continue
		}

		attempt := ProbeAttempt{
			ProbeName:   probe.Name(),
			SafetyClass: probe.SafetyClass(),
		}

		if probe.SafetyClass() != ProbeReadOnly {
			attempt.Skipped = true
			attempt.Error = "probe safety class is not READ_ONLY"
			result.Attempts = append(result.Attempts, attempt)
			continue
		}
		if !probe.Supports(result.EffectiveRequest, result.Final) {
			attempt.Skipped = true
			result.Attempts = append(result.Attempts, attempt)
			continue
		}
		if attempts >= maxAttempts {
			break
		}
		attempts++

		outcome, err := probe.Acquire(ctx, result.EffectiveRequest)
		if err != nil {
			attempt.Error = err.Error()
			result.Attempts = append(result.Attempts, attempt)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if err := validateProbeOutcome(outcome); err != nil {
			attempt.Error = err.Error()
			result.Attempts = append(result.Attempts, attempt)
			continue
		}

		attempt.ObservationCount = len(outcome.Evidence)
		attempt.ResourceVersion = outcome.ResourceVersion
		result.Attempts = append(result.Attempts, attempt)

		if len(outcome.Evidence) == 0 && outcome.ResourceVersion == "" {
			continue
		}

		result.EffectiveRequest.Evidence = append(
			result.EffectiveRequest.Evidence,
			outcome.Evidence...,
		)
		if outcome.ResourceVersion != "" {
			result.EffectiveRequest.ResourceVersion = outcome.ResourceVersion
		}
		result.EffectiveRequest.RequestedAt = latestObservationTime(
			result.EffectiveRequest.RequestedAt,
			outcome.Evidence,
		)

		result.Final = Evaluate(result.EffectiveRequest)
		if result.Final.Decision == Allow || result.Final.Decision == Block {
			return result
		}
	}

	return result
}

func isContradicted(result Result) bool {
	if result.Decision != Block {
		return false
	}
	for _, reason := range result.ReasonCodes {
		if reason == EvidenceContradicted {
			return true
		}
	}
	return false
}
