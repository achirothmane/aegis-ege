package decision

import (
	"context"
	"fmt"
	"time"
)

type ProbeSafetyClass string

const (
	ProbeReadOnly ProbeSafetyClass = "READ_ONLY"
)

type ProbeOutcome struct {
	Evidence        []EvidenceObservation
	ResourceVersion string
}

type EvidenceProbe interface {
	Name() string
	SafetyClass() ProbeSafetyClass
	Supports(Request, Result) bool
	Acquire(context.Context, Request) (ProbeOutcome, error)
}

type ProbeAttempt struct {
	ProbeName        string
	SafetyClass      ProbeSafetyClass
	ObservationCount int
	ResourceVersion  string
	Error            string
	Skipped          bool
}

type AcquisitionResult struct {
	Initial          Result
	Final            Result
	EffectiveRequest Request
	Attempts         []ProbeAttempt
}

func ResolveUnknown(
	ctx context.Context,
	req Request,
	probes []EvidenceProbe,
	maxAttempts int,
) AcquisitionResult {
	initial := Evaluate(req)
	result := AcquisitionResult{
		Initial:          initial,
		Final:            initial,
		EffectiveRequest: cloneRequest(req),
	}

	if !needsEvidence(initial) || maxAttempts <= 0 {
		return result
	}

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
		if !needsEvidence(result.Final) {
			return result
		}
	}

	return result
}

func needsEvidence(result Result) bool {
	if result.Decision != Escalate {
		return false
	}
	for _, reason := range result.ReasonCodes {
		if reason == InsufficientEvidence {
			return true
		}
	}
	return false
}

func latestObservationTime(current time.Time, evidence []EvidenceObservation) time.Time {
	latest := current
	for _, observation := range evidence {
		if observation.ObservedAt.After(latest) {
			latest = observation.ObservedAt
		}
	}
	return latest
}

func cloneRequest(req Request) Request {
	cloned := req
	cloned.Evidence = append([]EvidenceObservation(nil), req.Evidence...)
	return cloned
}

func validateProbeOutcome(outcome ProbeOutcome) error {
	for i, observation := range outcome.Evidence {
		if observation.Claim == "" {
			return fmt.Errorf("probe observation %d has empty claim", i)
		}
		if observation.Source == "" {
			return fmt.Errorf("probe observation %d has empty source", i)
		}
		if observation.ObservedAt.IsZero() {
			return fmt.Errorf("probe observation %d has zero observed time", i)
		}
	}
	return nil
}
