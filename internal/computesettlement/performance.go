package computesettlement

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

// PerformanceEnvelope defines one measurable quality dimension for a contracted
// compute execution. Metric names and units are adapter-owned strings so the
// settlement layer can govern bandwidth, goodput, tokens/sec, or another
// measurable quantity without teaching the governance kernel those semantics.
type PerformanceEnvelope struct {
	Metric                  string
	Unit                    string
	MinimumValue            uint64
	MaxGap                  time.Duration
	MaxBelowFloorDuration   time.Duration
}

type PerformanceSample struct {
	Sequence uint64    `json:"sequence"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Metric   string    `json:"metric"`
	Unit     string    `json:"unit"`
	Value    uint64    `json:"value"`
}

type PerformanceStream struct {
	Source         string              `json:"source"`
	EvidenceDigest string              `json:"evidence_digest"`
	Samples        []PerformanceSample `json:"samples"`
}

type PerformanceStreamAssessment struct {
	Source               string
	MinimumObservedValue uint64
	BelowFloorDuration   time.Duration
	Start                time.Time
	End                  time.Time
	SampleCount          int
	Compliant            bool
}

type PerformanceExecutionReconciliation struct {
	MeteredExecutionReconciliation
	PerformanceEstablished bool
	PerformanceAssessments []PerformanceStreamAssessment
}

// ReconcilePerformanceExecution composes VCS-05 on top of the already proven
// VCS-04 metering, VCS-03 hardware continuity, and VCS-02 evidence binding.
//
// A prior non-SETTLED disposition is never upgraded by performance evidence.
// Performance can only preserve SETTLED, downgrade to CREDIT_DUE or DISPUTED,
// or return UNKNOWN when the performance evidence itself lacks continuity.
func ReconcilePerformanceExecution(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	lease HardwareLeaseBinding,
	receipt ComputeExecutionReceipt,
	admission SignedHardwareIdentityAttestation,
	completion SignedHardwareIdentityAttestation,
	hardwarePolicy HardwareContinuityPolicy,
	actionID string,
	planDigest string,
	contractFacts map[string]string,
	observations []Observation,
	sources []egeproto.EvidenceSource,
	evidenceRequirement EvidenceRequirement,
	meteringRequirement MeteringRequirement,
	meterStreams []MeterStream,
	envelope PerformanceEnvelope,
	performanceStreams []PerformanceStream,
) PerformanceExecutionReconciliation {
	base := ReconcileMeteredExecution(
		ctx,
		verifier,
		lease,
		receipt,
		admission,
		completion,
		hardwarePolicy,
		actionID,
		planDigest,
		contractFacts,
		observations,
		sources,
		evidenceRequirement,
		meteringRequirement,
		meterStreams,
	)
	result := PerformanceExecutionReconciliation{
		MeteredExecutionReconciliation: base,
	}

	if base.Disposition != Settled {
		return result
	}
	if !base.MeteringEstablished {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "performance continuity: prerequisite metering is not established",
		}
		return result
	}

	fail := func(detail string) PerformanceExecutionReconciliation {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "performance continuity: " + detail,
		}
		result.PerformanceEstablished = false
		return result
	}

	if err := validatePerformanceEnvelope(envelope); err != nil {
		return fail(err.Error())
	}
	if len(performanceStreams) < 2 {
		return fail("at least two performance streams are required")
	}

	evidenceBySource := make(map[string]Observation, len(observations))
	for _, observation := range observations {
		evidenceBySource[observation.Source] = observation
	}

	assessments := make([]PerformanceStreamAssessment, 0, len(performanceStreams))
	seenSources := make(map[string]struct{}, len(performanceStreams))
	for _, stream := range performanceStreams {
		name := strings.TrimSpace(stream.Source)
		if name == "" || strings.TrimSpace(stream.EvidenceDigest) == "" {
			return fail("performance stream has incomplete provenance")
		}
		if _, duplicate := seenSources[name]; duplicate {
			return fail("performance stream source is duplicated")
		}
		seenSources[name] = struct{}{}

		observation, ok := evidenceBySource[name]
		if !ok || observation.EvidenceDigest != stream.EvidenceDigest {
			return fail("performance stream is not bound to assessed independent evidence")
		}

		assessment, err := assessPerformanceStream(
			stream,
			lease,
			receipt,
			envelope,
		)
		if err != nil {
			return fail(err.Error())
		}
		assessments = append(assessments, assessment)
	}
	result.PerformanceAssessments = assessments
	result.PerformanceEstablished = true

	compliant := 0
	for _, assessment := range assessments {
		if assessment.Compliant {
			compliant++
		}
	}

	switch {
	case compliant == len(assessments):
		return result
	case compliant > 0:
		result.Reconciliation = Reconciliation{
			Disposition: Disputed,
			Detail:      "performance sources disagree on contract compliance",
		}
		return result
	default:
		if performanceDegradationAgrees(assessments) {
			result.Reconciliation = Reconciliation{
				Disposition: CreditDue,
				Detail: fmt.Sprintf(
					"performance sources agree on under-delivery: metric=%s below_floor=%s",
					envelope.Metric,
					assessments[0].BelowFloorDuration,
				),
			}
			return result
		}
		result.Reconciliation = Reconciliation{
			Disposition: Disputed,
			Detail:      "performance sources agree that the contract failed but disagree on degradation extent",
		}
		return result
	}
}

func assessPerformanceStream(
	stream PerformanceStream,
	lease HardwareLeaseBinding,
	receipt ComputeExecutionReceipt,
	envelope PerformanceEnvelope,
) (PerformanceStreamAssessment, error) {
	if len(stream.Samples) == 0 {
		return PerformanceStreamAssessment{}, errors.New("performance stream is empty")
	}

	samples := append([]PerformanceSample(nil), stream.Samples...)
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Start.Equal(samples[j].Start) {
			return samples[i].Sequence < samples[j].Sequence
		}
		return samples[i].Start.Before(samples[j].Start)
	})

	var previousSequence uint64
	var previousEnd time.Time
	var belowFloor time.Duration
	minimum := ^uint64(0)

	for i, sample := range samples {
		if sample.Sequence == 0 ||
			sample.Start.IsZero() ||
			sample.End.IsZero() ||
			!sample.Start.Before(sample.End) {
			return PerformanceStreamAssessment{}, errors.New("performance sample is incomplete")
		}
		if strings.TrimSpace(sample.Metric) != envelope.Metric ||
			strings.TrimSpace(sample.Unit) != envelope.Unit {
			return PerformanceStreamAssessment{}, errors.New("performance sample metric or unit does not match contract envelope")
		}
		if sample.Start.Before(lease.StartsAt) || sample.End.After(lease.EndsAt) {
			return PerformanceStreamAssessment{}, errors.New("performance sample falls outside admitted lease")
		}
		if sample.Start.Before(receipt.StartedAt) || sample.End.After(receipt.FinishedAt) {
			return PerformanceStreamAssessment{}, errors.New("performance sample falls outside execution receipt interval")
		}

		if i == 0 {
			if sample.Start.After(receipt.StartedAt) &&
				sample.Start.Sub(receipt.StartedAt) > envelope.MaxGap {
				return PerformanceStreamAssessment{}, errors.New("performance stream has uncovered execution prefix")
			}
		} else {
			if sample.Sequence <= previousSequence {
				return PerformanceStreamAssessment{}, errors.New("performance sequence is non-monotonic or duplicated")
			}
			if sample.Sequence != previousSequence+1 {
				return PerformanceStreamAssessment{}, errors.New("performance sequence gap detected")
			}
			if sample.Start.Before(previousEnd) {
				return PerformanceStreamAssessment{}, errors.New("performance intervals overlap or duplicate observation")
			}
			if sample.Start.After(previousEnd) &&
				sample.Start.Sub(previousEnd) > envelope.MaxGap {
				return PerformanceStreamAssessment{}, errors.New("performance stream has an uncovered interval")
			}
		}

		if sample.Value < minimum {
			minimum = sample.Value
		}
		if sample.Value < envelope.MinimumValue {
			belowFloor += sample.End.Sub(sample.Start)
		}

		previousSequence = sample.Sequence
		previousEnd = sample.End
	}

	if previousEnd.Before(receipt.FinishedAt) &&
		receipt.FinishedAt.Sub(previousEnd) > envelope.MaxGap {
		return PerformanceStreamAssessment{}, errors.New("performance stream has uncovered execution suffix")
	}

	return PerformanceStreamAssessment{
		Source:               stream.Source,
		MinimumObservedValue: minimum,
		BelowFloorDuration:   belowFloor,
		Start:                samples[0].Start,
		End:                  previousEnd,
		SampleCount:          len(samples),
		Compliant:            belowFloor <= envelope.MaxBelowFloorDuration,
	}, nil
}

func validatePerformanceEnvelope(envelope PerformanceEnvelope) error {
	if strings.TrimSpace(envelope.Metric) == "" ||
		strings.TrimSpace(envelope.Unit) == "" ||
		envelope.MinimumValue == 0 {
		return errors.New("performance envelope is incomplete")
	}
	if envelope.MaxGap < 0 || envelope.MaxBelowFloorDuration < 0 {
		return errors.New("performance envelope durations must not be negative")
	}
	return nil
}

func performanceDegradationAgrees(assessments []PerformanceStreamAssessment) bool {
	if len(assessments) < 2 {
		return true
	}
	duration := assessments[0].BelowFloorDuration
	for _, assessment := range assessments[1:] {
		if assessment.BelowFloorDuration != duration {
			return false
		}
	}
	return true
}
