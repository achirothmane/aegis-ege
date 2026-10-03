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

type MeterSlice struct {
	Sequence            uint64    `json:"sequence"`
	Start               time.Time `json:"start"`
	End                 time.Time `json:"end"`
	GPUCount            uint32    `json:"gpu_count"`
	CounterStartSeconds uint64    `json:"counter_start_seconds"`
	CounterEndSeconds   uint64    `json:"counter_end_seconds"`
}

type MeterStream struct {
	Source         string       `json:"source"`
	EvidenceDigest string       `json:"evidence_digest"`
	Slices         []MeterSlice `json:"slices"`
}

type MeteringRequirement struct {
	ExpectedGPUSeconds uint64
	RequiredGPUCount   uint32
	MaxGap             time.Duration
}

type MeterStreamAssessment struct {
	Source              string
	DeliveredGPUSeconds uint64
	Start               time.Time
	End                 time.Time
	SliceCount          int
}

type MeteredExecutionReconciliation struct {
	AttestedEvidenceReconciliation
	MeteringEstablished bool
	MeteringAssessments []MeterStreamAssessment
}

func ReconcileMeteredExecution(
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
	streams []MeterStream,
) MeteredExecutionReconciliation {
	base := ReconcileAttestedExecution(
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
	)
	result := MeteredExecutionReconciliation{
		AttestedEvidenceReconciliation: base,
	}
	fail := func(detail string) MeteredExecutionReconciliation {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "metering continuity: " + detail,
		}
		result.MeteringEstablished = false
		return result
	}

	if base.Disposition != Settled || !base.HardwareContinuityEstablished {
		return fail("prerequisite attested execution is not settled")
	}
	if meteringRequirement.ExpectedGPUSeconds == 0 ||
		meteringRequirement.RequiredGPUCount == 0 {
		return fail("metering requirement is incomplete")
	}
	if len(streams) < 2 {
		return fail("at least two metering streams are required")
	}

	evidenceBySource := make(map[string]Observation, len(observations))
	for _, observation := range observations {
		evidenceBySource[observation.Source] = observation
	}

	assessments := make([]MeterStreamAssessment, 0, len(streams))
	seenSources := make(map[string]struct{}, len(streams))
	for _, stream := range streams {
		name := strings.TrimSpace(stream.Source)
		if name == "" || strings.TrimSpace(stream.EvidenceDigest) == "" {
			return fail("meter stream has incomplete provenance")
		}
		if _, duplicate := seenSources[name]; duplicate {
			return fail("meter stream source is duplicated")
		}
		seenSources[name] = struct{}{}

		observation, ok := evidenceBySource[name]
		if !ok || observation.EvidenceDigest != stream.EvidenceDigest {
			return fail("meter stream is not bound to assessed independent evidence")
		}

		assessment, err := assessMeterStream(
			stream,
			lease,
			receipt,
			meteringRequirement,
		)
		if err != nil {
			return fail(err.Error())
		}
		assessments = append(assessments, assessment)
	}
	result.MeteringAssessments = assessments

	reference := assessments[0].DeliveredGPUSeconds
	for _, assessment := range assessments[1:] {
		if assessment.DeliveredGPUSeconds != reference {
			result.Reconciliation = Reconciliation{
				Disposition: Disputed,
				Detail: fmt.Sprintf(
					"metering sources disagree on delivered GPU-seconds: %d vs %d",
					reference,
					assessment.DeliveredGPUSeconds,
				),
			}
			result.MeteringEstablished = true
			return result
		}
	}

	result.MeteringEstablished = true
	switch {
	case reference == meteringRequirement.ExpectedGPUSeconds:
		return result
	case reference < meteringRequirement.ExpectedGPUSeconds:
		result.Reconciliation = Reconciliation{
			Disposition: CreditDue,
			Detail: fmt.Sprintf(
				"metering sources agree on under-delivery: delivered=%d expected=%d GPU-seconds",
				reference,
				meteringRequirement.ExpectedGPUSeconds,
			),
		}
		return result
	default:
		result.Reconciliation = Reconciliation{
			Disposition: Disputed,
			Detail: fmt.Sprintf(
				"metering sources agree on over-metering: delivered=%d expected=%d GPU-seconds",
				reference,
				meteringRequirement.ExpectedGPUSeconds,
			),
		}
		return result
	}
}

func assessMeterStream(
	stream MeterStream,
	lease HardwareLeaseBinding,
	receipt ComputeExecutionReceipt,
	requirement MeteringRequirement,
) (MeterStreamAssessment, error) {
	if len(stream.Slices) == 0 {
		return MeterStreamAssessment{}, errors.New("meter stream is empty")
	}
	slices := append([]MeterSlice(nil), stream.Slices...)
	sort.Slice(slices, func(i, j int) bool {
		if slices[i].Start.Equal(slices[j].Start) {
			return slices[i].Sequence < slices[j].Sequence
		}
		return slices[i].Start.Before(slices[j].Start)
	})

	var delivered uint64
	var previousSequence uint64
	var previousEnd time.Time
	var previousCounter uint64

	for i, slice := range slices {
		if slice.Sequence == 0 || slice.Start.IsZero() || slice.End.IsZero() ||
			!slice.Start.Before(slice.End) || slice.GPUCount == 0 {
			return MeterStreamAssessment{}, errors.New("meter slice is incomplete")
		}
		if slice.GPUCount > requirement.RequiredGPUCount {
			return MeterStreamAssessment{}, fmt.Errorf(
				"meter slice GPU count %d exceeds contracted count %d",
				slice.GPUCount,
				requirement.RequiredGPUCount,
			)
		}
		if slice.Start.Before(lease.StartsAt) || slice.End.After(lease.EndsAt) {
			return MeterStreamAssessment{}, errors.New("meter slice falls outside admitted lease")
		}
		if slice.Start.Before(receipt.StartedAt) || slice.End.After(receipt.FinishedAt) {
			return MeterStreamAssessment{}, errors.New("meter slice falls outside execution receipt interval")
		}
		if i == 0 {
			if slice.Start.After(receipt.StartedAt) &&
				slice.Start.Sub(receipt.StartedAt) > requirement.MaxGap {
				return MeterStreamAssessment{}, errors.New("meter stream has uncovered execution prefix")
			}
		} else {
			if slice.Sequence <= previousSequence {
				return MeterStreamAssessment{}, errors.New("meter sequence is non-monotonic or duplicated")
			}
			if slice.Sequence != previousSequence+1 {
				return MeterStreamAssessment{}, errors.New("meter sequence gap detected")
			}
			if slice.Start.Before(previousEnd) {
				return MeterStreamAssessment{}, errors.New("meter intervals overlap or duplicate delivery")
			}
			if slice.Start.After(previousEnd) &&
				slice.Start.Sub(previousEnd) > requirement.MaxGap {
				return MeterStreamAssessment{}, errors.New("meter stream has an uncovered interval")
			}
			if slice.CounterStartSeconds < previousCounter {
				return MeterStreamAssessment{}, errors.New("meter cumulative counter reset detected")
			}
			if slice.CounterStartSeconds != previousCounter {
				return MeterStreamAssessment{}, errors.New("meter cumulative counter discontinuity detected")
			}
		}

		duration := slice.End.Sub(slice.Start)
		if duration%time.Second != 0 {
			return MeterStreamAssessment{}, errors.New("meter slice duration is not whole-second bounded")
		}
		expectedDelta := uint64(duration/time.Second) * uint64(slice.GPUCount)
		if slice.CounterEndSeconds < slice.CounterStartSeconds {
			return MeterStreamAssessment{}, errors.New("meter counter decreased inside slice")
		}
		actualDelta := slice.CounterEndSeconds - slice.CounterStartSeconds
		if actualDelta != expectedDelta {
			return MeterStreamAssessment{}, fmt.Errorf(
				"meter counter delta mismatch: got=%d want=%d",
				actualDelta,
				expectedDelta,
			)
		}

		delivered += actualDelta
		previousSequence = slice.Sequence
		previousEnd = slice.End
		previousCounter = slice.CounterEndSeconds
	}

	if previousEnd.Before(receipt.FinishedAt) &&
		receipt.FinishedAt.Sub(previousEnd) > requirement.MaxGap {
		return MeterStreamAssessment{}, errors.New("meter stream has uncovered execution suffix")
	}

	return MeterStreamAssessment{
		Source:              stream.Source,
		DeliveredGPUSeconds: delivered,
		Start:               slices[0].Start,
		End:                 previousEnd,
		SliceCount:          len(slices),
	}, nil
}
