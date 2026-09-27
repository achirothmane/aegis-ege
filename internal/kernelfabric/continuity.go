package kernelfabric

import (
	"errors"
	"fmt"
)

type EvidenceContinuityStatus string

const (
	EvidenceContinuityIntact   EvidenceContinuityStatus = "INTACT"
	EvidenceContinuityDegraded EvidenceContinuityStatus = "DEGRADED"
)

const (
	ContinuityReasonRingBufferLoss = "KERNEL_RINGBUF_OVERFLOW"
	ContinuityReasonSequenceGap    = "KERNEL_EVIDENCE_SEQUENCE_GAP"
)

var (
	ErrEvidenceSequenceInvalid = errors.New("kernel evidence sequence is invalid")
	ErrEvidenceCounterReset    = errors.New("kernel evidence accounting counter reset")
)

type ContinuityAssessment struct {
	Status             EvidenceContinuityStatus `json:"status"`
	LastSequence       uint64                   `json:"last_sequence"`
	KernelSequence     uint64                   `json:"kernel_sequence"`
	EmittedEvents      uint64                   `json:"emitted_events"`
	LostEventsTotal    uint64                   `json:"lost_events_total"`
	LostSinceBaseline  uint64                   `json:"lost_since_baseline"`
	SequenceGaps       uint64                   `json:"sequence_gaps"`
	ReasonCodes        []string                 `json:"reason_codes,omitempty"`
}

type ContinuityTracker struct {
	baselineLost uint64
	lastSequence uint64
	sequenceGaps uint64
}

func NewContinuityTracker(initial EvidenceAccounting) (*ContinuityTracker, error) {
	if initial.Emitted+initial.Lost > initial.Sequence {
		return nil, fmt.Errorf(
			"invalid initial evidence accounting: emitted=%d lost=%d sequence=%d",
			initial.Emitted,
			initial.Lost,
			initial.Sequence,
		)
	}
	return &ContinuityTracker{baselineLost: initial.Lost}, nil
}

func (t *ContinuityTracker) Observe(event EvidenceEvent) error {
	if t == nil {
		return errors.New("continuity tracker is nil")
	}
	if event.ABIVersion != EvidenceEventVersion ||
		event.EventType != EvidenceEventEnforcement ||
		event.Sequence == 0 {
		return ErrEvidenceSequenceInvalid
	}
	if t.lastSequence != 0 {
		if event.Sequence <= t.lastSequence {
			return fmt.Errorf(
				"%w: non-monotonic sequence %d after %d",
				ErrEvidenceSequenceInvalid,
				event.Sequence,
				t.lastSequence,
			)
		}
		if event.Sequence > t.lastSequence+1 {
			t.sequenceGaps += event.Sequence - t.lastSequence - 1
		}
	}
	t.lastSequence = event.Sequence
	return nil
}

func (t *ContinuityTracker) Assess(accounting EvidenceAccounting) (ContinuityAssessment, error) {
	if t == nil {
		return ContinuityAssessment{}, errors.New("continuity tracker is nil")
	}
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return ContinuityAssessment{}, fmt.Errorf(
			"invalid evidence accounting: emitted=%d lost=%d sequence=%d",
			accounting.Emitted,
			accounting.Lost,
			accounting.Sequence,
		)
	}
	if accounting.Lost < t.baselineLost {
		return ContinuityAssessment{}, ErrEvidenceCounterReset
	}
	if t.lastSequence > accounting.Sequence {
		return ContinuityAssessment{}, fmt.Errorf(
			"%w: observed sequence %d exceeds kernel sequence %d",
			ErrEvidenceSequenceInvalid,
			t.lastSequence,
			accounting.Sequence,
		)
	}

	assessment := ContinuityAssessment{
		Status:            EvidenceContinuityIntact,
		LastSequence:      t.lastSequence,
		KernelSequence:    accounting.Sequence,
		EmittedEvents:     accounting.Emitted,
		LostEventsTotal:   accounting.Lost,
		LostSinceBaseline: accounting.Lost - t.baselineLost,
		SequenceGaps:      t.sequenceGaps,
	}
	if assessment.LostSinceBaseline > 0 {
		assessment.Status = EvidenceContinuityDegraded
		assessment.ReasonCodes = append(assessment.ReasonCodes, ContinuityReasonRingBufferLoss)
	}
	if assessment.SequenceGaps > 0 {
		assessment.Status = EvidenceContinuityDegraded
		assessment.ReasonCodes = append(assessment.ReasonCodes, ContinuityReasonSequenceGap)
	}
	return assessment, nil
}

func (t *ContinuityTracker) Checkpoint(accounting EvidenceAccounting) error {
	if t == nil {
		return errors.New("continuity tracker is nil")
	}
	if accounting.Lost < t.baselineLost {
		return ErrEvidenceCounterReset
	}
	t.baselineLost = accounting.Lost
	t.sequenceGaps = 0
	return nil
}
