package kernelfabric

import (
	"errors"
	"fmt"
)

type TaintContinuityTracker struct {
	baselineLost uint64
	lastSequence uint64
	sequenceGaps uint64
}

func NewTaintContinuityTracker(initial TaintAccounting) (*TaintContinuityTracker, error) {
	if initial.Emitted+initial.Lost > initial.Sequence {
		return nil, fmt.Errorf(
			"invalid initial taint accounting: emitted=%d lost=%d sequence=%d",
			initial.Emitted,
			initial.Lost,
			initial.Sequence,
		)
	}
	return &TaintContinuityTracker{baselineLost: initial.Lost}, nil
}

func (t *TaintContinuityTracker) Observe(event TaintEvent) error {
	if t == nil {
		return errors.New("taint continuity tracker is nil")
	}
	if event.ABIVersion != TaintABIVersion || event.Sequence == 0 {
		return ErrEvidenceSequenceInvalid
	}
	if t.lastSequence != 0 {
		if event.Sequence <= t.lastSequence {
			return fmt.Errorf(
				"%w: non-monotonic taint sequence %d after %d",
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

func (t *TaintContinuityTracker) Assess(accounting TaintAccounting) (ContinuityAssessment, error) {
	if t == nil {
		return ContinuityAssessment{}, errors.New("taint continuity tracker is nil")
	}
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return ContinuityAssessment{}, fmt.Errorf(
			"invalid taint accounting: emitted=%d lost=%d sequence=%d",
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
			"%w: observed taint sequence %d exceeds kernel sequence %d",
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

func (t *TaintContinuityTracker) Checkpoint(accounting TaintAccounting) error {
	if t == nil {
		return errors.New("taint continuity tracker is nil")
	}
	if accounting.Lost < t.baselineLost {
		return ErrEvidenceCounterReset
	}
	t.baselineLost = accounting.Lost
	t.sequenceGaps = 0
	return nil
}
