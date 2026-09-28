package kernelfabric

import (
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/easl"

	"github.com/achirothmane/aegis-ege/internal/easlruntime"
)

func testEvidenceEvent(sequence uint64) EvidenceEvent {
	return EvidenceEvent{
		Sequence:         sequence,
		ObservedAtMonoNS: 1000 + sequence,
		CgroupID:         42,
		AuthorityTerm:    7,
		DecisionEpoch:    31,
		RevocationEpoch:  4,
		ActionClass:      ActionClassNetworkConnect,
		Verdict:          EvidenceVerdictAllow,
		Reason:           uint32(DenyNone),
		AddressFamily:    AddressFamilyIPv4,
		DestinationPort:  443,
		Protocol:         6,
		ABIVersion:       EvidenceEventVersion,
		EventType:        EvidenceEventEnforcement,
	}
}

func TestEvidenceEventABIRoundTrip(t *testing.T) {
	event := testEvidenceEvent(11)
	event.DecisionIDHash[0] = 0xaa
	event.DestinationAddr[0] = 203
	event.DestinationAddr[1] = 0
	event.DestinationAddr[2] = 113
	event.DestinationAddr[3] = 10

	payload, err := MarshalEvidenceEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != EvidenceEventSize {
		t.Fatalf("event size=%d want=%d", len(payload), EvidenceEventSize)
	}
	decoded, err := DecodeEvidenceEvent(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != event {
		t.Fatalf("decoded event mismatch:\n got=%+v\nwant=%+v", decoded, event)
	}
}

func TestEvidenceAccountingABIRoundTrip(t *testing.T) {
	accounting := EvidenceAccounting{Sequence: 12, Emitted: 10, Lost: 2}
	payload, err := MarshalEvidenceAccounting(accounting)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != EvidenceAccountingSize {
		t.Fatalf("accounting size=%d want=%d", len(payload), EvidenceAccountingSize)
	}
	decoded, err := DecodeEvidenceAccounting(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != accounting {
		t.Fatalf("decoded accounting=%+v want=%+v", decoded, accounting)
	}
}

func TestContinuityTrackerDetectsSequenceGap(t *testing.T) {
	tracker, err := NewContinuityTracker(EvidenceAccounting{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(testEvidenceEvent(5)); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(testEvidenceEvent(7)); err != nil {
		t.Fatal(err)
	}
	assessment, err := tracker.Assess(EvidenceAccounting{
		Sequence: 7,
		Emitted:  7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != EvidenceContinuityDegraded {
		t.Fatalf("expected DEGRADED, got %+v", assessment)
	}
	if assessment.SequenceGaps != 1 {
		t.Fatalf("sequence gaps=%d want=1", assessment.SequenceGaps)
	}
	if len(assessment.ReasonCodes) != 1 ||
		assessment.ReasonCodes[0] != ContinuityReasonSequenceGap {
		t.Fatalf("unexpected reasons: %v", assessment.ReasonCodes)
	}
}

func TestContinuityTrackerDetectsTrailingRingBufferLossWithoutGap(t *testing.T) {
	tracker, err := NewContinuityTracker(EvidenceAccounting{
		Sequence: 100,
		Emitted:  100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(testEvidenceEvent(101)); err != nil {
		t.Fatal(err)
	}

	assessment, err := tracker.Assess(EvidenceAccounting{
		Sequence: 103,
		Emitted:  101,
		Lost:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != EvidenceContinuityDegraded ||
		assessment.LostSinceBaseline != 2 ||
		assessment.SequenceGaps != 0 {
		t.Fatalf("unexpected assessment: %+v", assessment)
	}
	if len(assessment.ReasonCodes) != 1 ||
		assessment.ReasonCodes[0] != ContinuityReasonRingBufferLoss {
		t.Fatalf("unexpected reasons: %v", assessment.ReasonCodes)
	}
}

func TestContinuityCheckpointStartsNewLossWindow(t *testing.T) {
	tracker, err := NewContinuityTracker(EvidenceAccounting{})
	if err != nil {
		t.Fatal(err)
	}
	accounting := EvidenceAccounting{Sequence: 4, Emitted: 3, Lost: 1}
	if _, err := tracker.Assess(accounting); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Checkpoint(accounting); err != nil {
		t.Fatal(err)
	}
	assessment, err := tracker.Assess(accounting)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != EvidenceContinuityIntact ||
		assessment.LostSinceBaseline != 0 ||
		assessment.SequenceGaps != 0 {
		t.Fatalf("checkpoint did not reset continuity window: %+v", assessment)
	}
}

func TestContinuityTrackerRejectsCounterReset(t *testing.T) {
	tracker, err := NewContinuityTracker(EvidenceAccounting{
		Sequence: 10,
		Emitted:  8,
		Lost:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tracker.Assess(EvidenceAccounting{
		Sequence: 11,
		Emitted:  10,
		Lost:     1,
	})
	if !errors.Is(err, ErrEvidenceCounterReset) {
		t.Fatalf("expected counter reset, got %v", err)
	}
}

func TestDegradedContinuityBecomesEASLContradiction(t *testing.T) {
	observedAt := time.Date(2026, 9, 27, 21, 0, 0, 0, time.UTC)
	assessment := ContinuityAssessment{
		Status:            EvidenceContinuityDegraded,
		LostSinceBaseline: 3,
		ReasonCodes:       []string{ContinuityReasonRingBufferLoss},
	}
	evidence, err := assessment.ToEASLEvidence(
		easl.EvidenceID("kernel-continuity-1"),
		easl.AssumptionID("kernel-evidence-continuity"),
		observedAt,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Contradicts) != 1 ||
		evidence.Contradicts[0] != easl.AssumptionID("kernel-evidence-continuity") {
		t.Fatalf("degraded continuity did not contradict EASL assumption: %+v", evidence)
	}

	evaluation, err := easlruntime.Evaluate(easl.Snapshot{
		At:       observedAt.Add(time.Second),
		Evidence: []easl.Evidence{evidence},
		Assumptions: []easl.Assumption{{
			ID:       easl.AssumptionID("kernel-evidence-continuity"),
			Requires: []easl.EvidenceID{evidence.ID},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.State != easl.StateInvalid ||
		evaluation.EvidenceStatus != easl.EvidenceContradictory {
		t.Fatalf("unexpected EASL evaluation: %+v", evaluation)
	}
}

func TestIntactContinuityProducesNonContradictoryEASLEvidence(t *testing.T) {
	observedAt := time.Date(2026, 9, 27, 21, 0, 0, 0, time.UTC)
	assessment := ContinuityAssessment{Status: EvidenceContinuityIntact}
	evidence, err := assessment.ToEASLEvidence(
		easl.EvidenceID("kernel-continuity-2"),
		easl.AssumptionID("kernel-evidence-continuity"),
		observedAt,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Contradicts) != 0 {
		t.Fatalf("intact continuity unexpectedly contradicts: %+v", evidence)
	}
}
