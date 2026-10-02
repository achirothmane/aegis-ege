package kernelfabric

import "testing"

func TestTaintContinuityDetectsRingLossAndSequenceGap(t *testing.T) {
	tracker, err := NewTaintContinuityTracker(TaintAccounting{
		Sequence: 10,
		Emitted:  10,
		Lost:     0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(TaintEvent{
		Sequence:   11,
		EventType:  TaintEventSourceRead,
		Operation:  TaintOperationRead,
		ABIVersion: TaintABIVersion,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(TaintEvent{
		Sequence:   13,
		EventType:  TaintEventEgressDeny,
		Operation:  TaintOperationConnect,
		ABIVersion: TaintABIVersion,
	}); err != nil {
		t.Fatal(err)
	}

	assessment, err := tracker.Assess(TaintAccounting{
		Sequence: 13,
		Emitted:  12,
		Lost:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != EvidenceContinuityDegraded {
		t.Fatalf("status=%s want degraded", assessment.Status)
	}
	if assessment.SequenceGaps != 1 || assessment.LostSinceBaseline != 1 {
		t.Fatalf("assessment=%+v", assessment)
	}
	if len(assessment.ReasonCodes) != 2 {
		t.Fatalf("reason codes=%v", assessment.ReasonCodes)
	}
}

func TestTaintContinuityRejectsNonMonotonicSequence(t *testing.T) {
	tracker, err := NewTaintContinuityTracker(TaintAccounting{})
	if err != nil {
		t.Fatal(err)
	}
	event := TaintEvent{
		Sequence:   7,
		EventType:  TaintEventForkPropagation,
		Operation:  TaintOperationFork,
		ABIVersion: TaintABIVersion,
	}
	if err := tracker.Observe(event); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(event); err == nil {
		t.Fatal("duplicate taint sequence accepted")
	}
}
