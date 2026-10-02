package kernelfabric

import (
	"errors"
	"reflect"
	"testing"
)

func TestTaintEventABIRoundTrip(t *testing.T) {
	event := TaintEvent{
		Sequence:         9,
		ObservedAtMonoNS: 1234567,
		CgroupID:         77,
		FileDevice:       8,
		FileInode:        99,
		Labels:           0b101,
		TGID:             4242,
		RelatedTGID:      4343,
		EventType:        TaintEventForkPropagation,
		Operation:        TaintOperationFork,
		ABIVersion:       TaintABIVersion,
	}
	payload, err := marshalFixed(event, TaintEventSize)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTaintEvent(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != event {
		t.Fatalf("decoded=%+v want=%+v", decoded, event)
	}
}

func TestTaintAccountingABIRoundTrip(t *testing.T) {
	accounting := TaintAccounting{Sequence: 12, Emitted: 10, Lost: 2}
	payload, err := MarshalTaintAccounting(accounting)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTaintAccounting(payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != accounting {
		t.Fatalf("decoded=%+v want=%+v", decoded, accounting)
	}
}

func TestDecodeTaintLabelsFailsClosedOnUnknownBit(t *testing.T) {
	_, err := DecodeTaintLabels(1<<7, map[uint8]string{0: "user.private"})
	if !errors.Is(err, ErrTaintLabelUnmapped) {
		t.Fatalf("error=%v; want unmapped bit", err)
	}
}

func TestDecodeTaintLabelsUsesProfileOwnedMeanings(t *testing.T) {
	labels, err := DecodeTaintLabels(
		(1<<0)|(1<<3),
		map[uint8]string{
			0: "user.private",
			3: "tenant.secret",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tenant.secret", "user.private"}
	if !reflect.DeepEqual(labels, want) {
		t.Fatalf("labels=%v want=%v", labels, want)
	}
}

func TestBuildTaintEvidenceRequiresTrustedSubjectProvenance(t *testing.T) {
	if _, err := BuildTaintEvidence("", "monitor:bpf-lsm", "epoch-1", 1, map[uint8]string{0: "user.private"}); err == nil {
		t.Fatal("missing trusted subject_ref accepted")
	}

	evidence, err := BuildTaintEvidence(
		"linux-process:boot=abc;start=101;exe=11:22;cgroup=77",
		"monitor:bpf-lsm",
		"epoch-1",
		1,
		map[uint8]string{0: "user.private"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(evidence.Labels, []string{"user.private"}) {
		t.Fatalf("evidence labels=%v", evidence.Labels)
	}
}

func TestTaintEventDecoderRejectsReservedAndInvalidValues(t *testing.T) {
	base := TaintEvent{
		Sequence:   1,
		CgroupID:   77,
		TGID:       4242,
		EventType:  TaintEventSourceRead,
		Operation:  TaintOperationRead,
		ABIVersion: TaintABIVersion,
	}
	cases := []TaintEvent{
		func() TaintEvent { v := base; v.Reserved = 1; return v }(),
		func() TaintEvent { v := base; v.ABIVersion = 99; return v }(),
		func() TaintEvent { v := base; v.EventType = 99; return v }(),
		func() TaintEvent { v := base; v.Operation = 99; return v }(),
	}
	for _, event := range cases {
		payload, err := marshalFixed(event, TaintEventSize)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeTaintEvent(payload); !errors.Is(err, ErrTaintABIInvalid) {
			t.Fatalf("event=%+v error=%v; want invalid ABI", event, err)
		}
	}
}
