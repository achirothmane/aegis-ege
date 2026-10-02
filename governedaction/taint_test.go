package governedaction_test

import (
	"errors"
	"testing"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

func TestCheckTaintEgressCleanAndExplicitlyAllowed(t *testing.T) {
	admitted := ga.TaintEgressBinding{
		SubjectRef:    "process:p1",
		MonitorRef:    "monitor:synthetic-taintflow",
		MonitorEpoch:  "epoch-1",
		AllowedLabels: []string{"user.private"},
	}

	cases := []ga.TaintEvidence{
		{
			SubjectRef:   "process:p1",
			MonitorRef:   "monitor:synthetic-taintflow",
			MonitorEpoch: "epoch-1",
		},
		{
			SubjectRef:   "process:p1",
			MonitorRef:   "monitor:synthetic-taintflow",
			MonitorEpoch: "epoch-1",
			Labels:       []string{"user.private"},
		},
	}

	for _, observed := range cases {
		if err := ga.CheckTaintEgress(admitted, observed); err != nil {
			t.Fatalf("allowed taint rejected: %v", err)
		}
	}
}

func TestCheckTaintEgressRejectsUnboundTaintAndMonitorSubstitution(t *testing.T) {
	admitted := ga.TaintEgressBinding{
		SubjectRef:   "process:p1",
		MonitorRef:   "monitor:synthetic-taintflow",
		MonitorEpoch: "epoch-1",
	}

	tainted := ga.TaintEvidence{
		SubjectRef:   "process:p1",
		MonitorRef:   "monitor:synthetic-taintflow",
		MonitorEpoch: "epoch-1",
		Labels:       []string{"user.private"},
	}
	if err := ga.CheckTaintEgress(admitted, tainted); !errors.Is(err, ga.ErrTaintNotAuthorized) {
		t.Fatalf("error=%v; want taint not authorized", err)
	}

	substituted := tainted
	substituted.Labels = nil
	substituted.MonitorRef = "monitor:actor-self-report"
	if err := ga.CheckTaintEgress(admitted, substituted); !errors.Is(err, ga.ErrTaintBindingChanged) {
		t.Fatalf("error=%v; want monitor binding change", err)
	}

	substituted = tainted
	substituted.Labels = nil
	substituted.MonitorEpoch = "epoch-2"
	if err := ga.CheckTaintEgress(admitted, substituted); !errors.Is(err, ga.ErrTaintBindingChanged) {
		t.Fatalf("error=%v; want monitor epoch change", err)
	}
}

func TestCheckTaintEgressRejectsMalformedLabels(t *testing.T) {
	admitted := ga.TaintEgressBinding{
		SubjectRef:   "process:p1",
		MonitorRef:   "monitor:synthetic-taintflow",
		MonitorEpoch: "epoch-1",
	}
	observed := ga.TaintEvidence{
		SubjectRef:   "process:p1",
		MonitorRef:   "monitor:synthetic-taintflow",
		MonitorEpoch: "epoch-1",
		Labels:       []string{"user private"},
	}
	if err := ga.CheckTaintEgress(admitted, observed); !errors.Is(err, ga.ErrInvalidTaintLabel) {
		t.Fatalf("error=%v; want invalid taint label", err)
	}
}
