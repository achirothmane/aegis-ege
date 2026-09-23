package decision

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeProbe struct {
	name       string
	safety     ProbeSafetyClass
	supports   bool
	outcome    ProbeOutcome
	err        error
	acquisitions int
}

func (p *fakeProbe) Name() string { return p.name }
func (p *fakeProbe) SafetyClass() ProbeSafetyClass { return p.safety }
func (p *fakeProbe) Supports(Request, Result) bool { return p.supports }
func (p *fakeProbe) Acquire(context.Context, Request) (ProbeOutcome, error) {
	p.acquisitions++
	return p.outcome, p.err
}

func TestResolveUnknownAcquiresReadOnlyEvidenceAndAllows(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 30, 0, 0, time.UTC)
	req := acquisitionRequest(now)

	probe := &fakeProbe{
		name:     "live-node-health",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{
			ResourceVersion: "101",
			Evidence: []EvidenceObservation{{
				Claim:      "node_health",
				Source:     "kubernetes-live",
				Value:      "healthy",
				ObservedAt: now.Add(time.Second),
			}},
		},
	}

	got := ResolveUnknown(context.Background(), req, []EvidenceProbe{probe}, 1)

	if got.Initial.Decision != Escalate {
		t.Fatalf("expected initial ESCALATE, got %s", got.Initial.Decision)
	}
	if got.Final.Decision != Allow {
		t.Fatalf("expected final ALLOW, got %s reasons=%v", got.Final.Decision, got.Final.ReasonCodes)
	}
	if got.Final.Authorization == nil {
		t.Fatal("expected authorization after successful evidence acquisition")
	}
	if got.Final.Authorization.ResourceVersion != "101" {
		t.Fatalf("expected authorization to bind refreshed resourceVersion 101, got %q", got.Final.Authorization.ResourceVersion)
	}
	if probe.acquisitions != 1 {
		t.Fatalf("expected one probe acquisition, got %d", probe.acquisitions)
	}
}

func TestResolveUnknownContradictoryProbeBlocks(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 30, 0, 0, time.UTC)
	req := acquisitionRequest(now)

	probe := &fakeProbe{
		name:     "live-node-health",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{
			Evidence: []EvidenceObservation{{
				Claim:      "node_health",
				Source:     "kubernetes-live",
				Value:      "unhealthy",
				ObservedAt: now.Add(time.Second),
			}},
		},
	}

	got := ResolveUnknown(context.Background(), req, []EvidenceProbe{probe}, 1)

	if got.Final.Decision != Block {
		t.Fatalf("expected contradictory acquired evidence to BLOCK, got %s reasons=%v", got.Final.Decision, got.Final.ReasonCodes)
	}
	if len(got.Final.ReasonCodes) != 1 || got.Final.ReasonCodes[0] != EvidenceContradicted {
		t.Fatalf("expected %s, got %v", EvidenceContradicted, got.Final.ReasonCodes)
	}
	if got.Final.Authorization != nil {
		t.Fatal("contradictory evidence must not mint authorization")
	}
}

func TestResolveUnknownSkipsNonReadOnlyProbe(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 30, 0, 0, time.UTC)
	req := acquisitionRequest(now)

	probe := &fakeProbe{
		name:     "mutating-probe",
		safety:   ProbeSafetyClass("MUTATING"),
		supports: true,
	}

	got := ResolveUnknown(context.Background(), req, []EvidenceProbe{probe}, 1)

	if got.Final.Decision != Escalate {
		t.Fatalf("expected ESCALATE when only probe is unsafe, got %s", got.Final.Decision)
	}
	if probe.acquisitions != 0 {
		t.Fatalf("unsafe probe must never execute, acquisitions=%d", probe.acquisitions)
	}
	if len(got.Attempts) != 1 || !got.Attempts[0].Skipped {
		t.Fatalf("expected unsafe probe to be audited as skipped, got %+v", got.Attempts)
	}
}

func TestResolveUnknownProbeFailureRemainsEscalate(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 30, 0, 0, time.UTC)
	req := acquisitionRequest(now)

	probe := &fakeProbe{
		name:     "failing-probe",
		safety:   ProbeReadOnly,
		supports: true,
		err:      errors.New("live read unavailable"),
	}

	got := ResolveUnknown(context.Background(), req, []EvidenceProbe{probe}, 1)

	if got.Final.Decision != Escalate {
		t.Fatalf("expected probe failure to remain ESCALATE, got %s", got.Final.Decision)
	}
	if got.Final.Authorization != nil {
		t.Fatal("probe failure must not mint authorization")
	}
	if len(got.Attempts) != 1 || got.Attempts[0].Error == "" {
		t.Fatalf("expected probe error in audit record, got %+v", got.Attempts)
	}
}

func TestResolveUnknownHonorsMaxAttempts(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 30, 0, 0, time.UTC)
	req := acquisitionRequest(now)

	first := &fakeProbe{
		name:     "empty-probe",
		safety:   ProbeReadOnly,
		supports: true,
	}
	second := &fakeProbe{
		name:     "would-resolve",
		safety:   ProbeReadOnly,
		supports: true,
		outcome: ProbeOutcome{
			Evidence: []EvidenceObservation{{
				Claim:      "node_health",
				Source:     "source-two",
				Value:      "healthy",
				ObservedAt: now.Add(time.Second),
			}},
		},
	}

	got := ResolveUnknown(context.Background(), req, []EvidenceProbe{first, second}, 1)

	if got.Final.Decision != Escalate {
		t.Fatalf("expected unresolved ESCALATE after max attempts, got %s", got.Final.Decision)
	}
	if first.acquisitions != 1 || second.acquisitions != 0 {
		t.Fatalf("expected only first probe to run, first=%d second=%d", first.acquisitions, second.acquisitions)
	}
}

func acquisitionRequest(now time.Time) Request {
	return Request{
		ActionID:            "act-m1",
		Action:              "drain",
		Target:              "node/node-7",
		ResourceVersion:     "100",
		RequestedAt:         now,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []EvidenceObservation{{
			Claim:      "node_health",
			Source:     "epistemic-state-cache",
			Value:      "healthy",
			ObservedAt: now,
		}},
	}
}
