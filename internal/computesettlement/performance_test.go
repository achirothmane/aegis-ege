package computesettlement

import (
	"context"
	"testing"
	"time"
)

func TestVCS05MatchingPerformanceEnvelopeCanSettle(t *testing.T) {
	f := vcs04Fixture(t)
	result := vcs05Reconcile(
		t,
		f,
		vcs05FullPerformanceStreams(f.receipt, 1200, 1200),
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Settled {
		t.Fatalf("matching performance evidence should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.PerformanceEstablished {
		t.Fatal("expected performance continuity to be established")
	}
}

func TestVCS05ProviderTenantPerformanceContradictionIsDisputed(t *testing.T) {
	f := vcs04Fixture(t)
	result := vcs05Reconcile(
		t,
		f,
		vcs05FullPerformanceStreams(f.receipt, 1200, 800),
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Disputed {
		t.Fatalf("provider/tenant performance disagreement must be DISPUTED: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.PerformanceEstablished {
		t.Fatal("valid contradictory performance evidence should be established enough to dispute")
	}
}

func TestVCS05IndependentAgreementOnSustainedUnderperformanceProducesCreditDue(t *testing.T) {
	f := vcs04Fixture(t)
	result := vcs05Reconcile(
		t,
		f,
		vcs05FullPerformanceStreams(f.receipt, 800, 750),
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != CreditDue {
		t.Fatalf("independent agreement on sustained underperformance should produce CREDIT_DUE: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05DifferentDegradationExtentIsDisputed(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05TwoWindowStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		800,
		1200,
	)
	tenant := vcs05TwoWindowStream(
		"tenant-observer",
		"sha256:tenant-vcs02",
		f.receipt,
		800,
		800,
	)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{provider, tenant},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Disputed {
		t.Fatalf("different degradation extent should be DISPUTED: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05ContractToleranceCanPreserveSettlement(t *testing.T) {
	f := vcs04Fixture(t)
	envelope := vcs05Envelope()
	envelope.MaxBelowFloorDuration = time.Second

	provider := vcs05ThreeWindowStreamWithOneSecondDip(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
	)
	tenant := vcs05ThreeWindowStreamWithOneSecondDip(
		"tenant-observer",
		"sha256:tenant-vcs02",
		f.receipt,
	)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{provider, tenant},
		envelope,
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Settled {
		t.Fatalf("degradation inside explicit contract tolerance should remain SETTLED: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05OverlappingPerformanceWindowsRemainUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05TwoWindowStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		1200,
		1200,
	)
	provider.Samples[1].Start = provider.Samples[0].End.Add(-time.Second)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("overlapping performance windows must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.PerformanceEstablished {
		t.Fatal("overlapping performance windows must not establish performance continuity")
	}
}

func TestVCS05PerformanceSequenceGapRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05TwoWindowStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		1200,
		1200,
	)
	provider.Samples[1].Sequence = 3

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("performance sequence gap must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05PerformanceCoverageGapRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05TwoWindowStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		1200,
		1200,
	)
	provider.Samples[1].Start = provider.Samples[1].Start.Add(time.Second)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("performance coverage gap must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05WrongMetricCannotSatisfyContractEnvelope(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05FullPerformanceStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		1200,
	)
	provider.Samples[0].Metric = "different.metric"

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("wrong performance metric must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05PerformanceAfterReceiptBoundaryRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05FullPerformanceStream(
		"provider-control-plane",
		"sha256:provider-vcs02",
		f.receipt,
		1200,
	)
	provider.Samples[0].End = provider.Samples[0].End.Add(time.Second)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("performance evidence outside execution receipt must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05UnboundPerformanceDigestRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs05FullPerformanceStream(
		"provider-control-plane",
		"sha256:unassessed-performance-source",
		f.receipt,
		1200,
	)

	result := vcs05Reconcile(
		t,
		f,
		[]PerformanceStream{
			provider,
			vcs05FullPerformanceStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 1200),
		},
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("performance evidence not bound to assessed source must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS05PerformanceCannotUpgradePriorMeteringDispute(t *testing.T) {
	f := vcs04Fixture(t)
	result := vcs05Reconcile(
		t,
		f,
		vcs05FullPerformanceStreams(f.receipt, 1200, 1200),
		vcs05Envelope(),
		vcs05FullMeterStreams(f.receipt, 64, 63),
	)

	if result.Disposition != Disputed {
		t.Fatalf("performance must not upgrade prior metering dispute: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.PerformanceEstablished {
		t.Fatal("performance should not be evaluated after prior metering dispute")
	}
}

func vcs05Reconcile(
	t *testing.T,
	f vcs04FixtureState,
	performanceStreams []PerformanceStream,
	envelope PerformanceEnvelope,
	meterStreams []MeterStream,
) PerformanceExecutionReconciliation {
	t.Helper()
	return ReconcilePerformanceExecution(
		context.Background(),
		f.authority,
		f.lease,
		f.receipt,
		f.admission,
		f.completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs05",
		f.lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(f.evidenceAt, "true", "true"),
		vcs02Sources(f.evidenceAt, false),
		vcs02Requirement(),
		MeteringRequirement{
			ExpectedGPUSeconds: vcs04ExpectedGPUSeconds(f.receipt, 64),
			RequiredGPUCount:   64,
			MaxGap:             0,
		},
		meterStreams,
		envelope,
		performanceStreams,
	)
}

func vcs05Envelope() PerformanceEnvelope {
	return PerformanceEnvelope{
		Metric:                "collective.goodput",
		Unit:                  "contract_units_per_second",
		MinimumValue:          1000,
		MaxGap:                0,
		MaxBelowFloorDuration: 0,
	}
}

func vcs05FullMeterStreams(
	receipt ComputeExecutionReceipt,
	providerGPUCount uint32,
	tenantGPUCount uint32,
) []MeterStream {
	return []MeterStream{
		vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", receipt, providerGPUCount),
		vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", receipt, tenantGPUCount),
	}
}

func vcs05FullPerformanceStreams(
	receipt ComputeExecutionReceipt,
	providerValue uint64,
	tenantValue uint64,
) []PerformanceStream {
	return []PerformanceStream{
		vcs05FullPerformanceStream(
			"provider-control-plane",
			"sha256:provider-vcs02",
			receipt,
			providerValue,
		),
		vcs05FullPerformanceStream(
			"tenant-observer",
			"sha256:tenant-vcs02",
			receipt,
			tenantValue,
		),
	}
}

func vcs05FullPerformanceStream(
	source string,
	digest string,
	receipt ComputeExecutionReceipt,
	value uint64,
) PerformanceStream {
	return PerformanceStream{
		Source:         source,
		EvidenceDigest: digest,
		Samples: []PerformanceSample{{
			Sequence: 1,
			Start:    receipt.StartedAt,
			End:      receipt.FinishedAt,
			Metric:   "collective.goodput",
			Unit:     "contract_units_per_second",
			Value:    value,
		}},
	}
}

func vcs05TwoWindowStream(
	source string,
	digest string,
	receipt ComputeExecutionReceipt,
	firstValue uint64,
	secondValue uint64,
) PerformanceStream {
	total := receipt.FinishedAt.Sub(receipt.StartedAt)
	firstDuration := (total / 2).Truncate(time.Second)
	if firstDuration <= 0 {
		firstDuration = time.Second
	}
	mid := receipt.StartedAt.Add(firstDuration)
	return PerformanceStream{
		Source:         source,
		EvidenceDigest: digest,
		Samples: []PerformanceSample{
			{
				Sequence: 1,
				Start:    receipt.StartedAt,
				End:      mid,
				Metric:   "collective.goodput",
				Unit:     "contract_units_per_second",
				Value:    firstValue,
			},
			{
				Sequence: 2,
				Start:    mid,
				End:      receipt.FinishedAt,
				Metric:   "collective.goodput",
				Unit:     "contract_units_per_second",
				Value:    secondValue,
			},
		},
	}
}

func vcs05ThreeWindowStreamWithOneSecondDip(
	source string,
	digest string,
	receipt ComputeExecutionReceipt,
) PerformanceStream {
	dipStart := receipt.StartedAt.Add(10 * time.Second)
	dipEnd := dipStart.Add(time.Second)
	return PerformanceStream{
		Source:         source,
		EvidenceDigest: digest,
		Samples: []PerformanceSample{
			{
				Sequence: 1,
				Start:    receipt.StartedAt,
				End:      dipStart,
				Metric:   "collective.goodput",
				Unit:     "contract_units_per_second",
				Value:    1200,
			},
			{
				Sequence: 2,
				Start:    dipStart,
				End:      dipEnd,
				Metric:   "collective.goodput",
				Unit:     "contract_units_per_second",
				Value:    800,
			},
			{
				Sequence: 3,
				Start:    dipEnd,
				End:      receipt.FinishedAt,
				Metric:   "collective.goodput",
				Unit:     "contract_units_per_second",
				Value:    1200,
			},
		},
	}
}
