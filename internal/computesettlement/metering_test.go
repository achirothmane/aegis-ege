package computesettlement

import (
	"context"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestVCS04CompleteIndependentMeteringCanSettle(t *testing.T) {
	f := vcs04Fixture(t)
	streams := []MeterStream{
		vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64),
		vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
	}

	result := vcs04Reconcile(t, f, streams, vcs04ExpectedGPUSeconds(f.receipt, 64))
	if result.Disposition != Settled {
		t.Fatalf("complete matching metering should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.MeteringEstablished {
		t.Fatal("expected metering continuity to be established")
	}
}

func TestVCS04ProviderTenantQuantityContradictionIsDisputed(t *testing.T) {
	f := vcs04Fixture(t)
	streams := []MeterStream{
		vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64),
		vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 63),
	}

	result := vcs04Reconcile(t, f, streams, vcs04ExpectedGPUSeconds(f.receipt, 64))
	if result.Disposition != Disputed {
		t.Fatalf("valid metering streams with different delivered quantities must be DISPUTED: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.MeteringEstablished {
		t.Fatal("quantity disagreement is a dispute between valid streams, not a continuity failure")
	}
}

func TestVCS04AgreementOnUnderDeliveryProducesCreditDue(t *testing.T) {
	f := vcs04Fixture(t)
	streams := []MeterStream{
		vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 63),
		vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 63),
	}

	result := vcs04Reconcile(t, f, streams, vcs04ExpectedGPUSeconds(f.receipt, 64))
	if result.Disposition != CreditDue {
		t.Fatalf("independent agreement on under-delivery should produce CREDIT_DUE: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS04DuplicateOverlappingIntervalRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04TwoSliceStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[1].Start = provider.Slices[0].End.Add(-time.Second)
	provider.Slices[1].CounterStartSeconds = provider.Slices[0].CounterEndSeconds
	provider.Slices[1].CounterEndSeconds = provider.Slices[1].CounterStartSeconds +
		uint64(provider.Slices[1].End.Sub(provider.Slices[1].Start)/time.Second)*64

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("overlapping metering intervals must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.MeteringEstablished {
		t.Fatal("overlapping intervals must not establish metering continuity")
	}
}

func TestVCS04LostIntervalAfterRestartRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04TwoSliceStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[1].Start = provider.Slices[1].Start.Add(2 * time.Second)
	provider.Slices[1].CounterStartSeconds = provider.Slices[0].CounterEndSeconds
	provider.Slices[1].CounterEndSeconds = provider.Slices[1].CounterStartSeconds +
		uint64(provider.Slices[1].End.Sub(provider.Slices[1].Start)/time.Second)*64

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("metering gap after restart must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS04CounterResetRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04TwoSliceStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[1].CounterStartSeconds = provider.Slices[0].CounterEndSeconds - 64
	provider.Slices[1].CounterEndSeconds = provider.Slices[1].CounterStartSeconds +
		uint64(provider.Slices[1].End.Sub(provider.Slices[1].Start)/time.Second)*64

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("counter reset must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS04SequenceGapRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04TwoSliceStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[1].Sequence = 3

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("sequence gap must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS04MeteringAfterReceiptBoundaryRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[0].End = provider.Slices[0].End.Add(time.Second)
	provider.Slices[0].CounterEndSeconds += 64

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("metering beyond execution receipt must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS04CounterDeltaCannotOverstateElapsedCapacity(t *testing.T) {
	f := vcs04Fixture(t)
	provider := vcs04FullStream("provider-control-plane", "sha256:provider-vcs02", f.receipt, 64)
	provider.Slices[0].CounterEndSeconds += 64

	result := vcs04Reconcile(
		t,
		f,
		[]MeterStream{
			provider,
			vcs04FullStream("tenant-observer", "sha256:tenant-vcs02", f.receipt, 64),
		},
		vcs04ExpectedGPUSeconds(f.receipt, 64),
	)
	if result.Disposition != Unknown {
		t.Fatalf("counter delta larger than time×capacity must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

type vcs04FixtureState struct {
	authority  egeproto.PermitAuthority
	lease      HardwareLeaseBinding
	receipt    ComputeExecutionReceipt
	admission  SignedHardwareIdentityAttestation
	completion SignedHardwareIdentityAttestation
	evidenceAt time.Time
}

func vcs04Fixture(t *testing.T) vcs04FixtureState {
	t.Helper()
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.October, 3, 1, 20, 0, 0, time.UTC)
	lease, receipt, admission, completion := vcs03Fixture(
		t,
		authority,
		base,
		"sha256:hardware-set-a",
		"sha256:topology-a",
	)
	return vcs04FixtureState{
		authority:  authority,
		lease:      lease,
		receipt:    receipt,
		admission:  admission,
		completion: completion,
		evidenceAt: completion.Attestation.ObservedAt,
	}
}

func vcs04Reconcile(
	t *testing.T,
	f vcs04FixtureState,
	streams []MeterStream,
	expected uint64,
) MeteredExecutionReconciliation {
	t.Helper()
	return ReconcileMeteredExecution(
		context.Background(),
		f.authority,
		f.lease,
		f.receipt,
		f.admission,
		f.completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs04",
		f.lease.ContractDigest,
		vcs02Contract(),
		vcs02Observations(f.evidenceAt, "true", "true"),
		vcs02Sources(f.evidenceAt, false),
		vcs02Requirement(),
		MeteringRequirement{
			ExpectedGPUSeconds: expected,
			RequiredGPUCount:   64,
			MaxGap:             0,
		},
		streams,
	)
}

func vcs04ExpectedGPUSeconds(receipt ComputeExecutionReceipt, gpuCount uint32) uint64 {
	return uint64(receipt.FinishedAt.Sub(receipt.StartedAt)/time.Second) * uint64(gpuCount)
}

func vcs04FullStream(
	source string,
	digest string,
	receipt ComputeExecutionReceipt,
	gpuCount uint32,
) MeterStream {
	seconds := uint64(receipt.FinishedAt.Sub(receipt.StartedAt) / time.Second)
	return MeterStream{
		Source:         source,
		EvidenceDigest: digest,
		Slices: []MeterSlice{{
			Sequence:            1,
			Start:               receipt.StartedAt,
			End:                 receipt.FinishedAt,
			GPUCount:            gpuCount,
			CounterStartSeconds: 0,
			CounterEndSeconds:   seconds * uint64(gpuCount),
		}},
	}
}

func vcs04TwoSliceStream(
	source string,
	digest string,
	receipt ComputeExecutionReceipt,
	gpuCount uint32,
) MeterStream {
	total := receipt.FinishedAt.Sub(receipt.StartedAt)
	firstDuration := (total / 2).Truncate(time.Second)
	if firstDuration <= 0 {
		firstDuration = time.Second
	}
	mid := receipt.StartedAt.Add(firstDuration)
	firstDelta := uint64(mid.Sub(receipt.StartedAt)/time.Second) * uint64(gpuCount)
	secondDelta := uint64(receipt.FinishedAt.Sub(mid)/time.Second) * uint64(gpuCount)
	return MeterStream{
		Source:         source,
		EvidenceDigest: digest,
		Slices: []MeterSlice{
			{
				Sequence:            1,
				Start:               receipt.StartedAt,
				End:                 mid,
				GPUCount:            gpuCount,
				CounterStartSeconds: 0,
				CounterEndSeconds:   firstDelta,
			},
			{
				Sequence:            2,
				Start:               mid,
				End:                 receipt.FinishedAt,
				GPUCount:            gpuCount,
				CounterStartSeconds: firstDelta,
				CounterEndSeconds:   firstDelta + secondDelta,
			},
		},
	}
}
