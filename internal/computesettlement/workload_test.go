package computesettlement

import (
	"context"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestVCS06ExactContractedWorkloadCanSettle(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Settled {
		t.Fatalf("exact workload-bound performance should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.WorkloadBindingEstablished {
		t.Fatal("expected workload binding to be established")
	}
	if len(result.MeasurementAttestationDigests) != 2 {
		t.Fatalf("expected two bound measurement attestations, got %d", len(result.MeasurementAttestationDigests))
	}
}

func TestVCS06EasyBenchmarkCannotSatisfyDifferentContractedWorkload(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	contracted := vcs06Profile()
	easyBenchmark := contracted
	easyBenchmark.WorkloadDigest = "sha256:workload-easy-benchmark"
	easyBenchmark.BenchmarkProfileDigest = "sha256:benchmark-easy"
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 5000, 5000)

	result := vcs06Reconcile(
		t,
		f,
		contracted,
		performanceStreams,
		vcs06Measurements(t, f, easyBenchmark, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("easy benchmark evidence must not settle another workload: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.WorkloadBindingEstablished {
		t.Fatal("benchmark substitution must not establish workload binding")
	}
}

func TestVCS06ArtifactSubstitutionCannotReusePerformanceEvidence(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	contracted := vcs06Profile()
	substituted := contracted
	substituted.ArtifactDigest = "sha256:model-artifact-other"
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)

	result := vcs06Reconcile(
		t,
		f,
		contracted,
		performanceStreams,
		vcs06Measurements(t, f, substituted, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("artifact substitution must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS06RuntimeConfigSubstitutionCannotReusePerformanceEvidence(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	contracted := vcs06Profile()
	substituted := contracted
	substituted.RuntimeConfigDigest = "sha256:runtime-batch1-fp16"
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)

	result := vcs06Reconcile(
		t,
		f,
		contracted,
		performanceStreams,
		vcs06Measurements(t, f, substituted, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("runtime configuration substitution must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS06OldReceiptMeasurementCannotSettleCurrentExecution(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority)

	measurements[0].Attestation.ReceiptID = "receipt:older-execution"
	measurements[0] = vcs06Resign(t, providerAuthority, measurements[0].Attestation)

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("old receipt measurement must not settle current execution: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS06PostSignatureProfileRewriteFailsVerification(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority)

	measurements[0].Attestation.WorkloadProfileDigest = "sha256:rewritten-after-signature"

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("post-signature profile rewrite must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS06PerformanceEvidenceDigestSubstitutionFailsBinding(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority)

	measurements[0].Attestation.EvidenceDigest = "sha256:different-performance-evidence"
	measurements[0] = vcs06Resign(t, providerAuthority, measurements[0].Attestation)

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != Unknown {
		t.Fatalf("measurement evidence substitution must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS06BoundUnderperformancePreservesCreditDue(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 800, 800)

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 64),
	)

	if result.Disposition != CreditDue {
		t.Fatalf("workload binding must preserve proven underperformance credit: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.WorkloadBindingEstablished {
		t.Fatal("expected workload binding on underperformance evidence")
	}
}

func TestVCS06CannotUpgradePriorMeteringDispute(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	performanceStreams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)

	result := vcs06Reconcile(
		t,
		f,
		profile,
		performanceStreams,
		vcs06Measurements(t, f, profile, performanceStreams, providerAuthority, tenantAuthority),
		vcs06Verifiers(providerAuthority, tenantAuthority),
		vcs05FullMeterStreams(f.receipt, 64, 63),
	)

	if result.Disposition != Disputed {
		t.Fatalf("workload evidence must not upgrade prior metering dispute: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.WorkloadBindingEstablished {
		t.Fatal("workload binding should not be evaluated when performance was not evaluated")
	}
}

func vcs06Profile() WorkloadPerformanceProfile {
	return WorkloadPerformanceProfile{
		WorkloadID:             "training-job:vcs06",
		WorkloadDigest:         "sha256:workload-w",
		ArtifactDigest:         "sha256:model-artifact-w",
		BenchmarkProfileDigest: "sha256:benchmark-profile-w",
		RuntimeConfigDigest:    "sha256:runtime-batch64-bf16",
		InputProfileDigest:     "sha256:input-corpus-w",
	}
}

func vcs06Authority(t *testing.T) egeproto.PermitAuthority {
	t.Helper()
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func vcs06Verifiers(
	provider egeproto.PermitAuthority,
	tenant egeproto.PermitAuthority,
) map[string]egeproto.SignatureVerifier {
	return map[string]egeproto.SignatureVerifier{
		"provider-control-plane": provider,
		"tenant-observer":       tenant,
	}
}

func vcs06Measurements(
	t *testing.T,
	f vcs04FixtureState,
	profile WorkloadPerformanceProfile,
	streams []PerformanceStream,
	providerAuthority egeproto.PermitAuthority,
	tenantAuthority egeproto.PermitAuthority,
) []SignedWorkloadMeasurementAttestation {
	t.Helper()

	profileDigest, err := WorkloadPerformanceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}

	authorities := map[string]egeproto.PermitAuthority{
		"provider-control-plane": providerAuthority,
		"tenant-observer":       tenantAuthority,
	}

	out := make([]SignedWorkloadMeasurementAttestation, 0, len(streams))
	for _, stream := range streams {
		authority := authorities[stream.Source]
		if authority == nil {
			t.Fatalf("no authority for source %s", stream.Source)
		}
		attestation := WorkloadMeasurementAttestation{
			Version:               WorkloadMeasurementAttestationVersion,
			AttestationID:         "measurement:vcs06:" + stream.Source,
			Source:                stream.Source,
			EvidenceDigest:        stream.EvidenceDigest,
			Subject:               f.lease.Subject,
			LeaseID:               f.lease.LeaseID,
			ReceiptID:             f.receipt.ReceiptID,
			ContractDigest:        f.lease.ContractDigest,
			WorkloadProfileDigest: profileDigest,
			Metric:                vcs05Envelope().Metric,
			Unit:                  vcs05Envelope().Unit,
			StartedAt:             f.receipt.StartedAt,
			FinishedAt:            f.receipt.FinishedAt,
			MeasuredAt:            f.receipt.FinishedAt.Add(time.Second),
		}
		out = append(out, vcs06Resign(t, authority, attestation))
	}
	return out
}

func vcs06Resign(
	t *testing.T,
	authority egeproto.PermitAuthority,
	attestation WorkloadMeasurementAttestation,
) SignedWorkloadMeasurementAttestation {
	t.Helper()
	signed, err := SignWorkloadMeasurementAttestation(
		context.Background(),
		authority,
		attestation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func vcs06Reconcile(
	t *testing.T,
	f vcs04FixtureState,
	profile WorkloadPerformanceProfile,
	performanceStreams []PerformanceStream,
	measurements []SignedWorkloadMeasurementAttestation,
	verifiers map[string]egeproto.SignatureVerifier,
	meterStreams []MeterStream,
) WorkloadBoundPerformanceReconciliation {
	t.Helper()
	return ReconcileWorkloadBoundPerformance(
		context.Background(),
		f.authority,
		verifiers,
		f.lease,
		f.receipt,
		f.admission,
		f.completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs06",
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
		vcs05Envelope(),
		performanceStreams,
		profile,
		measurements,
	)
}
