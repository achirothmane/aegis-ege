package computesettlement

import (
	"context"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestVCS07ExactExecutionRootCanSettle(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Settled {
		t.Fatalf("exact workload-rooted performance should settle: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.ExecutionRootEstablished {
		t.Fatal("expected execution root to be established")
	}
	if len(result.MeasurementExecutionBindings) != 2 {
		t.Fatalf("expected two measurement execution bindings, got %d", len(result.MeasurementExecutionBindings))
	}
}

func TestVCS07RuntimeArtifactMismatchCannotSettleCorrectProfileLabel(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()

	provenance := vcs07UnsignedProvenance(t, f, profile, root)
	provenance.ExecutableArtifactDigest = "sha256:runtime-artifact-not-contracted"
	signedProvenance := vcs07SignProvenance(t, provenanceAuthority, provenance)
	bindings := vcs07Bindings(t, f, measurements, signedProvenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		signedProvenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("runtime artifact mismatch must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
	if result.ExecutionRootEstablished {
		t.Fatal("artifact mismatch must not establish execution root")
	}
}

func TestVCS07TrustedProcessIdentityMismatchRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	root.ProcessIdentityDigest = "sha256:different-runtime-process"

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("trusted process identity mismatch must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07OldReceiptProvenanceCannotRootCurrentMeasurement(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()

	provenancePayload := vcs07UnsignedProvenance(t, f, profile, root)
	provenancePayload.ReceiptID = "receipt:older-runtime"
	provenance := vcs07SignProvenance(t, provenanceAuthority, provenancePayload)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("old receipt provenance must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07DifferentHardwareLineageCannotRootMeasurement(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()

	provenancePayload := vcs07UnsignedProvenance(t, f, profile, root)
	provenancePayload.HardwareAttestationDigest = "sha256:different-hardware-lineage"
	provenance := vcs07SignProvenance(t, provenanceAuthority, provenancePayload)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("different hardware lineage must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07MeasurementSignerCannotRewriteSignedMeasurementAfterRuntimeBinding(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	// This remains a valid VCS-06 measurement: only its opaque attestation ID
	// changes. The VCS-07 runtime binding must detect that the signed
	// measurement digest is no longer the one rooted in execution provenance.
	rewritten := measurements[0].Attestation
	rewritten.AttestationID = "measurement:vcs07:rewritten-after-root-binding"
	measurements[0] = vcs06Resign(t, providerAuthority, rewritten)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("measurement rewritten after runtime binding must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07BindingToDifferentExecutionProvenanceRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	bad := bindings[0].Binding
	bad.ExecutionProvenanceDigest = "sha256:different-execution-provenance"
	bindings[0] = vcs07SignBinding(t, provenanceAuthority, bad)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("binding to different execution provenance must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07MissingRuntimeBindingRemainsUnknown(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings[:1],
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("missing runtime binding must remain UNKNOWN: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07MeasurementAuthorityCannotImpersonateProvenanceAuthority(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()

	// Provider owns a valid measurement signing key but not the independently
	// trusted execution provenance key.
	provenance := vcs07SignProvenance(
		t,
		providerAuthority,
		vcs07UnsignedProvenance(t, f, profile, root),
	)
	bindings := vcs07Bindings(t, f, measurements, provenance, providerAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != Unknown {
		t.Fatalf("measurement authority must not impersonate provenance authority: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS07RootedUnderperformancePreservesCreditDue(t *testing.T) {
	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	profile := vcs06Profile()
	streams := vcs05FullPerformanceStreams(f.receipt, 800, 800)
	measurements := vcs06Measurements(t, f, profile, streams, providerAuthority, tenantAuthority)
	root := vcs07Root()
	provenance := vcs07Provenance(t, f, profile, root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)

	result := vcs07Reconcile(
		t,
		f,
		profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root,
		provenance,
		bindings,
		provenanceAuthority,
	)

	if result.Disposition != CreditDue {
		t.Fatalf("rooted underperformance should preserve CREDIT_DUE: got %s (%s)", result.Disposition, result.Detail)
	}
	if !result.ExecutionRootEstablished {
		t.Fatal("expected execution root on proven underperformance")
	}
}

func vcs07Root() TrustedExecutionRoot {
	return TrustedExecutionRoot{
		ActivationReceiptDigest: "sha256:activation-receipt-vcs07",
		ProcessIdentityDigest:    "sha256:process-identity-vcs07",
		CgroupIdentityDigest:     "sha256:cgroup-identity-vcs07",
		BootMeasurementDigest:    "sha256:boot-measurement-vcs07",
	}
}

func vcs07UnsignedProvenance(
	t *testing.T,
	f vcs04FixtureState,
	profile WorkloadPerformanceProfile,
	root TrustedExecutionRoot,
) WorkloadExecutionProvenance {
	t.Helper()
	profileDigest, err := WorkloadPerformanceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	hardwareDigest, err := HardwareIdentityAttestationDigest(f.completion)
	if err != nil {
		t.Fatal(err)
	}
	return WorkloadExecutionProvenance{
		Version:                   WorkloadExecutionProvenanceVersion,
		ProvenanceID:              "execution-provenance:vcs07",
		Subject:                   f.lease.Subject,
		LeaseID:                   f.lease.LeaseID,
		ReceiptID:                 f.receipt.ReceiptID,
		ContractDigest:            f.lease.ContractDigest,
		WorkloadProfileDigest:     profileDigest,
		ExecutableArtifactDigest:  profile.ArtifactDigest,
		ActivationReceiptDigest:   root.ActivationReceiptDigest,
		ProcessIdentityDigest:     root.ProcessIdentityDigest,
		CgroupIdentityDigest:      root.CgroupIdentityDigest,
		BootMeasurementDigest:     root.BootMeasurementDigest,
		HardwareAttestationDigest: hardwareDigest,
		ObservedAt:                f.receipt.FinishedAt.Add(-time.Second),
	}
}

func vcs07Provenance(
	t *testing.T,
	f vcs04FixtureState,
	profile WorkloadPerformanceProfile,
	root TrustedExecutionRoot,
	authority egeproto.PermitAuthority,
) SignedWorkloadExecutionProvenance {
	t.Helper()
	return vcs07SignProvenance(
		t,
		authority,
		vcs07UnsignedProvenance(t, f, profile, root),
	)
}

func vcs07SignProvenance(
	t *testing.T,
	authority egeproto.PermitAuthority,
	provenance WorkloadExecutionProvenance,
) SignedWorkloadExecutionProvenance {
	t.Helper()
	signed, err := SignWorkloadExecutionProvenance(
		context.Background(),
		authority,
		provenance,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func vcs07Bindings(
	t *testing.T,
	f vcs04FixtureState,
	measurements []SignedWorkloadMeasurementAttestation,
	provenance SignedWorkloadExecutionProvenance,
	authority egeproto.PermitAuthority,
) []SignedMeasurementExecutionBinding {
	t.Helper()
	provenanceDigest, err := WorkloadExecutionProvenanceDigest(provenance)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]SignedMeasurementExecutionBinding, 0, len(measurements))
	for _, measurement := range measurements {
		measurementDigest, err := WorkloadMeasurementAttestationDigest(measurement)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, vcs07SignBinding(
			t,
			authority,
			MeasurementExecutionBinding{
				Version:                      MeasurementExecutionBindingVersion,
				BindingID:                    "execution-binding:vcs07:" + measurement.Attestation.Source,
				Source:                       measurement.Attestation.Source,
				MeasurementAttestationDigest: measurementDigest,
				ExecutionProvenanceDigest:    provenanceDigest,
				EvidenceDigest:               measurement.Attestation.EvidenceDigest,
				LeaseID:                      f.lease.LeaseID,
				ReceiptID:                    f.receipt.ReceiptID,
				BoundAt:                      f.receipt.FinishedAt.Add(2 * time.Second),
			},
		))
	}
	return out
}

func vcs07SignBinding(
	t *testing.T,
	authority egeproto.PermitAuthority,
	binding MeasurementExecutionBinding,
) SignedMeasurementExecutionBinding {
	t.Helper()
	signed, err := SignMeasurementExecutionBinding(
		context.Background(),
		authority,
		binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func vcs07Reconcile(
	t *testing.T,
	f vcs04FixtureState,
	profile WorkloadPerformanceProfile,
	performanceStreams []PerformanceStream,
	measurements []SignedWorkloadMeasurementAttestation,
	measurementVerifiers map[string]egeproto.SignatureVerifier,
	root TrustedExecutionRoot,
	provenance SignedWorkloadExecutionProvenance,
	bindings []SignedMeasurementExecutionBinding,
	provenanceVerifier egeproto.SignatureVerifier,
) WorkloadRootedPerformanceReconciliation {
	t.Helper()
	return ReconcileWorkloadRootedPerformance(
		context.Background(),
		f.authority,
		measurementVerifiers,
		provenanceVerifier,
		f.lease,
		f.receipt,
		f.admission,
		f.completion,
		vcs03HardwarePolicy(),
		"compute-execution/vcs07",
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
		vcs05FullMeterStreams(f.receipt, 64, 64),
		vcs05Envelope(),
		performanceStreams,
		profile,
		measurements,
		root,
		provenance,
		bindings,
	)
}
