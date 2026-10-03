package computesettlement

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const WorkloadMeasurementAttestationVersion = "aegis.compute/workload-measurement-attestation/v0"

// WorkloadPerformanceProfile is the exact workload/benchmark identity whose
// performance is allowed to satisfy the compute contract. The individual
// digests are domain-owned: model/artifact/config semantics do not enter the
// governance kernel.
type WorkloadPerformanceProfile struct {
	WorkloadID              string `json:"workload_id"`
	WorkloadDigest          string `json:"workload_digest"`
	ArtifactDigest          string `json:"artifact_digest"`
	BenchmarkProfileDigest  string `json:"benchmark_profile_digest"`
	RuntimeConfigDigest     string `json:"runtime_config_digest"`
	InputProfileDigest      string `json:"input_profile_digest"`
}

type WorkloadMeasurementAttestation struct {
	Version               string    `json:"version"`
	AttestationID         string    `json:"attestation_id"`
	Source                string    `json:"source"`
	EvidenceDigest        string    `json:"evidence_digest"`
	Subject               string    `json:"subject"`
	LeaseID               string    `json:"lease_id"`
	ReceiptID             string    `json:"receipt_id"`
	ContractDigest        string    `json:"contract_digest"`
	WorkloadProfileDigest string    `json:"workload_profile_digest"`
	Metric                string    `json:"metric"`
	Unit                  string    `json:"unit"`
	StartedAt             time.Time `json:"started_at"`
	FinishedAt            time.Time `json:"finished_at"`
	MeasuredAt            time.Time `json:"measured_at"`
}

type SignedWorkloadMeasurementAttestation struct {
	Attestation WorkloadMeasurementAttestation `json:"attestation"`
	KeyID       string                         `json:"key_id"`
	Signature   string                         `json:"signature"`
}

type WorkloadBoundPerformanceReconciliation struct {
	PerformanceExecutionReconciliation
	WorkloadBindingEstablished bool
	WorkloadProfileDigest      string
	MeasurementAttestationDigests map[string]string
}

func WorkloadPerformanceProfileDigest(
	profile WorkloadPerformanceProfile,
) (string, error) {
	if err := validateWorkloadPerformanceProfile(profile); err != nil {
		return "", err
	}
	normalized := profile
	normalized.WorkloadID = strings.TrimSpace(normalized.WorkloadID)
	normalized.WorkloadDigest = strings.TrimSpace(normalized.WorkloadDigest)
	normalized.ArtifactDigest = strings.TrimSpace(normalized.ArtifactDigest)
	normalized.BenchmarkProfileDigest = strings.TrimSpace(normalized.BenchmarkProfileDigest)
	normalized.RuntimeConfigDigest = strings.TrimSpace(normalized.RuntimeConfigDigest)
	normalized.InputProfileDigest = strings.TrimSpace(normalized.InputProfileDigest)

	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal workload performance profile: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/workload-performance-profile/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignWorkloadMeasurementAttestation(
	ctx context.Context,
	authority egeproto.PermitAuthority,
	attestation WorkloadMeasurementAttestation,
) (SignedWorkloadMeasurementAttestation, error) {
	if authority == nil {
		return SignedWorkloadMeasurementAttestation{}, errors.New("workload measurement authority is required")
	}
	if err := validateWorkloadMeasurementAttestation(attestation); err != nil {
		return SignedWorkloadMeasurementAttestation{}, err
	}
	payload, err := canonicalWorkloadMeasurementAttestationPayload(attestation)
	if err != nil {
		return SignedWorkloadMeasurementAttestation{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return SignedWorkloadMeasurementAttestation{}, fmt.Errorf("sign workload measurement attestation: %w", err)
	}
	return SignedWorkloadMeasurementAttestation{
		Attestation: attestation,
		KeyID:       keyID,
		Signature:   base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyWorkloadMeasurementAttestation(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	signed SignedWorkloadMeasurementAttestation,
) error {
	if verifier == nil {
		return errors.New("workload measurement verifier is required")
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return errors.New("workload measurement key id and signature are required")
	}
	if err := validateWorkloadMeasurementAttestation(signed.Attestation); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode workload measurement signature: %w", err)
	}
	payload, err := canonicalWorkloadMeasurementAttestationPayload(signed.Attestation)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, signed.KeyID, payload, signature); err != nil {
		return fmt.Errorf("verify workload measurement attestation: %w", err)
	}
	return nil
}

func WorkloadMeasurementAttestationDigest(
	signed SignedWorkloadMeasurementAttestation,
) (string, error) {
	if err := validateWorkloadMeasurementAttestation(signed.Attestation); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed workload measurement attestation is incomplete")
	}
	normalized := signed
	normalized.Attestation.StartedAt = normalized.Attestation.StartedAt.UTC()
	normalized.Attestation.FinishedAt = normalized.Attestation.FinishedAt.UTC()
	normalized.Attestation.MeasuredAt = normalized.Attestation.MeasuredAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal signed workload measurement attestation: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/signed-workload-measurement-attestation/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ReconcileWorkloadBoundPerformance verifies that every performance stream whose
// result is used commercially is signed over the exact contract workload
// profile, lease, receipt, metric, evidence digest, and execution interval.
//
// A workload-binding failure is UNKNOWN rather than a performance verdict: the
// system cannot establish that the measured benchmark is the purchased work.
func ReconcileWorkloadBoundPerformance(
	ctx context.Context,
	hardwareVerifier egeproto.SignatureVerifier,
	measurementVerifiers map[string]egeproto.SignatureVerifier,
	lease HardwareLeaseBinding,
	receipt ComputeExecutionReceipt,
	admission SignedHardwareIdentityAttestation,
	completion SignedHardwareIdentityAttestation,
	hardwarePolicy HardwareContinuityPolicy,
	actionID string,
	planDigest string,
	contractFacts map[string]string,
	observations []Observation,
	sources []egeproto.EvidenceSource,
	evidenceRequirement EvidenceRequirement,
	meteringRequirement MeteringRequirement,
	meterStreams []MeterStream,
	envelope PerformanceEnvelope,
	performanceStreams []PerformanceStream,
	expectedProfile WorkloadPerformanceProfile,
	measurementAttestations []SignedWorkloadMeasurementAttestation,
) WorkloadBoundPerformanceReconciliation {
	base := ReconcilePerformanceExecution(
		ctx,
		hardwareVerifier,
		lease,
		receipt,
		admission,
		completion,
		hardwarePolicy,
		actionID,
		planDigest,
		contractFacts,
		observations,
		sources,
		evidenceRequirement,
		meteringRequirement,
		meterStreams,
		envelope,
		performanceStreams,
	)
	result := WorkloadBoundPerformanceReconciliation{
		PerformanceExecutionReconciliation: base,
		MeasurementAttestationDigests:      map[string]string{},
	}

	// If performance was never evaluated because an earlier proof layer already
	// reached a non-SETTLED disposition, workload evidence must not overwrite it.
	if !base.PerformanceEstablished {
		return result
	}

	fail := func(detail string) WorkloadBoundPerformanceReconciliation {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "workload binding: " + detail,
		}
		result.WorkloadBindingEstablished = false
		return result
	}

	profileDigest, err := WorkloadPerformanceProfileDigest(expectedProfile)
	if err != nil {
		return fail(err.Error())
	}
	result.WorkloadProfileDigest = profileDigest

	if len(measurementAttestations) != len(performanceStreams) {
		return fail("performance streams and workload measurement attestations must have identical cardinality")
	}

	streamBySource := make(map[string]PerformanceStream, len(performanceStreams))
	for _, stream := range performanceStreams {
		if _, duplicate := streamBySource[stream.Source]; duplicate {
			return fail("performance stream source is duplicated")
		}
		streamBySource[stream.Source] = stream
	}

	seen := make(map[string]struct{}, len(measurementAttestations))
	for _, signed := range measurementAttestations {
		attestation := signed.Attestation
		source := strings.TrimSpace(attestation.Source)
		if source == "" {
			return fail("workload measurement source is required")
		}
		if _, duplicate := seen[source]; duplicate {
			return fail("workload measurement source is duplicated")
		}
		seen[source] = struct{}{}

		stream, ok := streamBySource[source]
		if !ok {
			return fail("workload measurement has no performance stream")
		}
		verifier := measurementVerifiers[source]
		if verifier == nil {
			return fail("workload measurement verifier is missing for source")
		}
		if err := VerifyWorkloadMeasurementAttestation(ctx, verifier, signed); err != nil {
			return fail("measurement attestation invalid: " + err.Error())
		}

		if attestation.Subject != lease.Subject ||
			attestation.LeaseID != lease.LeaseID ||
			attestation.ReceiptID != receipt.ReceiptID ||
			attestation.ContractDigest != lease.ContractDigest {
			return fail("measurement attestation does not bind the admitted execution")
		}
		if attestation.WorkloadProfileDigest != profileDigest {
			return fail("measured workload profile differs from contracted profile")
		}
		if attestation.EvidenceDigest != stream.EvidenceDigest {
			return fail("measurement attestation evidence digest differs from performance stream")
		}
		if attestation.Metric != envelope.Metric || attestation.Unit != envelope.Unit {
			return fail("measurement attestation metric or unit differs from contract envelope")
		}
		if !attestation.StartedAt.Equal(receipt.StartedAt) ||
			!attestation.FinishedAt.Equal(receipt.FinishedAt) {
			return fail("measurement attestation interval differs from execution receipt")
		}
		if attestation.MeasuredAt.Before(receipt.FinishedAt) {
			return fail("measurement attestation was issued before execution completed")
		}

		digest, err := WorkloadMeasurementAttestationDigest(signed)
		if err != nil {
			return fail("digest workload measurement attestation: " + err.Error())
		}
		result.MeasurementAttestationDigests[source] = digest
	}

	result.WorkloadBindingEstablished = true
	return result
}

func validateWorkloadPerformanceProfile(profile WorkloadPerformanceProfile) error {
	if strings.TrimSpace(profile.WorkloadID) == "" ||
		strings.TrimSpace(profile.WorkloadDigest) == "" ||
		strings.TrimSpace(profile.ArtifactDigest) == "" ||
		strings.TrimSpace(profile.BenchmarkProfileDigest) == "" ||
		strings.TrimSpace(profile.RuntimeConfigDigest) == "" ||
		strings.TrimSpace(profile.InputProfileDigest) == "" {
		return errors.New("workload performance profile is incomplete")
	}
	return nil
}

func validateWorkloadMeasurementAttestation(
	attestation WorkloadMeasurementAttestation,
) error {
	if attestation.Version != WorkloadMeasurementAttestationVersion {
		return fmt.Errorf("unsupported workload measurement attestation version %q", attestation.Version)
	}
	if strings.TrimSpace(attestation.AttestationID) == "" ||
		strings.TrimSpace(attestation.Source) == "" ||
		strings.TrimSpace(attestation.EvidenceDigest) == "" ||
		strings.TrimSpace(attestation.Subject) == "" ||
		strings.TrimSpace(attestation.LeaseID) == "" ||
		strings.TrimSpace(attestation.ReceiptID) == "" ||
		strings.TrimSpace(attestation.ContractDigest) == "" ||
		strings.TrimSpace(attestation.WorkloadProfileDigest) == "" ||
		strings.TrimSpace(attestation.Metric) == "" ||
		strings.TrimSpace(attestation.Unit) == "" ||
		attestation.StartedAt.IsZero() ||
		attestation.FinishedAt.IsZero() ||
		attestation.MeasuredAt.IsZero() {
		return errors.New("workload measurement attestation is incomplete")
	}
	if !attestation.StartedAt.Before(attestation.FinishedAt) ||
		attestation.MeasuredAt.Before(attestation.FinishedAt) {
		return errors.New("workload measurement attestation time ordering is invalid")
	}
	return nil
}

func canonicalWorkloadMeasurementAttestationPayload(
	attestation WorkloadMeasurementAttestation,
) ([]byte, error) {
	normalized := attestation
	normalized.StartedAt = normalized.StartedAt.UTC()
	normalized.FinishedAt = normalized.FinishedAt.UTC()
	normalized.MeasuredAt = normalized.MeasuredAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal workload measurement attestation: %w", err)
	}
	return append([]byte("aegis.compute/workload-measurement-attestation/v0\x00"), body...), nil
}
