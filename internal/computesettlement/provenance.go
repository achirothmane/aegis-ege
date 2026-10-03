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

const (
	WorkloadExecutionProvenanceVersion = "aegis.compute/workload-execution-provenance/v0"
	MeasurementExecutionBindingVersion = "aegis.compute/measurement-execution-binding/v0"
)

// TrustedExecutionRoot is the runtime-owned execution identity that the compute
// adapter must obtain from a trust path distinct from the performance
// measurement authority.
//
// In a production adapter these digests can be derived from Aegis workload
// activation/runtime-trust evidence, process identity, cgroup identity, and
// boot/IMA measurements. The settlement layer treats them as opaque commitments.
type TrustedExecutionRoot struct {
	ActivationReceiptDigest string `json:"activation_receipt_digest"`
	ProcessIdentityDigest    string `json:"process_identity_digest"`
	CgroupIdentityDigest     string `json:"cgroup_identity_digest"`
	BootMeasurementDigest    string `json:"boot_measurement_digest"`
}

type WorkloadExecutionProvenance struct {
	Version                    string    `json:"version"`
	ProvenanceID               string    `json:"provenance_id"`
	Subject                    string    `json:"subject"`
	LeaseID                    string    `json:"lease_id"`
	ReceiptID                  string    `json:"receipt_id"`
	ContractDigest             string    `json:"contract_digest"`
	WorkloadProfileDigest      string    `json:"workload_profile_digest"`
	ExecutableArtifactDigest   string    `json:"executable_artifact_digest"`
	ActivationReceiptDigest    string    `json:"activation_receipt_digest"`
	ProcessIdentityDigest      string    `json:"process_identity_digest"`
	CgroupIdentityDigest       string    `json:"cgroup_identity_digest"`
	BootMeasurementDigest      string    `json:"boot_measurement_digest"`
	HardwareAttestationDigest  string    `json:"hardware_attestation_digest"`
	ObservedAt                 time.Time `json:"observed_at"`
}

type SignedWorkloadExecutionProvenance struct {
	Provenance WorkloadExecutionProvenance `json:"provenance"`
	KeyID      string                      `json:"key_id"`
	Signature  string                      `json:"signature"`
}

// MeasurementExecutionBinding is signed by the execution-provenance authority,
// not by the performance measurement source. It binds one already-signed VCS-06
// measurement to the trusted execution lineage.
type MeasurementExecutionBinding struct {
	Version                      string    `json:"version"`
	BindingID                    string    `json:"binding_id"`
	Source                       string    `json:"source"`
	MeasurementAttestationDigest string    `json:"measurement_attestation_digest"`
	ExecutionProvenanceDigest    string    `json:"execution_provenance_digest"`
	EvidenceDigest               string    `json:"evidence_digest"`
	LeaseID                      string    `json:"lease_id"`
	ReceiptID                    string    `json:"receipt_id"`
	BoundAt                      time.Time `json:"bound_at"`
}

type SignedMeasurementExecutionBinding struct {
	Binding   MeasurementExecutionBinding `json:"binding"`
	KeyID     string                      `json:"key_id"`
	Signature string                      `json:"signature"`
}

type WorkloadRootedPerformanceReconciliation struct {
	WorkloadBoundPerformanceReconciliation
	ExecutionRootEstablished       bool
	ExecutionProvenanceDigest      string
	MeasurementExecutionBindings  map[string]string
}

func SignWorkloadExecutionProvenance(
	ctx context.Context,
	authority egeproto.PermitAuthority,
	provenance WorkloadExecutionProvenance,
) (SignedWorkloadExecutionProvenance, error) {
	if authority == nil {
		return SignedWorkloadExecutionProvenance{}, errors.New("workload execution provenance authority is required")
	}
	if err := validateWorkloadExecutionProvenance(provenance); err != nil {
		return SignedWorkloadExecutionProvenance{}, err
	}
	payload, err := canonicalWorkloadExecutionProvenancePayload(provenance)
	if err != nil {
		return SignedWorkloadExecutionProvenance{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return SignedWorkloadExecutionProvenance{}, fmt.Errorf("sign workload execution provenance: %w", err)
	}
	return SignedWorkloadExecutionProvenance{
		Provenance: provenance,
		KeyID:      keyID,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyWorkloadExecutionProvenance(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	signed SignedWorkloadExecutionProvenance,
) error {
	if verifier == nil {
		return errors.New("workload execution provenance verifier is required")
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return errors.New("workload execution provenance key id and signature are required")
	}
	if err := validateWorkloadExecutionProvenance(signed.Provenance); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode workload execution provenance signature: %w", err)
	}
	payload, err := canonicalWorkloadExecutionProvenancePayload(signed.Provenance)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, signed.KeyID, payload, signature); err != nil {
		return fmt.Errorf("verify workload execution provenance: %w", err)
	}
	return nil
}

func WorkloadExecutionProvenanceDigest(
	signed SignedWorkloadExecutionProvenance,
) (string, error) {
	if err := validateWorkloadExecutionProvenance(signed.Provenance); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed workload execution provenance is incomplete")
	}
	normalized := signed
	normalized.Provenance.ObservedAt = normalized.Provenance.ObservedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal signed workload execution provenance: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/signed-workload-execution-provenance/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignMeasurementExecutionBinding(
	ctx context.Context,
	authority egeproto.PermitAuthority,
	binding MeasurementExecutionBinding,
) (SignedMeasurementExecutionBinding, error) {
	if authority == nil {
		return SignedMeasurementExecutionBinding{}, errors.New("measurement execution binding authority is required")
	}
	if err := validateMeasurementExecutionBinding(binding); err != nil {
		return SignedMeasurementExecutionBinding{}, err
	}
	payload, err := canonicalMeasurementExecutionBindingPayload(binding)
	if err != nil {
		return SignedMeasurementExecutionBinding{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return SignedMeasurementExecutionBinding{}, fmt.Errorf("sign measurement execution binding: %w", err)
	}
	return SignedMeasurementExecutionBinding{
		Binding:   binding,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyMeasurementExecutionBinding(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	signed SignedMeasurementExecutionBinding,
) error {
	if verifier == nil {
		return errors.New("measurement execution binding verifier is required")
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return errors.New("measurement execution binding key id and signature are required")
	}
	if err := validateMeasurementExecutionBinding(signed.Binding); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode measurement execution binding signature: %w", err)
	}
	payload, err := canonicalMeasurementExecutionBindingPayload(signed.Binding)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, signed.KeyID, payload, signature); err != nil {
		return fmt.Errorf("verify measurement execution binding: %w", err)
	}
	return nil
}

func MeasurementExecutionBindingDigest(
	signed SignedMeasurementExecutionBinding,
) (string, error) {
	if err := validateMeasurementExecutionBinding(signed.Binding); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed measurement execution binding is incomplete")
	}
	normalized := signed
	normalized.Binding.BoundAt = normalized.Binding.BoundAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal signed measurement execution binding: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/signed-measurement-execution-binding/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ReconcileWorkloadRootedPerformance extends VCS-06 with an execution root that
// is verified by a provenance authority independent of the performance
// measurement authorities.
//
// A measurement is commercially usable only if:
//   1. VCS-06 binds it to the exact contracted workload profile;
//   2. trusted runtime execution-root commitments match;
//   3. a signed execution provenance statement binds those commitments to the
//      same lease/receipt/profile/hardware lineage;
//   4. the provenance authority separately binds each signed measurement digest
//      to that exact execution provenance digest.
//
// This prevents a performance signer, acting alone, from manufacturing a
// workload identity that the runtime provenance path did not observe.
func ReconcileWorkloadRootedPerformance(
	ctx context.Context,
	hardwareVerifier egeproto.SignatureVerifier,
	measurementVerifiers map[string]egeproto.SignatureVerifier,
	provenanceVerifier egeproto.SignatureVerifier,
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
	expectedRoot TrustedExecutionRoot,
	executionProvenance SignedWorkloadExecutionProvenance,
	measurementBindings []SignedMeasurementExecutionBinding,
) WorkloadRootedPerformanceReconciliation {
	base := ReconcileWorkloadBoundPerformance(
		ctx,
		hardwareVerifier,
		measurementVerifiers,
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
		expectedProfile,
		measurementAttestations,
	)
	result := WorkloadRootedPerformanceReconciliation{
		WorkloadBoundPerformanceReconciliation: base,
		MeasurementExecutionBindings:           map[string]string{},
	}

	// If workload binding was not established, a later provenance layer must not
	// overwrite the prior conservative disposition.
	if !base.WorkloadBindingEstablished {
		return result
	}

	fail := func(detail string) WorkloadRootedPerformanceReconciliation {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "workload execution provenance: " + detail,
		}
		result.ExecutionRootEstablished = false
		return result
	}

	if err := validateTrustedExecutionRoot(expectedRoot); err != nil {
		return fail(err.Error())
	}
	if err := VerifyWorkloadExecutionProvenance(ctx, provenanceVerifier, executionProvenance); err != nil {
		return fail("execution provenance invalid: " + err.Error())
	}

	profileDigest, err := WorkloadPerformanceProfileDigest(expectedProfile)
	if err != nil {
		return fail(err.Error())
	}
	completionDigest, err := HardwareIdentityAttestationDigest(completion)
	if err != nil {
		return fail("completion hardware attestation digest: " + err.Error())
	}

	provenance := executionProvenance.Provenance
	if provenance.Subject != lease.Subject ||
		provenance.LeaseID != lease.LeaseID ||
		provenance.ReceiptID != receipt.ReceiptID ||
		provenance.ContractDigest != lease.ContractDigest {
		return fail("execution provenance does not bind the admitted execution")
	}
	if provenance.WorkloadProfileDigest != profileDigest {
		return fail("execution provenance workload profile differs from contracted profile")
	}
	if provenance.ExecutableArtifactDigest != expectedProfile.ArtifactDigest {
		return fail("runtime executable artifact differs from contracted artifact")
	}
	if provenance.ActivationReceiptDigest != expectedRoot.ActivationReceiptDigest ||
		provenance.ProcessIdentityDigest != expectedRoot.ProcessIdentityDigest ||
		provenance.CgroupIdentityDigest != expectedRoot.CgroupIdentityDigest ||
		provenance.BootMeasurementDigest != expectedRoot.BootMeasurementDigest {
		return fail("execution provenance differs from trusted runtime execution root")
	}
	if provenance.HardwareAttestationDigest != completionDigest {
		return fail("execution provenance is not bound to the current hardware attestation")
	}
	if provenance.ObservedAt.Before(receipt.StartedAt) ||
		provenance.ObservedAt.After(receipt.FinishedAt) {
		return fail("execution provenance observation falls outside execution interval")
	}

	provenanceDigest, err := WorkloadExecutionProvenanceDigest(executionProvenance)
	if err != nil {
		return fail("digest execution provenance: " + err.Error())
	}
	result.ExecutionProvenanceDigest = provenanceDigest

	measurementBySource := make(map[string]SignedWorkloadMeasurementAttestation, len(measurementAttestations))
	measurementDigestBySource := make(map[string]string, len(measurementAttestations))
	for _, measurement := range measurementAttestations {
		source := strings.TrimSpace(measurement.Attestation.Source)
		if source == "" {
			return fail("measurement source is required")
		}
		if _, duplicate := measurementBySource[source]; duplicate {
			return fail("measurement source is duplicated")
		}
		digest, err := WorkloadMeasurementAttestationDigest(measurement)
		if err != nil {
			return fail("digest workload measurement attestation: " + err.Error())
		}
		measurementBySource[source] = measurement
		measurementDigestBySource[source] = digest
	}

	if len(measurementBindings) != len(measurementAttestations) {
		return fail("every workload measurement requires one execution binding")
	}

	seenBindings := make(map[string]struct{}, len(measurementBindings))
	for _, signedBinding := range measurementBindings {
		if err := VerifyMeasurementExecutionBinding(ctx, provenanceVerifier, signedBinding); err != nil {
			return fail("measurement execution binding invalid: " + err.Error())
		}
		binding := signedBinding.Binding
		source := strings.TrimSpace(binding.Source)
		if _, duplicate := seenBindings[source]; duplicate {
			return fail("measurement execution binding source is duplicated")
		}
		seenBindings[source] = struct{}{}

		measurement, ok := measurementBySource[source]
		if !ok {
			return fail("measurement execution binding has no signed workload measurement")
		}
		if binding.MeasurementAttestationDigest != measurementDigestBySource[source] {
			return fail("measurement execution binding does not bind the current signed measurement")
		}
		if binding.ExecutionProvenanceDigest != provenanceDigest {
			return fail("measurement execution binding references different execution provenance")
		}
		if binding.EvidenceDigest != measurement.Attestation.EvidenceDigest {
			return fail("measurement execution binding evidence digest differs from signed measurement")
		}
		if binding.LeaseID != lease.LeaseID || binding.ReceiptID != receipt.ReceiptID {
			return fail("measurement execution binding does not bind the current execution")
		}
		if binding.BoundAt.Before(provenance.ObservedAt) {
			return fail("measurement execution binding predates execution provenance observation")
		}

		digest, err := MeasurementExecutionBindingDigest(signedBinding)
		if err != nil {
			return fail("digest measurement execution binding: " + err.Error())
		}
		result.MeasurementExecutionBindings[source] = digest
	}

	result.ExecutionRootEstablished = true
	return result
}

func validateTrustedExecutionRoot(root TrustedExecutionRoot) error {
	if strings.TrimSpace(root.ActivationReceiptDigest) == "" ||
		strings.TrimSpace(root.ProcessIdentityDigest) == "" ||
		strings.TrimSpace(root.CgroupIdentityDigest) == "" ||
		strings.TrimSpace(root.BootMeasurementDigest) == "" {
		return errors.New("trusted execution root is incomplete")
	}
	return nil
}

func validateWorkloadExecutionProvenance(provenance WorkloadExecutionProvenance) error {
	if provenance.Version != WorkloadExecutionProvenanceVersion {
		return fmt.Errorf("unsupported workload execution provenance version %q", provenance.Version)
	}
	if strings.TrimSpace(provenance.ProvenanceID) == "" ||
		strings.TrimSpace(provenance.Subject) == "" ||
		strings.TrimSpace(provenance.LeaseID) == "" ||
		strings.TrimSpace(provenance.ReceiptID) == "" ||
		strings.TrimSpace(provenance.ContractDigest) == "" ||
		strings.TrimSpace(provenance.WorkloadProfileDigest) == "" ||
		strings.TrimSpace(provenance.ExecutableArtifactDigest) == "" ||
		strings.TrimSpace(provenance.ActivationReceiptDigest) == "" ||
		strings.TrimSpace(provenance.ProcessIdentityDigest) == "" ||
		strings.TrimSpace(provenance.CgroupIdentityDigest) == "" ||
		strings.TrimSpace(provenance.BootMeasurementDigest) == "" ||
		strings.TrimSpace(provenance.HardwareAttestationDigest) == "" ||
		provenance.ObservedAt.IsZero() {
		return errors.New("workload execution provenance is incomplete")
	}
	return nil
}

func validateMeasurementExecutionBinding(binding MeasurementExecutionBinding) error {
	if binding.Version != MeasurementExecutionBindingVersion {
		return fmt.Errorf("unsupported measurement execution binding version %q", binding.Version)
	}
	if strings.TrimSpace(binding.BindingID) == "" ||
		strings.TrimSpace(binding.Source) == "" ||
		strings.TrimSpace(binding.MeasurementAttestationDigest) == "" ||
		strings.TrimSpace(binding.ExecutionProvenanceDigest) == "" ||
		strings.TrimSpace(binding.EvidenceDigest) == "" ||
		strings.TrimSpace(binding.LeaseID) == "" ||
		strings.TrimSpace(binding.ReceiptID) == "" ||
		binding.BoundAt.IsZero() {
		return errors.New("measurement execution binding is incomplete")
	}
	return nil
}

func canonicalWorkloadExecutionProvenancePayload(
	provenance WorkloadExecutionProvenance,
) ([]byte, error) {
	normalized := provenance
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal workload execution provenance: %w", err)
	}
	return append([]byte("aegis.compute/workload-execution-provenance/v0\x00"), body...), nil
}

func canonicalMeasurementExecutionBindingPayload(
	binding MeasurementExecutionBinding,
) ([]byte, error) {
	normalized := binding
	normalized.BoundAt = normalized.BoundAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal measurement execution binding: %w", err)
	}
	return append([]byte("aegis.compute/measurement-execution-binding/v0\x00"), body...), nil
}
