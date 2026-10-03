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

const HardwareIdentityAttestationVersion = "aegis.compute/hardware-identity-attestation/v0"

type HardwareIdentityAttestation struct {
	Version           string    `json:"version"`
	AttestationID     string    `json:"attestation_id"`
	Sequence          uint64    `json:"sequence"`
	Subject           string    `json:"subject"`
	HardwareSetDigest string    `json:"hardware_set_digest"`
	TopologyDigest    string    `json:"topology_digest"`
	EvidenceDigest    string    `json:"evidence_digest"`
	VerifierID        string    `json:"verifier_id"`
	ObservedAt        time.Time `json:"observed_at"`
	ValidUntil        time.Time `json:"valid_until"`
}

type SignedHardwareIdentityAttestation struct {
	Attestation HardwareIdentityAttestation `json:"attestation"`
	KeyID       string                      `json:"key_id"`
	Signature   string                      `json:"signature"`
}

// HardwareLeaseBinding is the immutable compute identity admitted for one
// execution lease. Hardware and topology are opaque digests owned by the
// compute adapter, not interpreted by the governance kernel.
type HardwareLeaseBinding struct {
	LeaseID                    string    `json:"lease_id"`
	Subject                    string    `json:"subject"`
	ContractDigest             string    `json:"contract_digest"`
	HardwareSetDigest          string    `json:"hardware_set_digest"`
	TopologyDigest             string    `json:"topology_digest"`
	AdmissionAttestationDigest string    `json:"admission_attestation_digest"`
	StartsAt                   time.Time `json:"starts_at"`
	EndsAt                     time.Time `json:"ends_at"`
}

// ComputeExecutionReceipt binds the claimed execution to the exact admitted
// lease and the hardware observations used at admission and completion.
type ComputeExecutionReceipt struct {
	ReceiptID                   string    `json:"receipt_id"`
	LeaseID                     string    `json:"lease_id"`
	ContractDigest              string    `json:"contract_digest"`
	HardwareSetDigest           string    `json:"hardware_set_digest"`
	TopologyDigest              string    `json:"topology_digest"`
	AdmissionAttestationDigest  string    `json:"admission_attestation_digest"`
	CompletionAttestationDigest string    `json:"completion_attestation_digest"`
	StartedAt                   time.Time `json:"started_at"`
	FinishedAt                  time.Time `json:"finished_at"`
}

type HardwareContinuityPolicy struct {
	MaxAdmissionAge       time.Duration
	MaxCompletionProbeLag time.Duration
}

type AttestedEvidenceReconciliation struct {
	EvidenceBoundReconciliation
	HardwareContinuityEstablished bool
	AdmissionAttestationDigest    string
	CompletionAttestationDigest   string
}

func SignHardwareIdentityAttestation(
	ctx context.Context,
	authority egeproto.PermitAuthority,
	attestation HardwareIdentityAttestation,
) (SignedHardwareIdentityAttestation, error) {
	if authority == nil {
		return SignedHardwareIdentityAttestation{}, errors.New("hardware attestation authority is required")
	}
	if err := validateHardwareIdentityAttestation(attestation); err != nil {
		return SignedHardwareIdentityAttestation{}, err
	}
	payload, err := canonicalHardwareIdentityAttestationPayload(attestation)
	if err != nil {
		return SignedHardwareIdentityAttestation{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return SignedHardwareIdentityAttestation{}, fmt.Errorf("sign hardware identity attestation: %w", err)
	}
	return SignedHardwareIdentityAttestation{
		Attestation: attestation,
		KeyID:       keyID,
		Signature:   base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyHardwareIdentityAttestation(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	signed SignedHardwareIdentityAttestation,
) error {
	if verifier == nil {
		return errors.New("hardware attestation verifier is required")
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return errors.New("hardware attestation key id and signature are required")
	}
	if err := validateHardwareIdentityAttestation(signed.Attestation); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode hardware attestation signature: %w", err)
	}
	payload, err := canonicalHardwareIdentityAttestationPayload(signed.Attestation)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, signed.KeyID, payload, signature); err != nil {
		return fmt.Errorf("verify hardware identity attestation: %w", err)
	}
	return nil
}

func HardwareIdentityAttestationDigest(
	signed SignedHardwareIdentityAttestation,
) (string, error) {
	if err := validateHardwareIdentityAttestation(signed.Attestation); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed hardware attestation is incomplete")
	}
	normalized := signed
	normalized.Attestation.ObservedAt = normalized.Attestation.ObservedAt.UTC()
	normalized.Attestation.ValidUntil = normalized.Attestation.ValidUntil.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal signed hardware attestation: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/signed-hardware-identity-attestation/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ReconcileAttestedExecution(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
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
) AttestedEvidenceReconciliation {
	base := ReconcileWithEvidence(
		actionID,
		planDigest,
		contractFacts,
		observations,
		sources,
		evidenceRequirement,
	)

	result := AttestedEvidenceReconciliation{
		EvidenceBoundReconciliation: base,
	}

	fail := func(detail string) AttestedEvidenceReconciliation {
		result.Reconciliation = Reconciliation{
			Disposition: Unknown,
			Detail:      "hardware continuity: " + detail,
		}
		result.HardwareContinuityEstablished = false
		return result
	}

	if err := validateHardwareLeaseBinding(lease); err != nil {
		return fail(err.Error())
	}
	if err := validateComputeExecutionReceipt(receipt); err != nil {
		return fail(err.Error())
	}
	if err := VerifyHardwareIdentityAttestation(ctx, verifier, admission); err != nil {
		return fail("admission attestation invalid: " + err.Error())
	}
	if err := VerifyHardwareIdentityAttestation(ctx, verifier, completion); err != nil {
		return fail("completion attestation invalid: " + err.Error())
	}

	admissionDigest, err := HardwareIdentityAttestationDigest(admission)
	if err != nil {
		return fail("digest admission attestation: " + err.Error())
	}
	completionDigest, err := HardwareIdentityAttestationDigest(completion)
	if err != nil {
		return fail("digest completion attestation: " + err.Error())
	}
	result.AdmissionAttestationDigest = admissionDigest
	result.CompletionAttestationDigest = completionDigest

	if receipt.LeaseID != lease.LeaseID ||
		receipt.ContractDigest != lease.ContractDigest {
		return fail("receipt does not bind the admitted lease and contract")
	}
	if receipt.HardwareSetDigest != lease.HardwareSetDigest ||
		receipt.TopologyDigest != lease.TopologyDigest {
		return fail("receipt hardware binding differs from the admitted lease")
	}
	if receipt.AdmissionAttestationDigest != lease.AdmissionAttestationDigest ||
		receipt.AdmissionAttestationDigest != admissionDigest {
		return fail("admission attestation binding changed")
	}
	if receipt.CompletionAttestationDigest != completionDigest {
		return fail("receipt does not bind the current completion attestation")
	}

	if receipt.StartedAt.Before(lease.StartsAt) ||
		receipt.FinishedAt.After(lease.EndsAt) ||
		receipt.FinishedAt.Before(receipt.StartedAt) {
		return fail("receipt execution interval falls outside the admitted lease")
	}

	start := admission.Attestation
	end := completion.Attestation
	if start.Subject != lease.Subject || end.Subject != lease.Subject {
		return fail("attestation subject changed")
	}
	if start.HardwareSetDigest != lease.HardwareSetDigest {
		return fail("admission hardware identity differs from the admitted lease")
	}
	if start.TopologyDigest != lease.TopologyDigest {
		return fail("admission topology differs from the admitted lease")
	}
	if end.HardwareSetDigest != lease.HardwareSetDigest {
		return fail("attested hardware identity changed before settlement")
	}
	if end.TopologyDigest != lease.TopologyDigest {
		return fail("attested topology changed before settlement")
	}
	if end.Sequence <= start.Sequence {
		return fail("completion attestation is not newer than admission attestation")
	}

	if start.ObservedAt.After(lease.StartsAt) || !lease.StartsAt.Before(start.ValidUntil) {
		return fail("admission attestation does not cover lease start")
	}
	if hardwarePolicy.MaxAdmissionAge > 0 &&
		lease.StartsAt.Sub(start.ObservedAt) > hardwarePolicy.MaxAdmissionAge {
		return fail("admission attestation is too old for lease start")
	}

	if end.ObservedAt.Before(receipt.FinishedAt) {
		return fail("completion attestation predates execution completion")
	}
	if !end.ObservedAt.Before(end.ValidUntil) {
		return fail("completion attestation validity window is empty")
	}
	if hardwarePolicy.MaxCompletionProbeLag > 0 &&
		end.ObservedAt.Sub(receipt.FinishedAt) > hardwarePolicy.MaxCompletionProbeLag {
		return fail("completion hardware observation is too far from execution completion")
	}

	result.HardwareContinuityEstablished = true
	return result
}

func validateHardwareIdentityAttestation(attestation HardwareIdentityAttestation) error {
	if attestation.Version != HardwareIdentityAttestationVersion {
		return fmt.Errorf("unsupported hardware attestation version %q", attestation.Version)
	}
	if strings.TrimSpace(attestation.AttestationID) == "" ||
		attestation.Sequence == 0 ||
		strings.TrimSpace(attestation.Subject) == "" ||
		strings.TrimSpace(attestation.HardwareSetDigest) == "" ||
		strings.TrimSpace(attestation.TopologyDigest) == "" ||
		strings.TrimSpace(attestation.EvidenceDigest) == "" ||
		strings.TrimSpace(attestation.VerifierID) == "" ||
		attestation.ObservedAt.IsZero() ||
		attestation.ValidUntil.IsZero() {
		return errors.New("hardware identity attestation is incomplete")
	}
	if !attestation.ObservedAt.Before(attestation.ValidUntil) {
		return errors.New("hardware identity attestation validity window is invalid")
	}
	return nil
}

func validateHardwareLeaseBinding(lease HardwareLeaseBinding) error {
	if strings.TrimSpace(lease.LeaseID) == "" ||
		strings.TrimSpace(lease.Subject) == "" ||
		strings.TrimSpace(lease.ContractDigest) == "" ||
		strings.TrimSpace(lease.HardwareSetDigest) == "" ||
		strings.TrimSpace(lease.TopologyDigest) == "" ||
		strings.TrimSpace(lease.AdmissionAttestationDigest) == "" ||
		lease.StartsAt.IsZero() ||
		lease.EndsAt.IsZero() {
		return errors.New("compute hardware lease binding is incomplete")
	}
	if !lease.StartsAt.Before(lease.EndsAt) {
		return errors.New("compute hardware lease interval is invalid")
	}
	return nil
}

func validateComputeExecutionReceipt(receipt ComputeExecutionReceipt) error {
	if strings.TrimSpace(receipt.ReceiptID) == "" ||
		strings.TrimSpace(receipt.LeaseID) == "" ||
		strings.TrimSpace(receipt.ContractDigest) == "" ||
		strings.TrimSpace(receipt.HardwareSetDigest) == "" ||
		strings.TrimSpace(receipt.TopologyDigest) == "" ||
		strings.TrimSpace(receipt.AdmissionAttestationDigest) == "" ||
		strings.TrimSpace(receipt.CompletionAttestationDigest) == "" ||
		receipt.StartedAt.IsZero() ||
		receipt.FinishedAt.IsZero() {
		return errors.New("compute execution receipt is incomplete")
	}
	return nil
}

func canonicalHardwareIdentityAttestationPayload(
	attestation HardwareIdentityAttestation,
) ([]byte, error) {
	normalized := attestation
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	normalized.ValidUntil = normalized.ValidUntil.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal hardware identity attestation: %w", err)
	}
	return append([]byte("aegis.compute/hardware-identity-attestation/v0\x00"), body...), nil
}
