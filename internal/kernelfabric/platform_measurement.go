package kernelfabric

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	PlatformMeasurementCommitmentVersion = "aegis.ege/platform-measurement-commitment/v1"
	PlatformMeasurementClassMeasuredBoot = "MEASURED_BOOT"
)

// PlatformMeasurementCommitment is a narrow, implementation-agnostic export of
// a platform measurement that has already been checked by its authoritative
// source.
//
// The consumer intentionally does not receive PCR numbers, TPM handles, event
// logs, firmware semantics, or device-specific implementation details.
type PlatformMeasurementCommitment struct {
	Version                string `json:"version"`
	EvidenceClass          string `json:"evidence_class"`
	CommitmentDigest       string `json:"commitment_digest"`
	PlatformIdentityDigest string `json:"platform_identity_digest"`
	VerifiedGeneration     uint64 `json:"verified_generation"`
}

// PlatformMeasurementSource exports the current verified platform measurement.
// Implementations are responsible for fail-closed freshness/rollback checks
// before returning a commitment.
type PlatformMeasurementSource interface {
	CurrentPlatformMeasurement(context.Context) (PlatformMeasurementCommitment, error)
}

// NewPlatformMeasurementCommitment seals an implementation-owned measurement
// identity behind a generic commitment.
//
// VerifiedGeneration is audit metadata proving which monotonic source state was
// checked. It is intentionally not included in CommitmentDigest so an unchanged
// platform measurement remains stable while unrelated monotonic state advances.
func NewPlatformMeasurementCommitment(
	evidenceClass string,
	platformIdentityDigest string,
	measurementIdentityDigest string,
	verifiedGeneration uint64,
) (PlatformMeasurementCommitment, error) {
	evidenceClass = strings.TrimSpace(evidenceClass)
	if evidenceClass == "" {
		return PlatformMeasurementCommitment{}, errors.New("platform measurement evidence class is required")
	}
	if _, err := ParseSHA256Digest(platformIdentityDigest); err != nil {
		return PlatformMeasurementCommitment{}, fmt.Errorf("platform identity digest: %w", err)
	}
	if _, err := ParseSHA256Digest(measurementIdentityDigest); err != nil {
		return PlatformMeasurementCommitment{}, fmt.Errorf("platform measurement identity digest: %w", err)
	}
	if verifiedGeneration == 0 {
		return PlatformMeasurementCommitment{}, errors.New("platform measurement verified generation must be non-zero")
	}

	h := sha256.New()
	_, _ = h.Write([]byte("aegis.ege/platform-measurement-commitment/v1\\x00"))
	_, _ = h.Write([]byte(evidenceClass))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(platformIdentityDigest))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(measurementIdentityDigest))

	commitment := PlatformMeasurementCommitment{
		Version:                PlatformMeasurementCommitmentVersion,
		EvidenceClass:          evidenceClass,
		CommitmentDigest:       "sha256:" + hex.EncodeToString(h.Sum(nil)),
		PlatformIdentityDigest: platformIdentityDigest,
		VerifiedGeneration:     verifiedGeneration,
	}
	if err := ValidatePlatformMeasurementCommitment(commitment); err != nil {
		return PlatformMeasurementCommitment{}, err
	}
	return commitment, nil
}

func ValidatePlatformMeasurementCommitment(commitment PlatformMeasurementCommitment) error {
	if commitment.Version != PlatformMeasurementCommitmentVersion {
		return fmt.Errorf("unsupported platform measurement commitment version %q", commitment.Version)
	}
	if strings.TrimSpace(commitment.EvidenceClass) == "" {
		return errors.New("platform measurement evidence class is required")
	}
	if _, err := ParseSHA256Digest(commitment.CommitmentDigest); err != nil {
		return fmt.Errorf("platform measurement commitment digest: %w", err)
	}
	if _, err := ParseSHA256Digest(commitment.PlatformIdentityDigest); err != nil {
		return fmt.Errorf("platform identity digest: %w", err)
	}
	if commitment.VerifiedGeneration == 0 {
		return errors.New("platform measurement verified generation must be non-zero")
	}
	return nil
}
