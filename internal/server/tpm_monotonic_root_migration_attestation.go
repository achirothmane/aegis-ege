package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const TPMRootMigrationDestinationAttestationVersion = "aegis.ege/tpm-root-migration-destination-attestation/v1"

var ErrTPMRootMigrationDestinationAttestation = errors.New("TPM root migration destination attestation is invalid")

type TPMRootMigrationDestinationAttestation struct {
	Version                         string    `json:"version"`
	AttestationID                   string    `json:"attestation_id"`
	MigrationID                     string    `json:"migration_id"`
	EnrolledDeviceID                string    `json:"enrolled_device_id"`
	DestinationDeviceIdentity       string    `json:"destination_device_identity"`
	DestinationMeasuredBootIdentity string    `json:"destination_measured_boot_identity"`
	RemoteDecisionDigest            string    `json:"remote_decision_digest"`
	Decision                        string    `json:"decision"`
	VerifiedAt                      time.Time `json:"verified_at"`
	ExpiresAt                       time.Time `json:"expires_at"`
	VerifierID                      string    `json:"verifier_id"`
}

type SignedTPMRootMigrationDestinationAttestation struct {
	Attestation TPMRootMigrationDestinationAttestation `json:"attestation"`
	KeyID       string                                 `json:"key_id"`
	Signature   string                                 `json:"signature"`
}

func ValidateTPMRootMigrationDestinationAttestation(att TPMRootMigrationDestinationAttestation) error {
	if att.Version != TPMRootMigrationDestinationAttestationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTPMRootMigrationDestinationAttestation, att.Version)
	}
	if strings.TrimSpace(att.AttestationID) == "" ||
		strings.TrimSpace(att.MigrationID) == "" ||
		strings.TrimSpace(att.EnrolledDeviceID) == "" ||
		strings.TrimSpace(att.VerifierID) == "" {
		return fmt.Errorf("%w: identity fields are required", ErrTPMRootMigrationDestinationAttestation)
	}
	if !validSHA256Ref(att.DestinationDeviceIdentity) ||
		!validSHA256Ref(att.DestinationMeasuredBootIdentity) ||
		!validSHA256Ref(att.RemoteDecisionDigest) {
		return fmt.Errorf("%w: digest binding is invalid", ErrTPMRootMigrationDestinationAttestation)
	}
	if att.Decision != "ALLOW" {
		return fmt.Errorf("%w: destination decision must be ALLOW", ErrTPMRootMigrationDestinationAttestation)
	}
	if att.VerifiedAt.IsZero() || att.ExpiresAt.IsZero() || !att.ExpiresAt.After(att.VerifiedAt) {
		return fmt.Errorf("%w: validity window is invalid", ErrTPMRootMigrationDestinationAttestation)
	}
	return nil
}

func SignTPMRootMigrationDestinationAttestation(
	att TPMRootMigrationDestinationAttestation,
	privateKey ed25519.PrivateKey,
) (SignedTPMRootMigrationDestinationAttestation, error) {
	if err := ValidateTPMRootMigrationDestinationAttestation(att); err != nil {
		return SignedTPMRootMigrationDestinationAttestation{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTPMRootMigrationDestinationAttestation{}, fmt.Errorf("%w: invalid Ed25519 verifier key", ErrTPMRootMigrationDestinationAttestation)
	}
	payload, err := canonicalTPMRootMigrationDestinationAttestationPayload(att)
	if err != nil {
		return SignedTPMRootMigrationDestinationAttestation{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedTPMRootMigrationDestinationAttestation{
		Attestation: att,
		KeyID:       tpmRootMigrationKeyID(publicKey),
		Signature:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTPMRootMigrationDestinationAttestation(
	signed SignedTPMRootMigrationDestinationAttestation,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := ValidateTPMRootMigrationDestinationAttestation(signed.Attestation); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 verifier public key", ErrTPMRootMigrationDestinationAttestation)
	}
	if signed.KeyID != tpmRootMigrationKeyID(publicKey) {
		return fmt.Errorf("%w: verifier key mismatch", ErrTPMRootMigrationDestinationAttestation)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrTPMRootMigrationDestinationAttestation)
	}
	payload, err := canonicalTPMRootMigrationDestinationAttestationPayload(signed.Attestation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("%w: signature verification failed", ErrTPMRootMigrationDestinationAttestation)
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Attestation.VerifiedAt.UTC()) || !now.Before(signed.Attestation.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: attestation is outside its validity window", ErrTPMRootMigrationDestinationAttestation)
	}
	return nil
}

func TPMRootMigrationDestinationAttestationDigest(
	signed SignedTPMRootMigrationDestinationAttestation,
) (string, error) {
	payload, err := canonicalTPMRootMigrationDestinationAttestationPayload(signed.Attestation)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		Payload   []byte `json:"payload"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{
		Payload: payload, KeyID: signed.KeyID, Signature: signed.Signature,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/tpm-root-migration-destination-attestation-commitment/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalTPMRootMigrationDestinationAttestationPayload(
	att TPMRootMigrationDestinationAttestation,
) ([]byte, error) {
	att.AttestationID = strings.TrimSpace(att.AttestationID)
	att.MigrationID = strings.TrimSpace(att.MigrationID)
	att.EnrolledDeviceID = strings.TrimSpace(att.EnrolledDeviceID)
	att.DestinationDeviceIdentity = strings.TrimSpace(att.DestinationDeviceIdentity)
	att.DestinationMeasuredBootIdentity = strings.TrimSpace(att.DestinationMeasuredBootIdentity)
	att.RemoteDecisionDigest = strings.TrimSpace(att.RemoteDecisionDigest)
	att.Decision = strings.TrimSpace(att.Decision)
	att.VerifierID = strings.TrimSpace(att.VerifierID)
	att.VerifiedAt = att.VerifiedAt.UTC()
	att.ExpiresAt = att.ExpiresAt.UTC()
	body, err := json.Marshal(att)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/tpm-root-migration-destination-attestation/v1\x00"), body...), nil
}
