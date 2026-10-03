package kernelfabric

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

const EnrollmentIdentitySuccessorAuthorizationVersion = "aegis.ege/enrollment-identity-successor-authorization/v1"

var (
	ErrEnrollmentIdentitySuccessorAuthorization = errors.New("enrollment identity successor authorization is invalid")
	ErrEnrollmentIdentitySuccessorSignature     = errors.New("enrollment identity successor authorization signature is invalid")
)

type EnrollmentIdentitySuccessorAuthorization struct {
	Version                              string    `json:"version"`
	AuthorizationID                      string    `json:"authorization_id"`
	DeviceID                             string    `json:"device_id"`
	PredecessorReceiptDigest             string    `json:"predecessor_receipt_digest"`
	PredecessorSequence                  uint64    `json:"predecessor_sequence"`
	PredecessorHardwareIdentityDigest    string    `json:"predecessor_hardware_identity_digest"`
	SuccessorEnrollmentID                string    `json:"successor_enrollment_id"`
	SuccessorEnrollmentRequestDigest     string    `json:"successor_enrollment_request_digest"`
	SuccessorHardwareIdentityDigest      string    `json:"successor_hardware_identity_digest"`
	ContinuityTransferAuthorizationDigest string  `json:"continuity_transfer_authorization_digest"`
	DestinationAttestationDigest         string    `json:"destination_attestation_digest"`
	SourceDeviceIdentity                 string    `json:"source_device_identity"`
	DestinationDeviceIdentity            string    `json:"destination_device_identity"`
	DestinationMeasuredBootIdentity      string    `json:"destination_measured_boot_identity"`
	DestinationGeneration                uint64    `json:"destination_generation"`
	HistoryWitnessPolicyHash             string    `json:"history_witness_policy_hash"`
	OwnershipWitnessPolicyHash           string    `json:"ownership_witness_policy_hash"`
	NotBefore                            time.Time `json:"not_before"`
	ExpiresAt                            time.Time `json:"expires_at"`
}

type SignedEnrollmentIdentitySuccessorAuthorization struct {
	Authorization EnrollmentIdentitySuccessorAuthorization `json:"authorization"`
	KeyID         string                                   `json:"key_id"`
	Signature     string                                   `json:"signature"`
}

func ValidateEnrollmentIdentitySuccessorAuthorization(
	auth EnrollmentIdentitySuccessorAuthorization,
) error {
	if auth.Version != EnrollmentIdentitySuccessorAuthorizationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrEnrollmentIdentitySuccessorAuthorization, auth.Version)
	}
	if strings.TrimSpace(auth.AuthorizationID) == "" ||
		strings.TrimSpace(auth.DeviceID) == "" ||
		strings.TrimSpace(auth.SuccessorEnrollmentID) == "" {
		return fmt.Errorf("%w: authorization, device, and successor enrollment ids are required", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	if auth.PredecessorSequence == 0 || auth.DestinationGeneration == 0 {
		return fmt.Errorf("%w: predecessor sequence and destination generation must be non-zero", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	for label, digest := range map[string]string{
		"predecessor receipt":             auth.PredecessorReceiptDigest,
		"predecessor hardware identity":   auth.PredecessorHardwareIdentityDigest,
		"successor enrollment request":    auth.SuccessorEnrollmentRequestDigest,
		"successor hardware identity":     auth.SuccessorHardwareIdentityDigest,
		"continuity transfer authorization": auth.ContinuityTransferAuthorizationDigest,
		"destination attestation":         auth.DestinationAttestationDigest,
		"source device identity":          auth.SourceDeviceIdentity,
		"destination device identity":     auth.DestinationDeviceIdentity,
		"destination measured boot":       auth.DestinationMeasuredBootIdentity,
		"history witness policy":          auth.HistoryWitnessPolicyHash,
		"ownership witness policy":        auth.OwnershipWitnessPolicyHash,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%w: %s digest: %v", ErrEnrollmentIdentitySuccessorAuthorization, label, err)
		}
	}
	if auth.PredecessorHardwareIdentityDigest == auth.SuccessorHardwareIdentityDigest {
		return fmt.Errorf("%w: successor hardware identity must differ from predecessor", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	if auth.SourceDeviceIdentity == auth.DestinationDeviceIdentity {
		return fmt.Errorf("%w: source and destination TPM device identities must differ", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	if auth.NotBefore.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.NotBefore) {
		return fmt.Errorf("%w: validity window is invalid", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	return nil
}

func SignEnrollmentIdentitySuccessorAuthorization(
	auth EnrollmentIdentitySuccessorAuthorization,
	privateKey ed25519.PrivateKey,
) (SignedEnrollmentIdentitySuccessorAuthorization, error) {
	if err := ValidateEnrollmentIdentitySuccessorAuthorization(auth); err != nil {
		return SignedEnrollmentIdentitySuccessorAuthorization{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedEnrollmentIdentitySuccessorAuthorization{}, errors.New("invalid enrollment successor governance Ed25519 private key")
	}
	payload, err := canonicalEnrollmentIdentitySuccessorAuthorizationPayload(auth)
	if err != nil {
		return SignedEnrollmentIdentitySuccessorAuthorization{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := enrollmentSuccessorGovernanceKeyID(publicKey)
	if err != nil {
		return SignedEnrollmentIdentitySuccessorAuthorization{}, err
	}
	return SignedEnrollmentIdentitySuccessorAuthorization{
		Authorization: auth,
		KeyID:         keyID,
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedEnrollmentIdentitySuccessorAuthorization(
	signed SignedEnrollmentIdentitySuccessorAuthorization,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := ValidateEnrollmentIdentitySuccessorAuthorization(signed.Authorization); err != nil {
		return err
	}
	keyID, err := enrollmentSuccessorGovernanceKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return ErrEnrollmentIdentitySuccessorSignature
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrEnrollmentIdentitySuccessorSignature
	}
	payload, err := canonicalEnrollmentIdentitySuccessorAuthorizationPayload(signed.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrEnrollmentIdentitySuccessorSignature
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Authorization.NotBefore.UTC()) ||
		!now.Before(signed.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrEnrollmentIdentitySuccessorAuthorization)
	}
	return nil
}

func EnrollmentIdentitySuccessorAuthorizationDigest(
	signed SignedEnrollmentIdentitySuccessorAuthorization,
) (string, error) {
	if err := ValidateEnrollmentIdentitySuccessorAuthorization(signed.Authorization); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", ErrEnrollmentIdentitySuccessorSignature
	}
	payload, err := canonicalEnrollmentIdentitySuccessorAuthorizationPayload(signed.Authorization)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		Payload   []byte `json:"payload"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{
		Payload: payload,
		KeyID: signed.KeyID,
		Signature: signed.Signature,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis.ege/signed-enrollment-identity-successor-authorization/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalEnrollmentIdentitySuccessorAuthorizationPayload(
	auth EnrollmentIdentitySuccessorAuthorization,
) ([]byte, error) {
	normalized := auth
	normalized.AuthorizationID = strings.TrimSpace(normalized.AuthorizationID)
	normalized.DeviceID = strings.TrimSpace(normalized.DeviceID)
	normalized.SuccessorEnrollmentID = strings.TrimSpace(normalized.SuccessorEnrollmentID)
	normalized.NotBefore = normalized.NotBefore.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis.ege/enrollment-identity-successor-authorization/v1\x00"), body...), nil
}

func enrollmentSuccessorGovernanceKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid enrollment successor governance Ed25519 public key")
	}
	sum := sha256.Sum256(append([]byte("aegis.ege/enrollment-successor-governance-key/v1\x00"), publicKey...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
