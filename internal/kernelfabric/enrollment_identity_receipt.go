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

const (
	EnrollmentIdentityReceiptVersion   = "aegis.ege/tpm-enrollment-identity-receipt/v1"
	EnrollmentIdentityReceiptVersionV2 = "aegis.ege/tpm-enrollment-identity-receipt/v2"
)

var (
	ErrEnrollmentIdentityReceiptInvalid   = errors.New("enrollment identity receipt is invalid")
	ErrEnrollmentIdentitySignatureInvalid = errors.New("enrollment identity receipt signature is invalid")
	ErrEnrollmentIdentityRollback         = errors.New("enrollment identity receipt rollback detected")
)

type EnrollmentIdentityReceipt struct {
	Version                      string    `json:"version"`
	ReceiptID                    string    `json:"receipt_id"`
	Sequence                     uint64    `json:"sequence"`
	PreviousReceiptDigest        string    `json:"previous_receipt_digest,omitempty"`
	SuccessorAuthorizationDigest string    `json:"successor_authorization_digest,omitempty"`
	DeviceID                     string    `json:"device_id"`
	EKSPKISHA256                 string    `json:"ek_spki_sha256"`
	EnrollmentIdentityDigest     string    `json:"enrollment_identity_digest"`
	EnrolledAt                   time.Time `json:"enrolled_at"`
	IssuedAt                     time.Time `json:"issued_at"`
}

type SignedEnrollmentIdentityReceipt struct {
	Receipt   EnrollmentIdentityReceipt `json:"receipt"`
	KeyID     string                    `json:"key_id"`
	Signature string                    `json:"signature"`
}

func EnrolledTPMIdentityDigest(identity EnrolledTPMIdentity) (string, error) {
	if err := validateEnrolledTPMIdentity(identity); err != nil {
		return "", err
	}
	normalized := identity
	normalized.EnrolledAt = normalized.EnrolledAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal enrolled TPM identity: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.ege/enrolled-tpm-identity/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func NewEnrollmentIdentityReceipt(
	receiptID string,
	sequence uint64,
	previousReceiptDigest string,
	identity EnrolledTPMIdentity,
	issuedAt time.Time,
) (EnrollmentIdentityReceipt, error) {
	return newEnrollmentIdentityReceipt(
		EnrollmentIdentityReceiptVersion,
		receiptID,
		sequence,
		previousReceiptDigest,
		"",
		identity,
		issuedAt,
	)
}

func NewGovernedEnrollmentIdentitySuccessorReceipt(
	receiptID string,
	sequence uint64,
	previousReceiptDigest string,
	successorAuthorizationDigest string,
	identity EnrolledTPMIdentity,
	issuedAt time.Time,
) (EnrollmentIdentityReceipt, error) {
	return newEnrollmentIdentityReceipt(
		EnrollmentIdentityReceiptVersionV2,
		receiptID,
		sequence,
		previousReceiptDigest,
		successorAuthorizationDigest,
		identity,
		issuedAt,
	)
}

func newEnrollmentIdentityReceipt(
	version string,
	receiptID string,
	sequence uint64,
	previousReceiptDigest string,
	successorAuthorizationDigest string,
	identity EnrolledTPMIdentity,
	issuedAt time.Time,
) (EnrollmentIdentityReceipt, error) {
	identityDigest, err := EnrolledTPMIdentityDigest(identity)
	if err != nil {
		return EnrollmentIdentityReceipt{}, err
	}
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	receipt := EnrollmentIdentityReceipt{
		Version:                      version,
		ReceiptID:                    strings.TrimSpace(receiptID),
		Sequence:                     sequence,
		PreviousReceiptDigest:        strings.TrimSpace(previousReceiptDigest),
		SuccessorAuthorizationDigest: strings.TrimSpace(successorAuthorizationDigest),
		DeviceID:                     identity.DeviceID,
		EKSPKISHA256:                 identity.EKSPKISHA256,
		EnrollmentIdentityDigest:     identityDigest,
		EnrolledAt:                   identity.EnrolledAt.UTC(),
		IssuedAt:                     issuedAt.UTC(),
	}
	if err := ValidateEnrollmentIdentityReceipt(receipt); err != nil {
		return EnrollmentIdentityReceipt{}, err
	}
	return receipt, nil
}

func SignEnrollmentIdentityReceipt(
	receipt EnrollmentIdentityReceipt,
	privateKey ed25519.PrivateKey,
) (SignedEnrollmentIdentityReceipt, error) {
	if err := ValidateEnrollmentIdentityReceipt(receipt); err != nil {
		return SignedEnrollmentIdentityReceipt{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedEnrollmentIdentityReceipt{}, errors.New("invalid enrollment authority Ed25519 private key")
	}
	payload, err := canonicalEnrollmentIdentityReceiptPayload(receipt)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := enrollmentAuthorityKeyID(publicKey)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, err
	}
	return SignedEnrollmentIdentityReceipt{
		Receipt:   receipt,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedEnrollmentIdentityReceipt(
	signed SignedEnrollmentIdentityReceipt,
	publicKey ed25519.PublicKey,
) error {
	if err := ValidateEnrollmentIdentityReceipt(signed.Receipt); err != nil {
		return err
	}
	expectedKeyID, err := enrollmentAuthorityKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != expectedKeyID {
		return ErrEnrollmentIdentitySignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrEnrollmentIdentitySignatureInvalid
	}
	payload, err := canonicalEnrollmentIdentityReceiptPayload(signed.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrEnrollmentIdentitySignatureInvalid
	}
	return nil
}

func EnrollmentIdentityReceiptDigest(
	signed SignedEnrollmentIdentityReceipt,
) (string, error) {
	if err := ValidateEnrollmentIdentityReceipt(signed.Receipt); err != nil {
		return "", err
	}
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", ErrEnrollmentIdentitySignatureInvalid
	}
	normalized := signed
	normalized.Receipt.EnrolledAt = normalized.Receipt.EnrolledAt.UTC()
	normalized.Receipt.IssuedAt = normalized.Receipt.IssuedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal signed enrollment identity receipt: %w", err)
	}
	domain, err := signedEnrollmentIdentityReceiptDomain(signed.Receipt.Version)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func VerifyEnrollmentIdentityReceiptForIdentity(
	signed SignedEnrollmentIdentityReceipt,
	publicKey ed25519.PublicKey,
	identity EnrolledTPMIdentity,
) error {
	if err := VerifySignedEnrollmentIdentityReceipt(signed, publicKey); err != nil {
		return err
	}
	digest, err := EnrolledTPMIdentityDigest(identity)
	if err != nil {
		return err
	}
	if signed.Receipt.DeviceID != identity.DeviceID ||
		signed.Receipt.EKSPKISHA256 != identity.EKSPKISHA256 ||
		signed.Receipt.EnrollmentIdentityDigest != digest ||
		!signed.Receipt.EnrolledAt.Equal(identity.EnrolledAt.UTC()) {
		return fmt.Errorf("%w: receipt does not bind the presented enrolled TPM identity", ErrEnrollmentIdentityReceiptInvalid)
	}
	return nil
}

func ValidateEnrollmentIdentityReceipt(receipt EnrollmentIdentityReceipt) error {
	switch receipt.Version {
	case EnrollmentIdentityReceiptVersion:
		if receipt.SuccessorAuthorizationDigest != "" {
			return fmt.Errorf("%w: v1 receipt cannot carry successor authorization", ErrEnrollmentIdentityReceiptInvalid)
		}
	case EnrollmentIdentityReceiptVersionV2:
		if receipt.Sequence < 2 {
			return fmt.Errorf("%w: governed successor receipt requires sequence >= 2", ErrEnrollmentIdentityReceiptInvalid)
		}
		if _, err := ParseSHA256Digest(receipt.SuccessorAuthorizationDigest); err != nil {
			return fmt.Errorf("%w: successor authorization digest: %v", ErrEnrollmentIdentityReceiptInvalid, err)
		}
	default:
		return fmt.Errorf("%w: unsupported version %q", ErrEnrollmentIdentityReceiptInvalid, receipt.Version)
	}
	if strings.TrimSpace(receipt.ReceiptID) == "" {
		return fmt.Errorf("%w: receipt id is required", ErrEnrollmentIdentityReceiptInvalid)
	}
	if receipt.Sequence == 0 {
		return fmt.Errorf("%w: sequence must be non-zero", ErrEnrollmentIdentityReceiptInvalid)
	}
	if receipt.Sequence == 1 {
		if receipt.PreviousReceiptDigest != "" {
			return fmt.Errorf("%w: first receipt cannot have a predecessor", ErrEnrollmentIdentityReceiptInvalid)
		}
	} else {
		if _, err := ParseSHA256Digest(receipt.PreviousReceiptDigest); err != nil {
			return fmt.Errorf("%w: previous receipt digest: %v", ErrEnrollmentIdentityReceiptInvalid, err)
		}
	}
	if strings.TrimSpace(receipt.DeviceID) == "" {
		return fmt.Errorf("%w: device id is required", ErrEnrollmentIdentityReceiptInvalid)
	}
	if _, err := ParseSHA256Digest(receipt.EKSPKISHA256); err != nil {
		return fmt.Errorf("%w: EK SPKI digest: %v", ErrEnrollmentIdentityReceiptInvalid, err)
	}
	if _, err := ParseSHA256Digest(receipt.EnrollmentIdentityDigest); err != nil {
		return fmt.Errorf("%w: enrollment identity digest: %v", ErrEnrollmentIdentityReceiptInvalid, err)
	}
	if receipt.EnrolledAt.IsZero() || receipt.IssuedAt.IsZero() {
		return fmt.Errorf("%w: enrolled_at and issued_at are required", ErrEnrollmentIdentityReceiptInvalid)
	}
	if receipt.IssuedAt.Before(receipt.EnrolledAt) {
		return fmt.Errorf("%w: issued_at precedes enrollment", ErrEnrollmentIdentityReceiptInvalid)
	}
	return nil
}

func validateEnrolledTPMIdentity(identity EnrolledTPMIdentity) error {
	if strings.TrimSpace(identity.DeviceID) == "" {
		return errors.New("enrolled TPM device id is required")
	}
	if _, err := ParseSHA256Digest(identity.EKSPKISHA256); err != nil {
		return fmt.Errorf("enrolled TPM EK SPKI digest: %w", err)
	}
	if len(identity.AK.Public) == 0 {
		return errors.New("enrolled TPM AK public area is required")
	}
	if len(identity.BootstrapAttestorPublicKey) != ed25519.PublicKeySize {
		return errors.New("enrolled TPM bootstrap attestor public key is required")
	}
	if identity.EnrolledAt.IsZero() {
		return errors.New("enrolled TPM enrolled_at is required")
	}
	if identity.EKCertificateSHA256 != "" {
		if _, err := ParseSHA256Digest(identity.EKCertificateSHA256); err != nil {
			return fmt.Errorf("enrolled TPM EK certificate digest: %w", err)
		}
	}
	return nil
}

func canonicalEnrollmentIdentityReceiptPayload(
	receipt EnrollmentIdentityReceipt,
) ([]byte, error) {
	normalized := receipt
	normalized.EnrolledAt = normalized.EnrolledAt.UTC()
	normalized.IssuedAt = normalized.IssuedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal enrollment identity receipt: %w", err)
	}
	domain, err := enrollmentIdentityReceiptDomain(receipt.Version)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

func enrollmentIdentityReceiptDomain(version string) (string, error) {
	switch version {
	case EnrollmentIdentityReceiptVersion:
		return "aegis.ege/tpm-enrollment-identity-receipt/v1\x00", nil
	case EnrollmentIdentityReceiptVersionV2:
		return "aegis.ege/tpm-enrollment-identity-receipt/v2\x00", nil
	default:
		return "", fmt.Errorf("%w: unsupported version %q", ErrEnrollmentIdentityReceiptInvalid, version)
	}
}

func signedEnrollmentIdentityReceiptDomain(version string) (string, error) {
	switch version {
	case EnrollmentIdentityReceiptVersion:
		return "aegis.ege/signed-enrollment-identity-receipt/v1\x00", nil
	case EnrollmentIdentityReceiptVersionV2:
		return "aegis.ege/signed-enrollment-identity-receipt/v2\x00", nil
	default:
		return "", fmt.Errorf("%w: unsupported version %q", ErrEnrollmentIdentityReceiptInvalid, version)
	}
}

func enrollmentAuthorityKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid enrollment authority Ed25519 public key")
	}
	sum := sha256.Sum256(append([]byte("aegis.ege/enrollment-authority-key/v1\x00"), publicKey...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
