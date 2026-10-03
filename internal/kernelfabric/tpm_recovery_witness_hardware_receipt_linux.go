//go:build linux

package kernelfabric

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const TPMRecoveryWitnessHardwareReceiptVersion = "aegis.ege/tpm-recovery-witness-hardware-receipt/v1"

type TPMRecoveryWitnessHardwareStatement struct {
	Version          string                           `json:"version"`
	Hardware         TPMHardwareIdentityEvidence      `json:"hardware"`
	WitnessAlgorithm string                           `json:"witness_algorithm"`
	WitnessKeyID     string                           `json:"witness_key_id"`
	WitnessPublicKey string                           `json:"witness_public_key"`
	WitnessPublic    TPMRecoveryWitnessPublicEvidence `json:"witness_public"`
	Challenge        string                           `json:"challenge"`
	CapturedAt       time.Time                        `json:"captured_at"`
}

type TPMRecoveryWitnessHardwareReceipt struct {
	Statement     TPMRecoveryWitnessHardwareStatement `json:"statement"`
	Signature     string                              `json:"signature"`
	ReceiptDigest string                              `json:"receipt_digest"`
}

func NewTPMHardwareEvidenceChallenge() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate TPM hardware evidence challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func CreateTPMRecoveryWitnessHardwareReceipt(
	ctx context.Context,
	signer *TPMRecoveryWitnessSigner,
	hardware TPMHardwareIdentityEvidence,
	challenge string,
	now time.Time,
) (TPMRecoveryWitnessHardwareReceipt, error) {
	if signer == nil {
		return TPMRecoveryWitnessHardwareReceipt{}, errors.New("TPM recovery witness signer is required")
	}
	if err := ValidateTPMHardwareIdentityEvidence(hardware); err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		return TPMRecoveryWitnessHardwareReceipt{}, errors.New("TPM hardware evidence challenge is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	publicEvidence, err := signer.PublicEvidence()
	if err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	encodedPublic, err := signer.Verifier().EncodedPublicKey()
	if err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	statement := TPMRecoveryWitnessHardwareStatement{
		Version:          TPMRecoveryWitnessHardwareReceiptVersion,
		Hardware:         hardware,
		WitnessAlgorithm: signer.Verifier().Algorithm(),
		WitnessKeyID:     signer.KeyID(),
		WitnessPublicKey: encodedPublic,
		WitnessPublic:    publicEvidence,
		Challenge:        challenge,
		CapturedAt:       now.UTC(),
	}
	payload, err := canonicalTPMRecoveryWitnessHardwareStatement(statement)
	if err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	signature, err := signer.SignHardwareEvidence(ctx, payload)
	if err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	receipt := TPMRecoveryWitnessHardwareReceipt{
		Statement: statement,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	digest, err := TPMRecoveryWitnessHardwareReceiptDigest(receipt)
	if err != nil {
		return TPMRecoveryWitnessHardwareReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, nil
}

func VerifyTPMRecoveryWitnessHardwareReceipt(receipt TPMRecoveryWitnessHardwareReceipt) error {
	if receipt.Statement.Version != TPMRecoveryWitnessHardwareReceiptVersion {
		return errors.New("unsupported TPM recovery witness hardware receipt version")
	}
	if err := ValidateTPMHardwareIdentityEvidence(receipt.Statement.Hardware); err != nil {
		return err
	}
	if strings.TrimSpace(receipt.Statement.Challenge) == "" || receipt.Statement.CapturedAt.IsZero() {
		return errors.New("TPM hardware receipt freshness coordinates are incomplete")
	}
	verifier, err := NewRecoveryWitnessVerifier(
		receipt.Statement.WitnessAlgorithm,
		receipt.Statement.WitnessPublicKey,
	)
	if err != nil {
		return err
	}
	if verifier.KeyID() != receipt.Statement.WitnessKeyID {
		return errors.New("TPM hardware receipt witness key id does not match public key")
	}
	if receipt.Statement.WitnessAlgorithm != RecoveryWitnessSignatureECDSAP256SHA256 {
		return errors.New("TPM hardware receipt requires ECDSA P-256 witness identity")
	}
	expectedPublic, err := expectedTPMRecoveryWitnessPublicEvidence(verifier)
	if err != nil {
		return err
	}
	if receipt.Statement.WitnessPublic != expectedPublic {
		return errors.New("TPM hardware receipt public area does not match pinned witness public key")
	}
	payload, err := canonicalTPMRecoveryWitnessHardwareStatement(receipt.Statement)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) == 0 || !verifier.Verify(payload, signature) {
		return errors.New("TPM hardware receipt signature is invalid")
	}
	expectedDigest, err := TPMRecoveryWitnessHardwareReceiptDigest(TPMRecoveryWitnessHardwareReceipt{
		Statement: receipt.Statement,
		Signature: receipt.Signature,
	})
	if err != nil {
		return err
	}
	if receipt.ReceiptDigest != expectedDigest {
		return errors.New("TPM hardware receipt digest mismatch")
	}
	return nil
}

func canonicalTPMRecoveryWitnessHardwareStatement(statement TPMRecoveryWitnessHardwareStatement) ([]byte, error) {
	body, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode TPM hardware witness statement: %w", err)
	}
	return append([]byte(tpmHardwareWitnessEvidenceDomain), body...), nil
}

func TPMRecoveryWitnessHardwareReceiptDigest(receipt TPMRecoveryWitnessHardwareReceipt) (string, error) {
	if strings.TrimSpace(receipt.Signature) == "" {
		return "", errors.New("TPM hardware receipt signature is required")
	}
	body, err := json.Marshal(struct {
		Statement TPMRecoveryWitnessHardwareStatement `json:"statement"`
		Signature string                              `json:"signature"`
	}{Statement: receipt.Statement, Signature: receipt.Signature})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/tpm-recovery-witness-hardware-receipt-digest/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
