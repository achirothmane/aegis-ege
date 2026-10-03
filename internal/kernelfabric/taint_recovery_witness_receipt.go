package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ucarion/jcs"
)

const WitnessRecoveryReceiptVersion = "aegis.ege/witness-recovery-receipt/v1"

type WitnessRecoveryReceipt struct {
	Version              string    `json:"version"`
	WitnessID            string    `json:"witness_id"`
	WitnessKeyID         string    `json:"witness_key_id"`
	ProfileEpoch         uint64    `json:"profile_epoch"`
	Endpoint             string    `json:"endpoint"`
	TLSTrustAnchorSHA256 string    `json:"tls_trust_anchor_sha256"`
	PolicyEpoch          uint64    `json:"policy_epoch"`
	PolicyHash           string    `json:"policy_hash"`
	AuthorizationID      string    `json:"authorization_id"`
	JointCommitmentHash  string    `json:"joint_commitment_hash"`
	Nonce                string    `json:"nonce"`
	EvaluatedAt          time.Time `json:"evaluated_at"`
	Signature            string    `json:"signature"`
}

func signWitnessRecoveryReceipt(
	profile ExternalRecoveryWitnessProfile,
	authorizationID string,
	commitment [32]byte,
	nonce string,
	evaluatedAt time.Time,
	witnessPrivateKey ed25519.PrivateKey,
) (WitnessRecoveryReceipt, error) {
	signer, err := NewEd25519RecoveryWitnessSigner(witnessPrivateKey)
	if err != nil {
		return WitnessRecoveryReceipt{}, err
	}
	return signWitnessRecoveryReceiptWithSigner(
		context.Background(),
		profile,
		authorizationID,
		commitment,
		nonce,
		evaluatedAt,
		signer,
	)
}

func signWitnessRecoveryReceiptWithSigner(
	ctx context.Context,
	profile ExternalRecoveryWitnessProfile,
	authorizationID string,
	commitment [32]byte,
	nonce string,
	evaluatedAt time.Time,
	signer RecoveryWitnessSigner,
) (WitnessRecoveryReceipt, error) {
	if signer == nil {
		return WitnessRecoveryReceipt{}, fmt.Errorf("recovery witness receipt signer is unavailable")
	}
	receipt := WitnessRecoveryReceipt{
		Version:              WitnessRecoveryReceiptVersion,
		WitnessID:            profile.WitnessID,
		WitnessKeyID:         profile.WitnessKeyID,
		ProfileEpoch:         profile.ProfileEpoch,
		Endpoint:             profile.Endpoint,
		TLSTrustAnchorSHA256: profile.TLSTrustAnchorSHA256,
		PolicyEpoch:          profile.PolicyEpoch,
		PolicyHash:           profile.PolicyHash,
		AuthorizationID:      strings.TrimSpace(authorizationID),
		JointCommitmentHash:  "sha256:" + hex.EncodeToString(commitment[:]),
		Nonce:                strings.TrimSpace(nonce),
		EvaluatedAt:          evaluatedAt.UTC(),
	}
	payload, err := canonicalWitnessRecoveryReceiptPayload(receipt)
	if err != nil {
		return WitnessRecoveryReceipt{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return WitnessRecoveryReceipt{}, fmt.Errorf("sign recovery witness receipt: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return WitnessRecoveryReceipt{}, fmt.Errorf("recovery witness receipt signer returned invalid signature size")
	}
	receipt.Signature = base64.StdEncoding.EncodeToString(signature)
	return receipt, nil
}

func VerifyWitnessRecoveryReceipt(
	receipt WitnessRecoveryReceipt,
	profile *VerifiedExternalRecoveryWitnessProfile,
	joint JointSignedTaintRecoveryAuthorization,
	nonce string,
	witnessPublicKey ed25519.PublicKey,
) error {
	if profile == nil {
		return fmt.Errorf("%w: external witness profile is unavailable", ErrTaintRecoveryAuthorization)
	}
	if len(witnessPublicKey) != ed25519.PublicKeySize {
		return ErrBootstrapSignatureInvalid
	}
	expected := profile.profile
	if receipt.Version != WitnessRecoveryReceiptVersion ||
		receipt.WitnessID != expected.WitnessID ||
		receipt.WitnessKeyID != expected.WitnessKeyID ||
		receipt.ProfileEpoch != expected.ProfileEpoch ||
		receipt.Endpoint != expected.Endpoint ||
		receipt.TLSTrustAnchorSHA256 != expected.TLSTrustAnchorSHA256 ||
		receipt.PolicyEpoch != expected.PolicyEpoch ||
		receipt.PolicyHash != expected.PolicyHash {
		return fmt.Errorf("%w: witness receipt profile continuity mismatch", ErrTaintRecoveryAuthorization)
	}
	if receipt.AuthorizationID != joint.Authorization.AuthorizationID {
		return fmt.Errorf("%w: witness receipt authorization mismatch", ErrTaintRecoveryAuthorization)
	}
	if receipt.Nonce != nonce {
		return fmt.Errorf("%w: witness receipt nonce mismatch", ErrTaintRecoveryAuthorization)
	}
	commitment, err := JointTaintRecoveryCommitmentDigest(joint)
	if err != nil {
		return err
	}
	expectedCommitment := "sha256:" + hex.EncodeToString(commitment[:])
	if receipt.JointCommitmentHash != expectedCommitment {
		return fmt.Errorf("%w: witness receipt commitment mismatch", ErrTaintRecoveryAuthorization)
	}
	if receipt.EvaluatedAt.IsZero() {
		return fmt.Errorf("%w: witness receipt evaluation time is missing", ErrTaintRecoveryAuthorization)
	}
	if receipt.EvaluatedAt.Before(joint.Authorization.NotBefore.UTC()) ||
		!receipt.EvaluatedAt.Before(joint.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: witness receipt evaluation time is outside authorization window",
			ErrTaintRecoveryAuthorization)
	}
	signature, err := decodeTaintRecoverySignature(receipt.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalWitnessRecoveryReceiptPayload(receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(witnessPublicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func canonicalWitnessRecoveryReceiptPayload(receipt WitnessRecoveryReceipt) ([]byte, error) {
	normalized := receipt
	normalized.Signature = ""
	normalized.EvaluatedAt = receipt.EvaluatedAt.UTC()
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/witness-recovery-receipt/v1\x00"), canonical...), nil
}
