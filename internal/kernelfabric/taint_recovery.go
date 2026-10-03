package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	TaintRecoveryAuthorizationVersion      = "aegis.ege/taint-recovery-authorization/v0"
	JointTaintRecoveryAuthorizationVersion = "aegis.ege/taint-recovery-joint/v1"
)

var ErrTaintRecoveryAuthorization = errors.New("taint recovery authorization is invalid")

type TaintRecoveryAuthorization struct {
	Version         string    `json:"version"`
	AuthorizationID string    `json:"authorization_id"`
	PlanDigest      string    `json:"plan_digest"`
	CgroupID        uint64    `json:"cgroup_id"`
	BPFFSRoot       string    `json:"bpffs_root"`
	BootIDHash      string    `json:"boot_id_hash"`
	FromEpoch       uint64    `json:"from_epoch"`
	ToEpoch         uint64    `json:"to_epoch"`
	ExpectedDirty   uint64    `json:"expected_dirty"`
	NotBefore       time.Time `json:"not_before"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type SignedTaintRecoveryAuthorization struct {
	Authorization TaintRecoveryAuthorization `json:"authorization"`
	KeyID         string                     `json:"key_id"`
	Signature     string                     `json:"signature"`
}

type JointSignedTaintRecoveryAuthorization struct {
	Version            string                     `json:"version"`
	Authorization      TaintRecoveryAuthorization `json:"authorization"`
	AuthorityKeyID     string                     `json:"authority_key_id"`
	AuthoritySignature string                     `json:"authority_signature"`
	WitnessKeyID       string                     `json:"witness_key_id"`
	WitnessSignature   string                     `json:"witness_signature"`
}

func ValidateTaintRecoveryAuthorization(auth TaintRecoveryAuthorization) error {
	if auth.Version != TaintRecoveryAuthorizationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTaintRecoveryAuthorization, auth.Version)
	}
	if strings.TrimSpace(auth.AuthorizationID) == "" {
		return fmt.Errorf("%w: authorization_id is required", ErrTaintRecoveryAuthorization)
	}
	if _, err := ParseSHA256Digest(auth.PlanDigest); err != nil {
		return fmt.Errorf("%w: plan_digest: %v", ErrTaintRecoveryAuthorization, err)
	}
	if auth.CgroupID == 0 {
		return fmt.Errorf("%w: cgroup_id is required", ErrTaintRecoveryAuthorization)
	}
	root := filepath.Clean(strings.TrimSpace(auth.BPFFSRoot))
	if root == "." || !filepath.IsAbs(root) {
		return fmt.Errorf("%w: bpffs_root must be absolute", ErrTaintRecoveryAuthorization)
	}
	if _, err := ParseSHA256Digest(auth.BootIDHash); err != nil {
		return fmt.Errorf("%w: boot_id_hash: %v", ErrTaintRecoveryAuthorization, err)
	}
	if auth.FromEpoch == 0 || auth.ToEpoch != auth.FromEpoch+1 {
		return fmt.Errorf("%w: recovery epoch must advance exactly once", ErrTaintRecoveryAuthorization)
	}
	if auth.ExpectedDirty == 0 {
		return fmt.Errorf("%w: expected_dirty must be non-zero", ErrTaintRecoveryAuthorization)
	}
	if auth.NotBefore.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.NotBefore) {
		return fmt.Errorf("%w: validity window is invalid", ErrTaintRecoveryAuthorization)
	}
	return nil
}

func SignTaintRecoveryAuthorization(
	auth TaintRecoveryAuthorization,
	privateKey ed25519.PrivateKey,
) (SignedTaintRecoveryAuthorization, error) {
	if err := ValidateTaintRecoveryAuthorization(auth); err != nil {
		return SignedTaintRecoveryAuthorization{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTaintRecoveryAuthorization{}, errors.New("invalid Ed25519 taint recovery key")
	}
	payload, err := canonicalTaintRecoveryAuthorizationPayload(auth)
	if err != nil {
		return SignedTaintRecoveryAuthorization{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedTaintRecoveryAuthorization{}, err
	}
	return SignedTaintRecoveryAuthorization{
		Authorization: auth,
		KeyID:         keyID,
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTaintRecoveryAuthorization(
	signed SignedTaintRecoveryAuthorization,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := ValidateTaintRecoveryAuthorization(signed.Authorization); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrBootstrapSignatureInvalid
	}
	expectedKeyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if expectedKeyID != signed.KeyID {
		return ErrBootstrapSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalTaintRecoveryAuthorizationPayload(signed.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Authorization.NotBefore.UTC()) || !now.Before(signed.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrTaintRecoveryAuthorization)
	}
	return nil
}

func SignJointTaintRecoveryAuthorization(
	auth TaintRecoveryAuthorization,
	authorityPrivateKey ed25519.PrivateKey,
	witnessPrivateKey ed25519.PrivateKey,
) (JointSignedTaintRecoveryAuthorization, error) {
	if err := ValidateTaintRecoveryAuthorization(auth); err != nil {
		return JointSignedTaintRecoveryAuthorization{}, err
	}
	if len(authorityPrivateKey) != ed25519.PrivateKeySize || len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return JointSignedTaintRecoveryAuthorization{}, errors.New("invalid Ed25519 joint taint recovery key")
	}
	authorityKeyID, err := BootstrapKeyID(authorityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, err
	}
	witnessKeyID, err := BootstrapKeyID(witnessPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, err
	}
	if authorityKeyID == witnessKeyID {
		return JointSignedTaintRecoveryAuthorization{}, fmt.Errorf("%w: recovery authority and witness must use distinct keys", ErrTaintRecoveryAuthorization)
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(auth)
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, err
	}
	return JointSignedTaintRecoveryAuthorization{
		Version:            JointTaintRecoveryAuthorizationVersion,
		Authorization:      auth,
		AuthorityKeyID:     authorityKeyID,
		AuthoritySignature: base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivateKey, payload)),
		WitnessKeyID:       witnessKeyID,
		WitnessSignature:   base64.StdEncoding.EncodeToString(ed25519.Sign(witnessPrivateKey, payload)),
	}, nil
}

func VerifyJointTaintRecoveryAuthorization(
	signed JointSignedTaintRecoveryAuthorization,
	authorityPublicKey ed25519.PublicKey,
	witnessPublicKey ed25519.PublicKey,
	now time.Time,
) error {
	verifier, err := NewRecoveryWitnessVerifier(
		RecoveryWitnessSignatureEd25519,
		base64.StdEncoding.EncodeToString(witnessPublicKey),
	)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	return VerifyJointTaintRecoveryAuthorizationWithWitnessVerifier(
		signed,
		authorityPublicKey,
		verifier,
		now,
	)
}

func VerifyJointTaintRecoveryAuthorizationWithWitnessVerifier(
	signed JointSignedTaintRecoveryAuthorization,
	authorityPublicKey ed25519.PublicKey,
	witnessVerifier RecoveryWitnessVerifier,
	now time.Time,
) error {
	if signed.Version != JointTaintRecoveryAuthorizationVersion {
		return fmt.Errorf("%w: unsupported joint authorization version %q", ErrTaintRecoveryAuthorization, signed.Version)
	}
	if err := ValidateTaintRecoveryAuthorization(signed.Authorization); err != nil {
		return err
	}
	if len(authorityPublicKey) != ed25519.PublicKeySize ||
		strings.TrimSpace(witnessVerifier.KeyID()) == "" {
		return ErrBootstrapSignatureInvalid
	}
	authorityKeyID, err := BootstrapKeyID(authorityPublicKey)
	if err != nil {
		return err
	}
	witnessKeyID := witnessVerifier.KeyID()
	if authorityKeyID == witnessKeyID {
		return fmt.Errorf("%w: recovery authority and witness must be distinct principals", ErrTaintRecoveryAuthorization)
	}
	if signed.AuthorityKeyID != authorityKeyID || signed.WitnessKeyID != witnessKeyID {
		return ErrBootstrapSignatureInvalid
	}
	authoritySignature, err := decodeTaintRecoverySignature(signed.AuthoritySignature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	witnessSignature, err := decodeRecoveryWitnessSignature(signed.WitnessSignature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(signed.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(authorityPublicKey, payload, authoritySignature) ||
		!witnessVerifier.Verify(payload, witnessSignature) {
		return ErrBootstrapSignatureInvalid
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Authorization.NotBefore.UTC()) || !now.Before(signed.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrTaintRecoveryAuthorization)
	}
	return nil
}

func JointTaintRecoveryCommitmentDigest(
	signed JointSignedTaintRecoveryAuthorization,
) ([32]byte, error) {
	if signed.Version != JointTaintRecoveryAuthorizationVersion {
		return [32]byte{}, fmt.Errorf("%w: unsupported joint authorization version %q", ErrTaintRecoveryAuthorization, signed.Version)
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(signed.Authorization)
	if err != nil {
		return [32]byte{}, err
	}
	body, err := json.Marshal(struct {
		Version            string `json:"version"`
		Payload            []byte `json:"payload"`
		AuthorityKeyID     string `json:"authority_key_id"`
		AuthoritySignature string `json:"authority_signature"`
		WitnessKeyID       string `json:"witness_key_id"`
		WitnessSignature   string `json:"witness_signature"`
	}{
		Version:            signed.Version,
		Payload:            payload,
		AuthorityKeyID:     signed.AuthorityKeyID,
		AuthoritySignature: signed.AuthoritySignature,
		WitnessKeyID:       signed.WitnessKeyID,
		WitnessSignature:   signed.WitnessSignature,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("aegis-ege/taint-recovery-joint-commitment/v1\x00"), body...)), nil
}

func canonicalJointTaintRecoveryAuthorizationPayload(auth TaintRecoveryAuthorization) ([]byte, error) {
	normalized := auth
	normalized.BPFFSRoot = filepath.Clean(strings.TrimSpace(auth.BPFFSRoot))
	normalized.NotBefore = auth.NotBefore.UTC()
	normalized.ExpiresAt = auth.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/taint-recovery-joint/v1\x00"), body...), nil
}

func decodeTaintRecoverySignature(encoded string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrBootstrapSignatureInvalid
	}
	return signature, nil
}

func decodeRecoveryWitnessSignature(encoded string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) == 0 {
		return nil, ErrBootstrapSignatureInvalid
	}
	return signature, nil
}

func TaintRecoveryCommitmentDigest(
	signed SignedTaintRecoveryAuthorization,
) ([32]byte, error) {
	payload, err := canonicalTaintRecoveryAuthorizationPayload(signed.Authorization)
	if err != nil {
		return [32]byte{}, err
	}
	body, err := json.Marshal(struct {
		Payload   []byte `json:"payload"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{
		Payload:   payload,
		KeyID:     signed.KeyID,
		Signature: signed.Signature,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("aegis-ege/taint-recovery-commitment/v0\x00"), body...)), nil
}

func canonicalTaintRecoveryAuthorizationPayload(auth TaintRecoveryAuthorization) ([]byte, error) {
	normalized := auth
	normalized.BPFFSRoot = filepath.Clean(strings.TrimSpace(auth.BPFFSRoot))
	normalized.NotBefore = auth.NotBefore.UTC()
	normalized.ExpiresAt = auth.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/taint-recovery-authorization/v0\x00"), body...), nil
}
