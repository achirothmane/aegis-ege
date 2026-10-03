package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ucarion/jcs"
)

const ExternalRecoveryWitnessProfileVersion = "aegis.ege/external-recovery-witness-profile/v1"

type ExternalRecoveryWitnessProfile struct {
	Version               string `json:"version"`
	ProfileEpoch          uint64 `json:"profile_epoch"`
	WitnessID             string `json:"witness_id"`
	WitnessKeyID          string `json:"witness_key_id"`
	Endpoint              string `json:"endpoint"`
	TLSTrustAnchorSHA256  string `json:"tls_trust_anchor_sha256"`
	PolicyEpoch           uint64 `json:"policy_epoch"`
	PolicyHash            string `json:"policy_hash"`
}

type SignedExternalRecoveryWitnessProfile struct {
	Profile     ExternalRecoveryWitnessProfile `json:"profile"`
	SignerKeyID string                         `json:"signer_key_id"`
	Signature   string                         `json:"signature"`
}

type VerifiedExternalRecoveryWitnessProfile struct {
	profile ExternalRecoveryWitnessProfile
}

func SignExternalRecoveryWitnessProfile(
	profile ExternalRecoveryWitnessProfile,
	signerPrivateKey ed25519.PrivateKey,
) (SignedExternalRecoveryWitnessProfile, error) {
	if len(signerPrivateKey) != ed25519.PrivateKeySize {
		return SignedExternalRecoveryWitnessProfile{}, fmt.Errorf("invalid external witness profile signer key")
	}
	normalized, err := normalizeExternalRecoveryWitnessProfile(profile)
	if err != nil {
		return SignedExternalRecoveryWitnessProfile{}, err
	}
	payload, err := canonicalExternalRecoveryWitnessProfilePayload(normalized)
	if err != nil {
		return SignedExternalRecoveryWitnessProfile{}, err
	}
	keyID, err := BootstrapKeyID(signerPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedExternalRecoveryWitnessProfile{}, err
	}
	return SignedExternalRecoveryWitnessProfile{
		Profile: normalized,
		SignerKeyID: keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signerPrivateKey, payload)),
	}, nil
}

func VerifyExternalRecoveryWitnessProfile(
	signed SignedExternalRecoveryWitnessProfile,
	trustedSignerPublicKey ed25519.PublicKey,
	trustRoot *TaintRecoveryTrustRoot,
	minimumProfileEpoch uint64,
	minimumPolicyEpoch uint64,
) (*VerifiedExternalRecoveryWitnessProfile, error) {
	if len(trustedSignerPublicKey) != ed25519.PublicKeySize {
		return nil, ErrBootstrapSignatureInvalid
	}
	if trustRoot == nil {
		return nil, fmt.Errorf("%w: recovery trust root is unavailable", ErrTaintRecoveryAuthorization)
	}
	profile, err := normalizeExternalRecoveryWitnessProfile(signed.Profile)
	if err != nil {
		return nil, err
	}
	if profile.ProfileEpoch < minimumProfileEpoch {
		return nil, fmt.Errorf("%w: external witness profile epoch rollback: got=%d minimum=%d",
			ErrTaintRecoveryAuthorization, profile.ProfileEpoch, minimumProfileEpoch)
	}
	if profile.PolicyEpoch < minimumPolicyEpoch {
		return nil, fmt.Errorf("%w: external witness policy epoch rollback: got=%d minimum=%d",
			ErrTaintRecoveryAuthorization, profile.PolicyEpoch, minimumPolicyEpoch)
	}
	if profile.WitnessKeyID != trustRoot.manifest.WitnessKeyID {
		return nil, fmt.Errorf("%w: external witness key is not pinned by recovery trust root",
			ErrTaintRecoveryAuthorization)
	}
	signerKeyID, err := BootstrapKeyID(trustedSignerPublicKey)
	if err != nil {
		return nil, err
	}
	if signed.SignerKeyID != signerKeyID {
		return nil, ErrBootstrapSignatureInvalid
	}
	signature, err := decodeTaintRecoverySignature(signed.Signature)
	if err != nil {
		return nil, ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalExternalRecoveryWitnessProfilePayload(profile)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(trustedSignerPublicKey, payload, signature) {
		return nil, ErrBootstrapSignatureInvalid
	}
	return &VerifiedExternalRecoveryWitnessProfile{profile: profile}, nil
}

func (p *VerifiedExternalRecoveryWitnessProfile) Profile() ExternalRecoveryWitnessProfile {
	if p == nil {
		return ExternalRecoveryWitnessProfile{}
	}
	return p.profile
}

func CanonicalJSONSHA256(raw []byte) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func TLSCertificatePEMSHA256(raw []byte) (string, error) {
	// The profile binds the exact PEM trust-anchor bytes carried to the controller.
	// TLS verification then uses those same bytes as its trust root.
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", fmt.Errorf("TLS trust anchor is empty")
	}
	sum := sha256.Sum256([]byte(trimmed))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func normalizeExternalRecoveryWitnessProfile(
	profile ExternalRecoveryWitnessProfile,
) (ExternalRecoveryWitnessProfile, error) {
	if profile.Version != ExternalRecoveryWitnessProfileVersion {
		return ExternalRecoveryWitnessProfile{}, fmt.Errorf("%w: external witness profile version mismatch %q",
			ErrTaintRecoveryAuthorization, profile.Version)
	}
	profile.WitnessID = strings.TrimSpace(profile.WitnessID)
	profile.WitnessKeyID = strings.TrimSpace(profile.WitnessKeyID)
	profile.Endpoint = strings.TrimRight(strings.TrimSpace(profile.Endpoint), "/")
	profile.TLSTrustAnchorSHA256 = strings.TrimSpace(profile.TLSTrustAnchorSHA256)
	profile.PolicyHash = strings.TrimSpace(profile.PolicyHash)
	if profile.ProfileEpoch == 0 || profile.PolicyEpoch == 0 ||
		profile.WitnessID == "" || profile.WitnessKeyID == "" || profile.Endpoint == "" {
		return ExternalRecoveryWitnessProfile{}, fmt.Errorf("%w: incomplete external witness profile",
			ErrTaintRecoveryAuthorization)
	}
	if profile.ProfileEpoch > maxTaintRecoveryTrustJSONInteger ||
		profile.PolicyEpoch > maxTaintRecoveryTrustJSONInteger {
		return ExternalRecoveryWitnessProfile{}, fmt.Errorf(
			"%w: external witness epoch exceeds RFC8785/JCS exact integer profile",
			ErrTaintRecoveryAuthorization,
		)
	}
	if _, err := ParseSHA256Digest(profile.TLSTrustAnchorSHA256); err != nil {
		return ExternalRecoveryWitnessProfile{}, fmt.Errorf("%w: TLS trust anchor digest: %v",
			ErrTaintRecoveryAuthorization, err)
	}
	if _, err := ParseSHA256Digest(profile.PolicyHash); err != nil {
		return ExternalRecoveryWitnessProfile{}, fmt.Errorf("%w: policy hash: %v",
			ErrTaintRecoveryAuthorization, err)
	}
	return profile, nil
}

func canonicalExternalRecoveryWitnessProfilePayload(
	profile ExternalRecoveryWitnessProfile,
) ([]byte, error) {
	raw, err := json.Marshal(profile)
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
	return append([]byte("aegis-ege/external-recovery-witness-profile/v1\x00"), canonical...), nil
}
