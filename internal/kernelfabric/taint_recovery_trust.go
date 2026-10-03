package kernelfabric

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ucarion/jcs"
)

const TaintRecoveryTrustManifestVersion = "aegis.ege/taint-recovery-trust/v1"

type TaintRecoveryTrustManifest struct {
	Version            string `json:"version"`
	TrustEpoch         uint64 `json:"trust_epoch"`
	AuthorityPrincipal string `json:"authority_principal"`
	AuthorityKeyID     string `json:"authority_key_id"`
	AuthorityPublicKey string `json:"authority_public_key"`
	WitnessPrincipal   string `json:"witness_principal"`
	WitnessKeyID       string `json:"witness_key_id"`
	WitnessPublicKey   string `json:"witness_public_key"`
}

type SignedTaintRecoveryTrustManifest struct {
	Manifest     TaintRecoveryTrustManifest `json:"manifest"`
	SignerKeyID  string                     `json:"signer_key_id"`
	Signature    string                     `json:"signature"`
}

type TaintRecoveryTrustRoot struct {
	manifest     TaintRecoveryTrustManifest
	authorityKey ed25519.PublicKey
	witnessKey   ed25519.PublicKey
}

func SignTaintRecoveryTrustManifest(
	manifest TaintRecoveryTrustManifest,
	signerPrivateKey ed25519.PrivateKey,
) (SignedTaintRecoveryTrustManifest, error) {
	if len(signerPrivateKey) != ed25519.PrivateKeySize {
		return SignedTaintRecoveryTrustManifest{}, errors.New("invalid taint recovery trust signer key")
	}
	normalized, authorityKey, witnessKey, err := normalizeTaintRecoveryTrustManifest(manifest)
	if err != nil {
		return SignedTaintRecoveryTrustManifest{}, err
	}
	_ = authorityKey
	_ = witnessKey
	payload, err := canonicalTaintRecoveryTrustManifestPayload(normalized)
	if err != nil {
		return SignedTaintRecoveryTrustManifest{}, err
	}
	signerKeyID, err := BootstrapKeyID(signerPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedTaintRecoveryTrustManifest{}, err
	}
	return SignedTaintRecoveryTrustManifest{
		Manifest:    normalized,
		SignerKeyID: signerKeyID,
		Signature:   base64.StdEncoding.EncodeToString(ed25519.Sign(signerPrivateKey, payload)),
	}, nil
}

func NewTaintRecoveryTrustRoot(
	signed SignedTaintRecoveryTrustManifest,
	trustedSignerPublicKey ed25519.PublicKey,
	minimumTrustEpoch uint64,
) (*TaintRecoveryTrustRoot, error) {
	if len(trustedSignerPublicKey) != ed25519.PublicKeySize {
		return nil, ErrBootstrapSignatureInvalid
	}
	manifest, authorityKey, witnessKey, err := normalizeTaintRecoveryTrustManifest(signed.Manifest)
	if err != nil {
		return nil, err
	}
	if manifest.TrustEpoch < minimumTrustEpoch {
		return nil, fmt.Errorf(
			"%w: recovery trust epoch rollback: got=%d minimum=%d",
			ErrTaintRecoveryAuthorization,
			manifest.TrustEpoch,
			minimumTrustEpoch,
		)
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
	payload, err := canonicalTaintRecoveryTrustManifestPayload(manifest)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(trustedSignerPublicKey, payload, signature) {
		return nil, ErrBootstrapSignatureInvalid
	}
	return &TaintRecoveryTrustRoot{
		manifest:     manifest,
		authorityKey: append(ed25519.PublicKey(nil), authorityKey...),
		witnessKey:   append(ed25519.PublicKey(nil), witnessKey...),
	}, nil
}

func (r *TaintRecoveryTrustRoot) Verify(
	signed JointSignedTaintRecoveryAuthorization,
	now time.Time,
) error {
	if r == nil {
		return fmt.Errorf("%w: recovery trust root is unavailable", ErrTaintRecoveryAuthorization)
	}
	if signed.AuthorityKeyID != r.manifest.AuthorityKeyID {
		return fmt.Errorf("%w: recovery authority is not trusted", ErrTaintRecoveryAuthorization)
	}
	if signed.WitnessKeyID != r.manifest.WitnessKeyID {
		return fmt.Errorf("%w: recovery witness is not trusted", ErrTaintRecoveryAuthorization)
	}
	return VerifyJointTaintRecoveryAuthorization(signed, r.authorityKey, r.witnessKey, now)
}

func (r *TaintRecoveryTrustRoot) TrustEpoch() uint64 {
	if r == nil {
		return 0
	}
	return r.manifest.TrustEpoch
}

func normalizeTaintRecoveryTrustManifest(
	manifest TaintRecoveryTrustManifest,
) (TaintRecoveryTrustManifest, ed25519.PublicKey, ed25519.PublicKey, error) {
	if manifest.Version != TaintRecoveryTrustManifestVersion {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery trust manifest version mismatch %q",
			ErrTaintRecoveryAuthorization,
			manifest.Version,
		)
	}
	if manifest.TrustEpoch == 0 {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery trust epoch must be non-zero",
			ErrTaintRecoveryAuthorization,
		)
	}
	manifest.AuthorityPrincipal = strings.TrimSpace(manifest.AuthorityPrincipal)
	manifest.WitnessPrincipal = strings.TrimSpace(manifest.WitnessPrincipal)
	manifest.AuthorityKeyID = strings.TrimSpace(manifest.AuthorityKeyID)
	manifest.WitnessKeyID = strings.TrimSpace(manifest.WitnessKeyID)
	if manifest.AuthorityPrincipal == "" || manifest.WitnessPrincipal == "" {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery trust principals are required",
			ErrTaintRecoveryAuthorization,
		)
	}
	if manifest.AuthorityPrincipal == manifest.WitnessPrincipal {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery authority and witness principals must differ",
			ErrTaintRecoveryAuthorization,
		)
	}
	authorityRaw, err := base64.StdEncoding.DecodeString(manifest.AuthorityPublicKey)
	if err != nil || len(authorityRaw) != ed25519.PublicKeySize {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: invalid recovery authority public key",
			ErrTaintRecoveryAuthorization,
		)
	}
	witnessRaw, err := base64.StdEncoding.DecodeString(manifest.WitnessPublicKey)
	if err != nil || len(witnessRaw) != ed25519.PublicKeySize {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: invalid recovery witness public key",
			ErrTaintRecoveryAuthorization,
		)
	}
	authorityKey := ed25519.PublicKey(authorityRaw)
	witnessKey := ed25519.PublicKey(witnessRaw)
	authorityKeyID, err := BootstrapKeyID(authorityKey)
	if err != nil {
		return TaintRecoveryTrustManifest{}, nil, nil, err
	}
	witnessKeyID, err := BootstrapKeyID(witnessKey)
	if err != nil {
		return TaintRecoveryTrustManifest{}, nil, nil, err
	}
	if authorityKeyID == witnessKeyID {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery trust manifest uses one key for both principals",
			ErrTaintRecoveryAuthorization,
		)
	}
	if manifest.AuthorityKeyID != authorityKeyID || manifest.WitnessKeyID != witnessKeyID {
		return TaintRecoveryTrustManifest{}, nil, nil, fmt.Errorf(
			"%w: recovery trust key id does not match public key",
			ErrTaintRecoveryAuthorization,
		)
	}
	return manifest, authorityKey, witnessKey, nil
}

func canonicalTaintRecoveryTrustManifestPayload(
	manifest TaintRecoveryTrustManifest,
) ([]byte, error) {
	raw, err := json.Marshal(manifest)
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
	return append([]byte("aegis-ege/taint-recovery-trust/v1\x00"), canonical...), nil
}
