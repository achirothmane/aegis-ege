package journal

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ucarion/jcs"
)

const WitnessTrustManifestVersion = "aegis-ege/witness-trust-manifest/v1"

type WitnessTrustManifest struct {
	Version             string `json:"version"`
	TrustEpoch          uint64 `json:"trust_epoch"`
	WorkloadPrincipal   string `json:"workload_principal"`
	WitnessPrincipal    string `json:"witness_principal"`
	Endpoint            string `json:"endpoint"`
	WitnessRuntimeKeyID string `json:"witness_runtime_key_id"`
	WitnessRuntimeKey   string `json:"witness_runtime_public_key"`
}

type SignedWitnessTrustManifest struct {
	Manifest             WitnessTrustManifest `json:"manifest"`
	WorkloadSignerKeyID  string               `json:"workload_signer_key_id"`
	WorkloadSignature    string               `json:"workload_signature"`
	WitnessOwnerKeyID    string               `json:"witness_owner_key_id"`
	WitnessOwnerSignature string              `json:"witness_owner_signature"`
}

type TwoPrincipalWitnessTrustRoot struct {
	workloadKeyID       string
	workloadPublicKey   ed25519.PublicKey
	witnessOwnerKeyID   string
	witnessOwnerKey     ed25519.PublicKey
	minimumTrustEpoch   uint64
}

func NewTwoPrincipalWitnessTrustRoot(
	workloadKeyID string,
	workloadPublicKey ed25519.PublicKey,
	witnessOwnerKeyID string,
	witnessOwnerPublicKey ed25519.PublicKey,
	minimumTrustEpoch uint64,
) (*TwoPrincipalWitnessTrustRoot, error) {
	workloadKeyID = strings.TrimSpace(workloadKeyID)
	witnessOwnerKeyID = strings.TrimSpace(witnessOwnerKeyID)
	if workloadKeyID == "" || witnessOwnerKeyID == "" {
		return nil, errors.New("two-principal witness trust root requires both signer key ids")
	}
	if len(workloadPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid workload principal public key")
	}
	if len(witnessOwnerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid witness owner public key")
	}
	return &TwoPrincipalWitnessTrustRoot{
		workloadKeyID:     workloadKeyID,
		workloadPublicKey: append(ed25519.PublicKey(nil), workloadPublicKey...),
		witnessOwnerKeyID: witnessOwnerKeyID,
		witnessOwnerKey:   append(ed25519.PublicKey(nil), witnessOwnerPublicKey...),
		minimumTrustEpoch: minimumTrustEpoch,
	}, nil
}

func (r *TwoPrincipalWitnessTrustRoot) Verify(
	ctx context.Context,
	signed SignedWitnessTrustManifest,
) (WitnessTrustManifest, ed25519.PublicKey, error) {
	if r == nil {
		return WitnessTrustManifest{}, nil, errors.New("two-principal witness trust root is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return WitnessTrustManifest{}, nil, err
	}
	manifest := signed.Manifest
	if manifest.Version != WitnessTrustManifestVersion {
		return WitnessTrustManifest{}, nil, fmt.Errorf("witness trust manifest version mismatch: %q", manifest.Version)
	}
	if manifest.TrustEpoch < r.minimumTrustEpoch {
		return WitnessTrustManifest{}, nil, fmt.Errorf(
			"witness trust epoch rollback: got %d minimum %d",
			manifest.TrustEpoch,
			r.minimumTrustEpoch,
		)
	}
	if strings.TrimSpace(manifest.WorkloadPrincipal) == "" ||
		strings.TrimSpace(manifest.WitnessPrincipal) == "" {
		return WitnessTrustManifest{}, nil, errors.New("witness trust manifest principals are required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(manifest.Endpoint), "/")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return WitnessTrustManifest{}, nil, errors.New("witness trust manifest endpoint must use HTTPS")
	}
	manifest.Endpoint = endpoint
	if strings.TrimSpace(manifest.WitnessRuntimeKeyID) == "" {
		return WitnessTrustManifest{}, nil, errors.New("witness runtime key id is required")
	}
	runtimeKey, err := base64.StdEncoding.DecodeString(manifest.WitnessRuntimeKey)
	if err != nil || len(runtimeKey) != ed25519.PublicKeySize {
		return WitnessTrustManifest{}, nil, errors.New("invalid witness runtime public key")
	}
	if signed.WorkloadSignerKeyID != r.workloadKeyID {
		return WitnessTrustManifest{}, nil, errors.New("workload signer key id mismatch")
	}
	if signed.WitnessOwnerKeyID != r.witnessOwnerKeyID {
		return WitnessTrustManifest{}, nil, errors.New("witness owner key id mismatch")
	}
	payload, err := CanonicalWitnessTrustManifestPayload(manifest)
	if err != nil {
		return WitnessTrustManifest{}, nil, err
	}
	workloadSignature, err := decodeWitnessTrustSignature(signed.WorkloadSignature)
	if err != nil || !ed25519.Verify(r.workloadPublicKey, payload, workloadSignature) {
		return WitnessTrustManifest{}, nil, errors.New("workload principal signature verification failed")
	}
	witnessSignature, err := decodeWitnessTrustSignature(signed.WitnessOwnerSignature)
	if err != nil || !ed25519.Verify(r.witnessOwnerKey, payload, witnessSignature) {
		return WitnessTrustManifest{}, nil, errors.New("witness owner signature verification failed")
	}
	return manifest, ed25519.PublicKey(runtimeKey), nil
}

func NewTwoPrincipalRemoteHeadStore(
	ctx context.Context,
	signed SignedWitnessTrustManifest,
	root *TwoPrincipalWitnessTrustRoot,
	client *http.Client,
) (*RemoteHeadStore, error) {
	manifest, runtimeKey, err := root.Verify(ctx, signed)
	if err != nil {
		return nil, err
	}
	return NewRemoteHeadStore(
		manifest.Endpoint,
		manifest.WitnessRuntimeKeyID,
		runtimeKey,
		client,
	)
}

func CanonicalWitnessTrustManifestPayload(manifest WitnessTrustManifest) ([]byte, error) {
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
	return []byte(canonical), nil
}

func SignWitnessTrustManifest(
	manifest WitnessTrustManifest,
	workloadKeyID string,
	workloadPrivateKey ed25519.PrivateKey,
	witnessOwnerKeyID string,
	witnessOwnerPrivateKey ed25519.PrivateKey,
) (SignedWitnessTrustManifest, error) {
	if len(workloadPrivateKey) != ed25519.PrivateKeySize ||
		len(witnessOwnerPrivateKey) != ed25519.PrivateKeySize {
		return SignedWitnessTrustManifest{}, errors.New("invalid two-principal signing key")
	}
	payload, err := CanonicalWitnessTrustManifestPayload(manifest)
	if err != nil {
		return SignedWitnessTrustManifest{}, err
	}
	return SignedWitnessTrustManifest{
		Manifest:              manifest,
		WorkloadSignerKeyID:   workloadKeyID,
		WorkloadSignature:     base64.StdEncoding.EncodeToString(ed25519.Sign(workloadPrivateKey, payload)),
		WitnessOwnerKeyID:     witnessOwnerKeyID,
		WitnessOwnerSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(witnessOwnerPrivateKey, payload)),
	}, nil
}

func decodeWitnessTrustSignature(encoded string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid witness trust signature length")
	}
	return signature, nil
}
