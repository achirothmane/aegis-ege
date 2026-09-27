package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	BootstrapManifestVersion = "aegis.ege/bpf-bootstrap/v1"
	BootstrapReceiptVersion  = "aegis.ege/bpf-bootstrap-receipt/v1"
	BPFObjectNameMaxLength   = 15
)

var (
	ErrBootstrapSignatureInvalid = errors.New("BPF bootstrap signature is invalid")
	ErrBootstrapManifestExpired  = errors.New("BPF bootstrap manifest is expired")
	ErrBootstrapArtifactMismatch = errors.New("BPF bootstrap artifact does not match signed manifest")
	ErrBootstrapPostloadMismatch = errors.New("loaded BPF state does not match signed manifest")
)

type BootstrapProgram struct {
	PinName    string `json:"pin_name"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	AttachType string `json:"attach_type"`
}

type BootstrapMap struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type BootstrapManifest struct {
	Version        string             `json:"version"`
	ArtifactSHA256 string             `json:"artifact_sha256"`
	ArtifactSize   int64              `json:"artifact_size"`
	ABIVersion     uint32             `json:"abi_version"`
	NotBefore      time.Time          `json:"not_before"`
	NotAfter       time.Time          `json:"not_after"`
	Programs       []BootstrapProgram `json:"programs"`
	Maps           []BootstrapMap     `json:"maps"`
}

type SignedBootstrapManifest struct {
	Manifest  BootstrapManifest `json:"manifest"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
}

type BootstrapTrustStore map[string]ed25519.PublicKey

type PinnedProgramAttestation struct {
	PinName    string `json:"pin_name"`
	ID         uint32 `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	AttachType string `json:"attach_type"`
}

type PinnedMapAttestation struct {
	Name       string `json:"name"`
	ID         uint32 `json:"id"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
}

type BootstrapHostSnapshot struct {
	BootIDHash   string `json:"boot_id_hash"`
	KernelRelease string `json:"kernel_release"`
	LockdownMode string `json:"lockdown_mode,omitempty"`
	BPFFSRoot    string `json:"bpffs_root"`
}

type BootstrapReceipt struct {
	Version             string                     `json:"version"`
	ManifestDigest      string                     `json:"manifest_digest"`
	ManifestSignerKeyID string                     `json:"manifest_signer_key_id"`
	ArtifactSHA256   string                     `json:"artifact_sha256"`
	ArtifactSize     int64                      `json:"artifact_size"`
	Host             BootstrapHostSnapshot      `json:"host"`
	CgroupPath       string                     `json:"cgroup_path"`
	Programs         []PinnedProgramAttestation `json:"programs"`
	Maps             []PinnedMapAttestation     `json:"maps"`
	CompletedAt      time.Time                  `json:"completed_at"`
}

type SignedBootstrapReceipt struct {
	Receipt   BootstrapReceipt `json:"receipt"`
	KeyID     string           `json:"key_id"`
	Signature string           `json:"signature"`
}

func BootstrapKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key length %d", len(publicKey))
	}
	sum := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(sum[:12]), nil
}

func SignBootstrapManifest(manifest BootstrapManifest, privateKey ed25519.PrivateKey) (SignedBootstrapManifest, error) {
	if err := ValidateBootstrapManifest(manifest, time.Time{}); err != nil {
		return SignedBootstrapManifest{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBootstrapManifest{}, errors.New("invalid Ed25519 private key")
	}
	payload, err := canonicalBootstrapManifestPayload(manifest)
	if err != nil {
		return SignedBootstrapManifest{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedBootstrapManifest{}, err
	}
	return SignedBootstrapManifest{
		Manifest:  manifest,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedBootstrapManifest(
	signed SignedBootstrapManifest,
	trust BootstrapTrustStore,
	now time.Time,
) error {
	if len(trust) == 0 {
		return errors.New("bootstrap trust store is empty")
	}
	publicKey := trust[strings.TrimSpace(signed.KeyID)]
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: unknown key id %q", ErrBootstrapSignatureInvalid, signed.KeyID)
	}
	if err := ValidateBootstrapManifest(signed.Manifest, now); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrBootstrapSignatureInvalid, err)
	}
	payload, err := canonicalBootstrapManifestPayload(signed.Manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func ValidateBootstrapManifest(manifest BootstrapManifest, now time.Time) error {
	if manifest.Version != BootstrapManifestVersion {
		return fmt.Errorf("unsupported bootstrap manifest version %q", manifest.Version)
	}
	if manifest.ABIVersion != ABIVersion {
		return fmt.Errorf("bootstrap manifest ABI %d does not match kernel ABI %d", manifest.ABIVersion, ABIVersion)
	}
	if _, err := ParseSHA256Digest(manifest.ArtifactSHA256); err != nil {
		return fmt.Errorf("bootstrap artifact digest: %w", err)
	}
	if manifest.ArtifactSize <= 0 {
		return errors.New("bootstrap artifact size must be positive")
	}
	if manifest.NotBefore.IsZero() || manifest.NotAfter.IsZero() || !manifest.NotAfter.After(manifest.NotBefore) {
		return errors.New("bootstrap manifest validity window is invalid")
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(manifest.NotBefore.UTC()) {
			return errors.New("BPF bootstrap manifest is not yet valid")
		}
		if !now.Before(manifest.NotAfter.UTC()) {
			return ErrBootstrapManifestExpired
		}
	}
	if len(manifest.Programs) == 0 || len(manifest.Maps) == 0 {
		return errors.New("bootstrap manifest must declare programs and maps")
	}
	programPins := map[string]struct{}{}
	for _, program := range manifest.Programs {
		if strings.TrimSpace(program.PinName) == "" ||
			strings.TrimSpace(program.Name) == "" ||
			strings.TrimSpace(program.Type) == "" ||
			strings.TrimSpace(program.AttachType) == "" {
			return errors.New("bootstrap program declaration is incomplete")
		}
		if len(program.Name) > BPFObjectNameMaxLength {
			return fmt.Errorf("bootstrap program name %q exceeds kernel BPF object-name limit", program.Name)
		}
		if strings.ContainsAny(program.PinName, "/.") {
			return fmt.Errorf("bootstrap program pin name %q is not a safe bpffs filename", program.PinName)
		}
		if _, exists := programPins[program.PinName]; exists {
			return fmt.Errorf("duplicate bootstrap program pin %q", program.PinName)
		}
		programPins[program.PinName] = struct{}{}
	}
	mapNames := map[string]struct{}{}
	for _, m := range manifest.Maps {
		if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Type) == "" {
			return errors.New("bootstrap map declaration is incomplete")
		}
		if len(m.Name) > BPFObjectNameMaxLength {
			return fmt.Errorf("bootstrap map name %q exceeds kernel BPF object-name limit", m.Name)
		}
		if strings.ContainsAny(m.Name, "/.") {
			return fmt.Errorf("bootstrap map name %q is not a safe bpffs filename", m.Name)
		}
		if _, exists := mapNames[m.Name]; exists {
			return fmt.Errorf("duplicate bootstrap map %q", m.Name)
		}
		mapNames[m.Name] = struct{}{}
	}
	return nil
}

func VerifyBootstrapArtifact(path string, manifest BootstrapManifest) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open BPF artifact: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat BPF artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: artifact is not a regular file", ErrBootstrapArtifactMismatch)
	}
	if info.Size() != manifest.ArtifactSize {
		return fmt.Errorf(
			"%w: size=%d want=%d",
			ErrBootstrapArtifactMismatch,
			info.Size(),
			manifest.ArtifactSize,
		)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash BPF artifact: %w", err)
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actual != manifest.ArtifactSHA256 {
		return fmt.Errorf(
			"%w: digest=%s want=%s",
			ErrBootstrapArtifactMismatch,
			actual,
			manifest.ArtifactSHA256,
		)
	}
	return nil
}

func BootstrapManifestDigest(manifest BootstrapManifest) (string, error) {
	payload, err := canonicalBootstrapManifestPayload(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignBootstrapReceipt(receipt BootstrapReceipt, privateKey ed25519.PrivateKey) (SignedBootstrapReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBootstrapReceipt{}, errors.New("invalid Ed25519 attestation private key")
	}
	payload, err := canonicalBootstrapReceiptPayload(receipt)
	if err != nil {
		return SignedBootstrapReceipt{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedBootstrapReceipt{}, err
	}
	return SignedBootstrapReceipt{
		Receipt: receipt,
		KeyID: keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedBootstrapReceipt(signed SignedBootstrapReceipt, publicKey ed25519.PublicKey) error {
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
	payload, err := canonicalBootstrapReceiptPayload(signed.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func canonicalBootstrapManifestPayload(manifest BootstrapManifest) ([]byte, error) {
	normalized := manifest
	normalized.NotBefore = normalized.NotBefore.UTC()
	normalized.NotAfter = normalized.NotAfter.UTC()
	normalized.Programs = append([]BootstrapProgram(nil), normalized.Programs...)
	normalized.Maps = append([]BootstrapMap(nil), normalized.Maps...)
	sort.Slice(normalized.Programs, func(i, j int) bool {
		return normalized.Programs[i].PinName < normalized.Programs[j].PinName
	})
	sort.Slice(normalized.Maps, func(i, j int) bool {
		return normalized.Maps[i].Name < normalized.Maps[j].Name
	})
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal bootstrap manifest: %w", err)
	}
	return append([]byte("aegis-ege/bpf-bootstrap-manifest/v1\x00"), body...), nil
}

func canonicalBootstrapReceiptPayload(receipt BootstrapReceipt) ([]byte, error) {
	normalized := receipt
	normalized.CompletedAt = normalized.CompletedAt.UTC()
	normalized.Programs = append([]PinnedProgramAttestation(nil), normalized.Programs...)
	normalized.Maps = append([]PinnedMapAttestation(nil), normalized.Maps...)
	sort.Slice(normalized.Programs, func(i, j int) bool {
		return normalized.Programs[i].PinName < normalized.Programs[j].PinName
	})
	sort.Slice(normalized.Maps, func(i, j int) bool {
		return normalized.Maps[i].Name < normalized.Maps[j].Name
	})
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal bootstrap receipt: %w", err)
	}
	return append([]byte("aegis-ege/bpf-bootstrap-receipt/v1\x00"), body...), nil
}

func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file permissions %o are too broad; require 0600 or stricter", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("invalid Ed25519 private key length %d", len(raw))
	}
}

func LoadSignedBootstrapManifest(path string) (SignedBootstrapManifest, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return SignedBootstrapManifest{}, err
	}
	var signed SignedBootstrapManifest
	if err := json.Unmarshal(payload, &signed); err != nil {
		return SignedBootstrapManifest{}, fmt.Errorf("decode signed bootstrap manifest: %w", err)
	}
	return signed, nil
}

func WriteSignedBootstrapManifest(path string, signed SignedBootstrapManifest) error {
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o644)
}

func WriteSignedBootstrapReceipt(path string, signed SignedBootstrapReceipt) error {
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o600)
}

