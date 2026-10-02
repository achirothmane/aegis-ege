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
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const TaintBootstrapReceiptVersion = "aegis.ege/taint-bpf-bootstrap-receipt/v0"

var ErrTaintBootstrapManifest = errors.New("taint BPF bootstrap manifest is invalid")

var taintBootstrapPrograms = []BootstrapProgram{
	{
		PinName:    "aegis_fperm",
		Name:       "aegis_fperm",
		Type:       "lsm",
		AttachType: "lsm/file_permission",
	},
	{
		PinName:    "aegis_fork",
		Name:       "aegis_fork",
		Type:       "raw_tracepoint",
		AttachType: "raw_tracepoint/sched_process_fork",
	},
	{
		PinName:    "aegis_trename",
		Name:       "aegis_trename",
		Type:       "lsm",
		AttachType: "lsm/inode_rename",
	},
	{
		PinName:    "aegis_tunlink",
		Name:       "aegis_tunlink",
		Type:       "lsm",
		AttachType: "lsm/inode_unlink",
	},
	{
		PinName:    "aegis_tmount",
		Name:       "aegis_tmount",
		Type:       "lsm",
		AttachType: "lsm/sb_mount",
	},
	{
		PinName:    "aegis_tumount",
		Name:       "aegis_tumount",
		Type:       "lsm",
		AttachType: "lsm/sb_umount",
	},
	{
		PinName:    "aegis_tremount",
		Name:       "aegis_tremount",
		Type:       "lsm",
		AttachType: "lsm/sb_remount",
	},
	{
		PinName:    "aegis_tmove",
		Name:       "aegis_tmove",
		Type:       "lsm",
		AttachType: "lsm/move_mount",
	},
	{
		PinName:    "aegis_tpivot",
		Name:       "aegis_tpivot",
		Type:       "lsm",
		AttachType: "lsm/sb_pivotroot",
	},
	{
		PinName:    "aegis_tconn4",
		Name:       "aegis_tconn4",
		Type:       "cgroup_sock_addr",
		AttachType: "connect4",
	},
	{
		PinName:    "aegis_tconn6",
		Name:       "aegis_tconn6",
		Type:       "cgroup_sock_addr",
		AttachType: "connect6",
	},
}

var taintBootstrapMaps = []BootstrapMap{
	{Name: "aegis_ftaint", Type: "hash"},
	{Name: "aegis_ptaint", Type: "hash"},
	{Name: "aegis_tprobe", Type: "hash"},
	{Name: "aegis_tprobe_r", Type: "hash"},
	{Name: "aegis_tacct", Type: "array"},
	{Name: "aegis_tallow", Type: "hash"},
	{Name: "aegis_tcgroups", Type: "hash"},
	{Name: "aegis_tevents", Type: "ringbuf"},
	{Name: "aegis_tfail", Type: "hash"},
	{Name: "aegis_tdirty", Type: "array"},
	{Name: "aegis_tarmed", Type: "array"},
	{Name: "aegis_tsrc", Type: "hash"},
}

func BuildTaintBootstrapManifest(
	artifactPath string,
	notBefore time.Time,
	notAfter time.Time,
) (BootstrapManifest, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("open taint BPF artifact: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("stat taint BPF artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return BootstrapManifest{}, errors.New("taint BPF artifact must be a non-empty regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return BootstrapManifest{}, fmt.Errorf("hash taint BPF artifact: %w", err)
	}

	manifest := BootstrapManifest{
		Version:        BootstrapManifestVersion,
		ArtifactSHA256: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		ArtifactSize:   info.Size(),
		ABIVersion:     ABIVersion,
		NotBefore:      notBefore.UTC(),
		NotAfter:       notAfter.UTC(),
		Programs:       append([]BootstrapProgram(nil), taintBootstrapPrograms...),
		Maps:           append([]BootstrapMap(nil), taintBootstrapMaps...),
	}
	if err := ValidateBootstrapManifest(manifest, time.Time{}); err != nil {
		return BootstrapManifest{}, err
	}
	if err := ValidateTaintBootstrapManifest(manifest); err != nil {
		return BootstrapManifest{}, err
	}
	return manifest, nil
}

// ValidateTaintBootstrapManifest narrows the generic signed BPF manifest to the
// exact experimental taint artifact surface. A signature over an artifact is
// not enough: the expected program/map topology is part of the trusted claim.
func ValidateTaintBootstrapManifest(manifest BootstrapManifest) error {
	if err := ValidateBootstrapManifest(manifest, time.Time{}); err != nil {
		return err
	}
	if !sameBootstrapPrograms(manifest.Programs, taintBootstrapPrograms) {
		return fmt.Errorf("%w: program set differs from taint profile", ErrTaintBootstrapManifest)
	}
	if !sameBootstrapMaps(manifest.Maps, taintBootstrapMaps) {
		return fmt.Errorf("%w: map set differs from taint profile", ErrTaintBootstrapManifest)
	}
	return nil
}

func sameBootstrapPrograms(got, want []BootstrapProgram) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := append([]BootstrapProgram(nil), got...)
	wantCopy := append([]BootstrapProgram(nil), want...)
	sort.Slice(gotCopy, func(i, j int) bool { return gotCopy[i].PinName < gotCopy[j].PinName })
	sort.Slice(wantCopy, func(i, j int) bool { return wantCopy[i].PinName < wantCopy[j].PinName })
	for i := range gotCopy {
		if gotCopy[i] != wantCopy[i] {
			return false
		}
	}
	return true
}

func sameBootstrapMaps(got, want []BootstrapMap) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := append([]BootstrapMap(nil), got...)
	wantCopy := append([]BootstrapMap(nil), want...)
	sort.Slice(gotCopy, func(i, j int) bool { return gotCopy[i].Name < gotCopy[j].Name })
	sort.Slice(wantCopy, func(i, j int) bool { return wantCopy[i].Name < wantCopy[j].Name })
	for i := range gotCopy {
		if gotCopy[i] != wantCopy[i] {
			return false
		}
	}
	return true
}

type TaintPinnedLinkAttestation struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	ProgramPin string `json:"program_pin"`
	AttachType string `json:"attach_type"`
}

type TaintBootstrapReceipt struct {
	Version             string                       `json:"version"`
	ManifestDigest      string                       `json:"manifest_digest"`
	ManifestSignerKeyID string                       `json:"manifest_signer_key_id"`
	ArtifactSHA256      string                       `json:"artifact_sha256"`
	ArtifactSize        int64                        `json:"artifact_size"`
	Host                BootstrapHostSnapshot        `json:"host"`
	CgroupPath          string                       `json:"cgroup_path"`
	Programs            []PinnedProgramAttestation   `json:"programs"`
	Maps                []PinnedMapAttestation       `json:"maps"`
	Links               []TaintPinnedLinkAttestation `json:"links"`
	CompletedAt         time.Time                    `json:"completed_at"`
}

type SignedTaintBootstrapReceipt struct {
	Receipt   TaintBootstrapReceipt `json:"receipt"`
	KeyID     string                `json:"key_id"`
	Signature string                `json:"signature"`
}

func SignTaintBootstrapReceipt(
	receipt TaintBootstrapReceipt,
	privateKey ed25519.PrivateKey,
) (SignedTaintBootstrapReceipt, error) {
	if err := ValidateTaintBootstrapReceipt(receipt); err != nil {
		return SignedTaintBootstrapReceipt{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTaintBootstrapReceipt{}, errors.New("invalid Ed25519 taint-bootstrap attestation key")
	}
	payload, err := canonicalTaintBootstrapReceiptPayload(receipt)
	if err != nil {
		return SignedTaintBootstrapReceipt{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedTaintBootstrapReceipt{}, err
	}
	return SignedTaintBootstrapReceipt{
		Receipt:   receipt,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTaintBootstrapReceipt(
	signed SignedTaintBootstrapReceipt,
	publicKey ed25519.PublicKey,
) error {
	if err := ValidateTaintBootstrapReceipt(signed.Receipt); err != nil {
		return err
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
	payload, err := canonicalTaintBootstrapReceiptPayload(signed.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func ValidateTaintBootstrapReceipt(receipt TaintBootstrapReceipt) error {
	if receipt.Version != TaintBootstrapReceiptVersion {
		return fmt.Errorf("unsupported taint bootstrap receipt version %q", receipt.Version)
	}
	if _, err := ParseSHA256Digest(receipt.ManifestDigest); err != nil {
		return fmt.Errorf("taint bootstrap manifest digest: %w", err)
	}
	if strings.TrimSpace(receipt.ManifestSignerKeyID) == "" {
		return errors.New("taint bootstrap manifest signer key id is required")
	}
	if _, err := ParseSHA256Digest(receipt.ArtifactSHA256); err != nil {
		return fmt.Errorf("taint bootstrap artifact digest: %w", err)
	}
	if receipt.ArtifactSize <= 0 {
		return errors.New("taint bootstrap artifact size must be positive")
	}
	if _, err := ParseSHA256Digest(receipt.Host.BootIDHash); err != nil {
		return fmt.Errorf("taint bootstrap boot id hash: %w", err)
	}
	if strings.TrimSpace(receipt.Host.KernelRelease) == "" ||
		strings.TrimSpace(receipt.Host.BPFFSRoot) == "" ||
		strings.TrimSpace(receipt.CgroupPath) == "" {
		return errors.New("taint bootstrap host/cgroup binding is incomplete")
	}
	if receipt.CompletedAt.IsZero() {
		return errors.New("taint bootstrap completed_at is required")
	}
	if len(receipt.Programs) != len(taintBootstrapPrograms) ||
		len(receipt.Maps) != len(taintBootstrapMaps) ||
		len(receipt.Links) != len(taintBootstrapPrograms) {
		return errors.New("taint bootstrap receipt object cardinality is incomplete")
	}

	expectedPrograms := make(map[string]BootstrapProgram, len(taintBootstrapPrograms))
	for _, expected := range taintBootstrapPrograms {
		expectedPrograms[expected.PinName] = expected
	}
	programPins := make(map[string]struct{}, len(receipt.Programs))
	for _, program := range receipt.Programs {
		if program.ID == 0 ||
			strings.TrimSpace(program.PinName) == "" ||
			strings.TrimSpace(program.Name) == "" ||
			strings.TrimSpace(program.Type) == "" ||
			strings.TrimSpace(program.Tag) == "" ||
			strings.TrimSpace(program.AttachType) == "" {
			return errors.New("taint bootstrap receipt contains incomplete program attestation")
		}
		if _, exists := programPins[program.PinName]; exists {
			return fmt.Errorf("duplicate taint bootstrap program pin %q", program.PinName)
		}
		expected, ok := expectedPrograms[program.PinName]
		if !ok ||
			program.Name != expected.Name ||
			program.Type != expected.Type ||
			program.AttachType != expected.AttachType {
			return fmt.Errorf("taint bootstrap program attestation differs from signed profile: %s", program.PinName)
		}
		programPins[program.PinName] = struct{}{}
	}

	expectedMaps := make(map[string]BootstrapMap, len(taintBootstrapMaps))
	for _, expected := range taintBootstrapMaps {
		expectedMaps[expected.Name] = expected
	}
	mapNames := make(map[string]struct{}, len(receipt.Maps))
	for _, m := range receipt.Maps {
		if m.ID == 0 || strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Type) == "" {
			return errors.New("taint bootstrap receipt contains incomplete map attestation")
		}
		if _, exists := mapNames[m.Name]; exists {
			return fmt.Errorf("duplicate taint bootstrap map %q", m.Name)
		}
		expected, ok := expectedMaps[m.Name]
		if !ok || m.Type != expected.Type {
			return fmt.Errorf("taint bootstrap map attestation differs from signed profile: %s", m.Name)
		}
		mapNames[m.Name] = struct{}{}
	}

	linkNames := make(map[string]struct{}, len(receipt.Links))
	for _, pinnedLink := range receipt.Links {
		if strings.TrimSpace(pinnedLink.Name) == "" ||
			strings.TrimSpace(pinnedLink.Path) == "" ||
			strings.TrimSpace(pinnedLink.ProgramPin) == "" ||
			strings.TrimSpace(pinnedLink.AttachType) == "" {
			return errors.New("taint bootstrap receipt contains incomplete link attestation")
		}
		if _, exists := linkNames[pinnedLink.Name]; exists {
			return fmt.Errorf("duplicate taint bootstrap link %q", pinnedLink.Name)
		}
		expected, ok := expectedPrograms[pinnedLink.Name]
		if !ok ||
			filepath.Base(pinnedLink.ProgramPin) != expected.PinName ||
			filepath.Base(pinnedLink.Path) != expected.PinName ||
			pinnedLink.AttachType != expected.AttachType {
			return fmt.Errorf("taint bootstrap link attestation differs from signed profile: %s", pinnedLink.Name)
		}
		linkNames[pinnedLink.Name] = struct{}{}
	}
	return nil
}

func canonicalTaintBootstrapReceiptPayload(receipt TaintBootstrapReceipt) ([]byte, error) {
	normalized := receipt
	normalized.CompletedAt = normalized.CompletedAt.UTC()
	normalized.Programs = append([]PinnedProgramAttestation(nil), normalized.Programs...)
	normalized.Maps = append([]PinnedMapAttestation(nil), normalized.Maps...)
	normalized.Links = append([]TaintPinnedLinkAttestation(nil), normalized.Links...)
	sort.Slice(normalized.Programs, func(i, j int) bool {
		return normalized.Programs[i].PinName < normalized.Programs[j].PinName
	})
	sort.Slice(normalized.Maps, func(i, j int) bool {
		return normalized.Maps[i].Name < normalized.Maps[j].Name
	})
	sort.Slice(normalized.Links, func(i, j int) bool {
		return normalized.Links[i].Name < normalized.Links[j].Name
	})
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal taint bootstrap receipt: %w", err)
	}
	return append([]byte("aegis-ege/taint-bpf-bootstrap-receipt/v0\x00"), body...), nil
}

func WriteSignedTaintBootstrapReceipt(path string, signed SignedTaintBootstrapReceipt) error {
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signed taint bootstrap receipt: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write signed taint bootstrap receipt: %w", err)
	}
	return nil
}

func LoadSignedTaintBootstrapReceipt(path string) (SignedTaintBootstrapReceipt, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return SignedTaintBootstrapReceipt{}, err
	}
	var signed SignedTaintBootstrapReceipt
	if err := json.Unmarshal(payload, &signed); err != nil {
		return SignedTaintBootstrapReceipt{}, fmt.Errorf("decode signed taint bootstrap receipt: %w", err)
	}
	return signed, nil
}
