package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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
		Type:       "tracepoint",
		AttachType: "tracepoint/sched/sched_process_fork",
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
	{Name: "aegis_tacct", Type: "array"},
	{Name: "aegis_tallow", Type: "hash"},
	{Name: "aegis_tcgroups", Type: "hash"},
	{Name: "aegis_tevents", Type: "ringbuf"},
	{Name: "aegis_tfail", Type: "hash"},
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
