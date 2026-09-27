package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

func BuildNetworkBootstrapManifest(
	artifactPath string,
	notBefore time.Time,
	notAfter time.Time,
) (BootstrapManifest, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("open BPF artifact: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("stat BPF artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return BootstrapManifest{}, fmt.Errorf("BPF artifact must be a non-empty regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return BootstrapManifest{}, fmt.Errorf("hash BPF artifact: %w", err)
	}

	manifest := BootstrapManifest{
		Version:        BootstrapManifestVersion,
		ArtifactSHA256: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		ArtifactSize:   info.Size(),
		ABIVersion:     ABIVersion,
		NotBefore:      notBefore.UTC(),
		NotAfter:       notAfter.UTC(),
		Programs: []BootstrapProgram{
			{
				PinName:    "aegis_connect4",
				Name:       "aegis_connect4",
				Type:       "cgroup_sock_addr",
				AttachType: "connect4",
			},
			{
				PinName:    "aegis_connect6",
				Name:       "aegis_connect6",
				Type:       "cgroup_sock_addr",
				AttachType: "connect6",
			},
		},
		Maps: []BootstrapMap{
			{Name: "aegis_capsules", Type: "hash"},
			{Name: "aegis_ev_acct", Type: "array"},
			{Name: "aegis_ev_events", Type: "ringbuf"},
			{Name: "aegis_fences", Type: "hash"},
			{Name: "aegis_stats", Type: "percpu_array"},
		},
	}
	if err := ValidateBootstrapManifest(manifest, time.Time{}); err != nil {
		return BootstrapManifest{}, err
	}
	return manifest, nil
}
