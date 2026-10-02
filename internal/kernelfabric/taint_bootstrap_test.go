package kernelfabric

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildTaintBootstrapManifestPinsExactSurface(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, []byte("synthetic-taint-bpf-object"), 0o600); err != nil {
		t.Fatal(err)
	}

	notBefore := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	manifest, err := BuildTaintBootstrapManifest(
		artifact,
		notBefore,
		notBefore.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTaintBootstrapManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Programs) != 6 {
		t.Fatalf("programs=%d want=6", len(manifest.Programs))
	}
	if len(manifest.Maps) != 12 {
		t.Fatalf("maps=%d want=12", len(manifest.Maps))
	}
}

func TestValidateTaintBootstrapManifestRejectsProgramExpansion(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, []byte("synthetic-taint-bpf-object"), 0o600); err != nil {
		t.Fatal(err)
	}

	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	manifest, err := BuildTaintBootstrapManifest(artifact, start, start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	tampered := manifest
	tampered.Programs = append([]BootstrapProgram(nil), manifest.Programs...)
	tampered.Programs[0].AttachType = "lsm/bprm_check_security"
	if err := ValidateTaintBootstrapManifest(tampered); err == nil {
		t.Fatal("taint manifest accepted different LSM hook")
	}

	tampered = manifest
	tampered.Maps = append([]BootstrapMap(nil), manifest.Maps...)
	tampered.Maps[0].Name = "other_map"
	if err := ValidateTaintBootstrapManifest(tampered); err == nil {
		t.Fatal("taint manifest accepted different map surface")
	}
}
