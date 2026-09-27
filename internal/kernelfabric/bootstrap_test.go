package kernelfabric

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bootstrapTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func bootstrapTestArtifact(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aegis_connect.bpf.o")
	if err := os.WriteFile(path, []byte("test-bpf-object-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bootstrapTestManifest(t *testing.T, artifact string) BootstrapManifest {
	t.Helper()
	now := time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC)
	manifest, err := BuildNetworkBootstrapManifest(
		artifact,
		now.Add(-time.Minute),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestSignedBootstrapManifestRejectsTamper(t *testing.T) {
	artifact := bootstrapTestArtifact(t)
	manifest := bootstrapTestManifest(t, artifact)
	pub, priv := bootstrapTestKeys(t)

	signed, err := SignBootstrapManifest(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := BootstrapKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	trust := BootstrapTrustStore{keyID: pub}
	now := time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC)

	if err := VerifySignedBootstrapManifest(signed, trust, now); err != nil {
		t.Fatalf("valid signed manifest rejected: %v", err)
	}

	tampered := signed
	tampered.Manifest.Programs = append([]BootstrapProgram(nil), signed.Manifest.Programs...)
	tampered.Manifest.Programs[0].AttachType = "connect6"
	if err := VerifySignedBootstrapManifest(tampered, trust, now); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("expected signature rejection after manifest tamper, got %v", err)
	}
}

func TestSignedBootstrapManifestRejectsExpiredWindow(t *testing.T) {
	artifact := bootstrapTestArtifact(t)
	manifest := bootstrapTestManifest(t, artifact)
	pub, priv := bootstrapTestKeys(t)
	signed, err := SignBootstrapManifest(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := BootstrapKeyID(pub)
	err = VerifySignedBootstrapManifest(
		signed,
		BootstrapTrustStore{keyID: pub},
		manifest.NotAfter,
	)
	if !errors.Is(err, ErrBootstrapManifestExpired) {
		t.Fatalf("expected manifest expiry, got %v", err)
	}
}

func TestBootstrapArtifactTamperIsRejected(t *testing.T) {
	artifact := bootstrapTestArtifact(t)
	manifest := bootstrapTestManifest(t, artifact)
	if err := os.WriteFile(artifact, []byte("tampered-object!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBootstrapArtifact(artifact, manifest); !errors.Is(err, ErrBootstrapArtifactMismatch) {
		t.Fatalf("expected artifact mismatch, got %v", err)
	}
}

func TestBootstrapPrivateKeyRequiresRestrictedPermissions(t *testing.T) {
	_, priv := bootstrapTestKeys(t)
	path := filepath.Join(t.TempDir(), "private.key")
	payload := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEd25519PrivateKey(path); err == nil {
		t.Fatal("expected broad private-key permissions to be rejected")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEd25519PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, priv) {
		t.Fatal("loaded private key differs")
	}
}

func TestSignedBootstrapReceiptRoundTrip(t *testing.T) {
	pub, priv := bootstrapTestKeys(t)
	receipt := BootstrapReceipt{
		Version:             BootstrapReceiptVersion,
		ManifestDigest:      "sha256:" + strings.Repeat("a", 64),
		ManifestSignerKeyID: "ed25519:manifest",
		ArtifactSHA256:      "sha256:" + strings.Repeat("b", 64),
		ArtifactSize:        123,
		Host: BootstrapHostSnapshot{
			BootIDHash:    "sha256:" + strings.Repeat("c", 64),
			KernelRelease: "6.18-test",
			LockdownMode:  "integrity",
			BPFFSRoot:     "/sys/fs/bpf/aegis-ege",
		},
		CgroupPath: "/sys/fs/cgroup/workload",
		Programs: []PinnedProgramAttestation{{
			PinName:    "aegis_connect4",
			ID:         11,
			Name:       "aegis_connect4",
			Type:       "cgroup_sock_addr",
			Tag:        "0123456789abcdef",
			AttachType: "connect4",
		}},
		Maps: []PinnedMapAttestation{{
			Name:       "aegis_capsules",
			ID:         22,
			Type:       "hash",
			KeySize:    40,
			ValueSize:  240,
			MaxEntries: 16384,
		}},
		CompletedAt: time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC),
	}
	signed, err := SignBootstrapReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedBootstrapReceipt(signed, pub); err != nil {
		t.Fatalf("valid bootstrap receipt rejected: %v", err)
	}
	signed.Receipt.CgroupPath = "/sys/fs/cgroup/other"
	if err := VerifySignedBootstrapReceipt(signed, pub); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered receipt was not rejected: %v", err)
	}
}

type fakeBootstrapHostProvider struct {
	snapshot BootstrapHostSnapshot
	err      error
}

func (p fakeBootstrapHostProvider) Snapshot(string) (BootstrapHostSnapshot, error) {
	return p.snapshot, p.err
}

type fakeBootstrapRunner struct {
	calls          [][]string
	failAttachType string
	badProgramType bool
}

func (f *fakeBootstrapRunner) Run(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)

	if len(args) >= 6 && args[0] == "cgroup" && args[1] == "attach" {
		if args[3] == f.failAttachType {
			return []byte("attach failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	if len(args) >= 5 && args[0] == "cgroup" && args[1] == "detach" {
		return nil, nil
	}
	if len(args) >= 6 && args[0] == "prog" && args[1] == "loadall" {
		return nil, nil
	}
	if len(args) >= 5 && args[0] == "-j" && args[1] == "prog" && args[2] == "show" && args[3] == "pinned" {
		pin := filepath.Base(args[4])
		typ := "cgroup_sock_addr"
		if f.badProgramType && pin == "aegis_connect4" {
			typ = "xdp"
		}
		return []byte(`{"id":11,"type":"` + typ + `","name":"` + pin + `","tag":"0123456789abcdef"}`), nil
	}
	if len(args) >= 5 && args[0] == "-j" && args[1] == "map" && args[2] == "show" && args[3] == "pinned" {
		name := filepath.Base(args[4])
		typ := map[string]string{
			"aegis_capsules":            "hash",
			"aegis_ev_acct": "array",
			"aegis_ev_events":     "ringbuf",
			"aegis_fences":              "hash",
			"aegis_stats":               "percpu_array",
		}[name]
		return []byte(`{"id":22,"type":"` + typ + `","name":"` + name + `","bytes_key":4,"bytes_value":8,"max_entries":16}`), nil
	}
	return nil, nil
}

func signedBootstrapTestRequest(
	t *testing.T,
	runner *fakeBootstrapRunner,
) (BootstrapLoader, BootstrapLoadRequest, ed25519.PublicKey) {
	t.Helper()
	artifact := bootstrapTestArtifact(t)
	manifest := bootstrapTestManifest(t, artifact)
	signerPub, signerPriv := bootstrapTestKeys(t)
	signed, err := SignBootstrapManifest(manifest, signerPriv)
	if err != nil {
		t.Fatal(err)
	}
	signerKeyID, _ := BootstrapKeyID(signerPub)

	attestPub, attestPriv := bootstrapTestKeys(t)
	root := filepath.Join(t.TempDir(), "bpffs", "aegis-ege")
	cgroup := filepath.Join(t.TempDir(), "cgroup")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}

	bpftoolPath := filepath.Join(t.TempDir(), "bpftool")
	if err := os.WriteFile(bpftoolPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	return BootstrapLoader{
			BPFToolPath: bpftoolPath,
			Runner:      runner,
			HostProvider: fakeBootstrapHostProvider{snapshot: BootstrapHostSnapshot{
				BootIDHash:    "sha256:" + strings.Repeat("d", 64),
				KernelRelease: "6.18-test",
				LockdownMode:  "integrity",
				BPFFSRoot:     root,
			}},
		}, BootstrapLoadRequest{
			ArtifactPath:   artifact,
			CgroupPath:     cgroup,
			BPFFSRoot:      root,
			SignedManifest: signed,
			Trust:                 BootstrapTrustStore{signerKeyID: signerPub},
			AttestationPrivateKey: attestPriv,
			Now:                   time.Date(2026, 9, 27, 22, 0, 0, 0, time.UTC),
		}, attestPub
}

func TestBootstrapLoaderVerifiesBeforeAttachAndSignsReceipt(t *testing.T) {
	runner := &fakeBootstrapRunner{}
	loader, req, attestPub := signedBootstrapTestRequest(t, runner)
	result, err := loader.LoadAndAttach(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedBootstrapReceipt(result.SignedReceipt, attestPub); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}
	if result.SignedReceipt.Receipt.ManifestSignerKeyID != req.SignedManifest.KeyID {
		t.Fatalf("receipt lost manifest signer identity: %+v", result.SignedReceipt.Receipt)
	}

	firstAttach := -1
	lastInspect := -1
	for i, call := range runner.calls {
		if len(call) > 2 && call[1] == "-j" {
			lastInspect = i
		}
		if len(call) > 3 && call[1] == "cgroup" && call[2] == "attach" && firstAttach == -1 {
			firstAttach = i
		}
	}
	if firstAttach == -1 || lastInspect == -1 || firstAttach <= lastInspect {
		t.Fatalf("attach occurred before all post-load inspections: %v", runner.calls)
	}
}

func TestBootstrapLoaderPostloadMismatchPreventsAttach(t *testing.T) {
	runner := &fakeBootstrapRunner{badProgramType: true}
	loader, req, _ := signedBootstrapTestRequest(t, runner)
	_, err := loader.LoadAndAttach(context.Background(), req)
	if !errors.Is(err, ErrBootstrapPostloadMismatch) {
		t.Fatalf("expected post-load mismatch, got %v", err)
	}
	for _, call := range runner.calls {
		if len(call) > 2 && call[1] == "cgroup" && call[2] == "attach" {
			t.Fatalf("attach occurred after post-load mismatch: %v", call)
		}
	}
}

func TestBootstrapLoaderRollsBackPartialAttach(t *testing.T) {
	runner := &fakeBootstrapRunner{failAttachType: "connect6"}
	loader, req, _ := signedBootstrapTestRequest(t, runner)
	_, err := loader.LoadAndAttach(context.Background(), req)
	if err == nil {
		t.Fatal("expected second attach failure")
	}

	var attach4, attach6, detach4 bool
	for _, call := range runner.calls {
		if len(call) < 4 || call[1] != "cgroup" {
			continue
		}
		switch {
		case call[2] == "attach" && call[4] == "connect4":
			attach4 = true
		case call[2] == "attach" && call[4] == "connect6":
			attach6 = true
		case call[2] == "detach" && call[4] == "connect4":
			detach4 = true
		}
	}
	if !attach4 || !attach6 || !detach4 {
		t.Fatalf("partial attach was not rolled back: %v", runner.calls)
	}
}

func TestBootstrapLoaderUsesVerifiedStagedArtifact(t *testing.T) {
	runner := &fakeBootstrapRunner{}
	loader, req, _ := signedBootstrapTestRequest(t, runner)
	original := req.ArtifactPath
	if _, err := loader.LoadAndAttach(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if len(call) >= 5 && call[1] == "prog" && call[2] == "loadall" {
			if call[3] == original {
				t.Fatalf("loader passed original mutable artifact path to bpftool: %v", call)
			}
			if !strings.Contains(call[3], "aegis-bpf-bootstrap-") {
				t.Fatalf("loader did not use secure staged artifact: %v", call)
			}
			return
		}
	}
	t.Fatalf("no bpftool loadall call observed: %v", runner.calls)
}


func TestBootstrapManifestRejectsOverlongKernelObjectName(t *testing.T) {
	artifact := bootstrapTestArtifact(t)
	manifest := bootstrapTestManifest(t, artifact)
	manifest.Maps = append([]BootstrapMap(nil), manifest.Maps...)
	manifest.Maps[0].Name = "aegis_name_longer_than_kernel_limit"
	if err := ValidateBootstrapManifest(manifest, time.Time{}); err == nil {
		t.Fatal("expected overlong BPF map name to be rejected")
	}
}
