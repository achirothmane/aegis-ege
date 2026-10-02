package server

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTPMNVCapabilityAuthFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nv-auth")
	want := []byte("capability-root-secret")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(want)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadTPMNVCapabilityAuthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded auth = %q, want %q", got, want)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTPMNVCapabilityAuthFile(path); err == nil {
		t.Fatal("expected world-readable TPM auth file to be rejected")
	}
}

func TestLoadTPMNVCapabilityAuthFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte(base64.StdEncoding.EncodeToString([]byte("secret"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTPMNVCapabilityAuthFile(link); err == nil {
		t.Fatal("expected TPM auth symlink to be rejected")
	}
}

func TestNewTPMNVCounterCapabilityAnchorCopiesAuth(t *testing.T) {
	auth := []byte("secret")
	anchor, err := NewTPMNVCounterCapabilityAnchor("/dev/tpmrm0", 0x01500020, auth)
	if err != nil {
		t.Fatal(err)
	}
	auth[0] = 'X'
	if string(anchor.auth) != "secret" {
		t.Fatalf("anchor retained caller-owned auth slice: %q", anchor.auth)
	}
}
