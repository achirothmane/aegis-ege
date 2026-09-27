package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeApprovalPublicKey(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "approval-public.pem")
	if err := os.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEBAApprovalVerifierDisabledNeedsNoKey(t *testing.T) {
	verifier, err := loadEBAApprovalVerifier(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if verifier != nil {
		t.Fatal("disabled EBA conformance unexpectedly loaded a verifier")
	}
}

func TestLoadEBAApprovalVerifierRequiresKeyWhenEnabled(t *testing.T) {
	_, err := loadEBAApprovalVerifier(true, "")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required-key error, got %v", err)
	}
}

func TestLoadEBAApprovalVerifierLoadsDurablePublicKey(t *testing.T) {
	verifier, err := loadEBAApprovalVerifier(true, writeApprovalPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if verifier == nil {
		t.Fatal("expected verifier")
	}
}

func TestLoadEBAApprovalVerifierRejectsMalformedPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadEBAApprovalVerifier(true, path)
	if err == nil || !strings.Contains(err.Error(), "valid PEM") {
		t.Fatalf("expected malformed PEM error, got %v", err)
	}
}
