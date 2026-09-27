package ege

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func approvalPublicKeyPEM(t *testing.T, authority *Ed25519Authority) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(authority.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestPublicKeyVerifierAcceptsApprovalFromMatchingAuthority(t *testing.T) {
	ctx := context.Background()
	signer, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519PublicKeyVerifierPEM(approvalPublicKeyPEM(t, signer))
	if err != nil {
		t.Fatal(err)
	}

	approval, err := SignApproval(ctx, signer, ApprovalClaims{
		ApprovalID:      "approval-1",
		IntentID:        "intent-1",
		ApproverID:      "human:operator",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		Action:          "drain",
		ResourceVersion: "100",
		PlanDigest:      "sha256:plan",
		ValidUntil:      time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyApproval(ctx, verifier, approval); err != nil {
		t.Fatalf("matching public verifier rejected approval: %v", err)
	}
	if verifier.KeyID() != approval.KeyID {
		t.Fatalf("key id mismatch: verifier=%s approval=%s", verifier.KeyID(), approval.KeyID)
	}
}

func TestPublicKeyVerifierRejectsDifferentApprovalKey(t *testing.T) {
	ctx := context.Background()
	signer, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519PublicKeyVerifierPEM(approvalPublicKeyPEM(t, other))
	if err != nil {
		t.Fatal(err)
	}

	approval, err := SignApproval(ctx, signer, ApprovalClaims{
		ApprovalID:      "approval-1",
		IntentID:        "intent-1",
		ApproverID:      "human:operator",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		Action:          "drain",
		ResourceVersion: "100",
		PlanDigest:      "sha256:plan",
		ValidUntil:      time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyApproval(ctx, verifier, approval); err == nil {
		t.Fatal("approval signed by a different key unexpectedly verified")
	}
}

func TestPublicKeyVerifierRejectsPrivateKeyPEM(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(authority.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = NewEd25519PublicKeyVerifierPEM(privatePEM)
	if err == nil || !strings.Contains(err.Error(), "PUBLIC KEY") {
		t.Fatalf("expected private key PEM rejection, got %v", err)
	}
}

func TestPublicKeyVerifierRejectsTrailingNonWhitespaceData(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	data := append(approvalPublicKeyPEM(t, authority), []byte("unexpected")...)
	_, err = NewEd25519PublicKeyVerifierPEM(data)
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected trailing-data rejection, got %v", err)
	}
}
