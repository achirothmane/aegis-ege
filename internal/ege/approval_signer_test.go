package ege

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestDurablePrivateSignerAndPublicVerifierShareStableKeyID(t *testing.T) {
	ctx := context.Background()
	original, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(original.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := approvalPublicKeyPEM(t, original)

	signerAfterRestart, err := NewEd25519AuthorityPKCS8PEM(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	daemonVerifier, err := NewEd25519PublicKeyVerifierPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if signerAfterRestart.keyID != daemonVerifier.KeyID() {
		t.Fatalf("durable key ids differ: signer=%s verifier=%s", signerAfterRestart.keyID, daemonVerifier.KeyID())
	}

	approval, err := SignApproval(ctx, signerAfterRestart, ApprovalClaims{
		ApprovalID:      "approval-restart-1",
		IntentID:        "intent-restart-1",
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
	if err := VerifyApproval(ctx, daemonVerifier, approval); err != nil {
		t.Fatalf("durably loaded signer approval rejected by public verifier: %v", err)
	}
}

func TestDurablePrivateSignerRejectsPublicPEM(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewEd25519AuthorityPKCS8PEM(approvalPublicKeyPEM(t, authority))
	if err == nil {
		t.Fatal("public key PEM unexpectedly accepted as signing private key")
	}
}
