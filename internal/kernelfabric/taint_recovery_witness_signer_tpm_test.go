//go:build linux && cgo

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMRecoveryWitnessSignerPreservesIdentityAndCompletesProfiledRecovery(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(20401)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	tpmSigner, err := NewTPMRecoveryWitnessSigner(sim, "")
	if err != nil {
		_ = sim.Close()
		t.Fatal(err)
	}
	verifier := tpmSigner.Verifier()
	if verifier.Algorithm() != RecoveryWitnessSignatureECDSAP256SHA256 {
		t.Fatalf("TPM signer algorithm=%q", verifier.Algorithm())
	}
	encodedWitnessPublic, err := verifier.EncodedPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustSignerPublic, trustSignerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityKeyID, err := BootstrapKeyID(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	signedTrust, err := SignTaintRecoveryTrustManifest(
		TaintRecoveryTrustManifest{
			Version:                   TaintRecoveryTrustManifestVersion,
			TrustEpoch:                1,
			AuthorityPrincipal:        "authority/a",
			AuthorityKeyID:            authorityKeyID,
			AuthorityPublicKey:        base64.StdEncoding.EncodeToString(authorityPublic),
			WitnessPrincipal:          "witness/b",
			WitnessKeyID:              verifier.KeyID(),
			WitnessPublicKey:          encodedWitnessPublic,
			WitnessSignatureAlgorithm: RecoveryWitnessSignatureECDSAP256SHA256,
		},
		trustSignerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTaintRecoveryTrustRoot(signedTrust, trustSignerPublic, 1)
	if err != nil {
		t.Fatal(err)
	}
	if root.witnessKey.Algorithm() != RecoveryWitnessSignatureECDSAP256SHA256 {
		t.Fatalf("root witness algorithm=%q", root.witnessKey.Algorithm())
	}

	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"tpm-b"}`))
	if err != nil {
		t.Fatal(err)
	}
	policy := testProfiledWitnessPolicy{epoch: 1, hash: policyHash}

	var inner http.Handler = http.NotFoundHandler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r)
	}))
	server.StartTLS()
	defer server.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})

	profileAuthorityPublic, profileAuthorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsHash, err := TLSCertificatePEMSHA256(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	signedProfile, err := SignExternalRecoveryWitnessProfile(
		ExternalRecoveryWitnessProfile{
			Version:              ExternalRecoveryWitnessProfileVersion,
			ProfileEpoch:         1,
			WitnessID:            "witness/b",
			WitnessKeyID:         verifier.KeyID(),
			Endpoint:             server.URL,
			TLSTrustAnchorSHA256: tlsHash,
			PolicyEpoch:          1,
			PolicyHash:           policyHash,
		},
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := VerifyExternalRecoveryWitnessProfile(
		signedProfile,
		profileAuthorityPublic,
		root,
		1,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	inner, err = NewProfiledTaintRecoveryWitnessHandlerWithSigner(
		root,
		tpmSigner,
		policy,
		profile,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewProfiledRemoteTaintRecoveryWitness(
		server.URL,
		root,
		profile,
		certPEM,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := root.SignAuthorityRequest(auth, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	joint, receipt, err := remote.CoSignWithReceipt(context.Background(), partial)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Verify(joint, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWitnessRecoveryReceiptWithVerifier(
		receipt,
		profile,
		joint,
		receipt.Nonce,
		verifier,
	); err != nil {
		t.Fatal(err)
	}
	firstKeyID := verifier.KeyID()
	if err := tpmSigner.Close(); err != nil {
		t.Fatal(err)
	}

	sameSim, err := simulator.GetWithFixedSeedInsecure(20401)
	if err != nil {
		t.Fatal(err)
	}
	sameSigner, err := NewTPMRecoveryWitnessSigner(sameSim, "")
	if err != nil {
		_ = sameSim.Close()
		t.Fatal(err)
	}
	if sameSigner.KeyID() != firstKeyID {
		t.Fatalf("same TPM seed changed B identity: got=%s want=%s", sameSigner.KeyID(), firstKeyID)
	}
	if err := sameSigner.Close(); err != nil {
		t.Fatal(err)
	}

	otherSim, err := simulator.GetWithFixedSeedInsecure(20402)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := NewTPMRecoveryWitnessSigner(otherSim, "")
	if err != nil {
		_ = otherSim.Close()
		t.Fatal(err)
	}
	defer otherSigner.Close()
	if otherSigner.KeyID() == firstKeyID {
		t.Fatal("different TPM seed reproduced trusted B identity")
	}
	if _, err := NewProfiledTaintRecoveryWitnessHandlerWithSigner(
		root,
		otherSigner,
		policy,
		profile,
		func() time.Time { return now },
	); err == nil {
		t.Fatal("B handler accepted signer rooted in a different TPM")
	}
}
