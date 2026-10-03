package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

type taintRecoveryTrustFixture struct {
	authorityPublic   ed25519.PublicKey
	authorityPrivate  ed25519.PrivateKey
	witnessPublic     ed25519.PublicKey
	witnessPrivate    ed25519.PrivateKey
	signerPublic      ed25519.PublicKey
	signerPrivate     ed25519.PrivateKey
	signedManifest    SignedTaintRecoveryTrustManifest
	root              *TaintRecoveryTrustRoot
}

func newTaintRecoveryTrustFixture(t *testing.T, epoch uint64) taintRecoveryTrustFixture {
	t.Helper()
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityKeyID, err := BootstrapKeyID(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	witnessKeyID, err := BootstrapKeyID(witnessPublic)
	if err != nil {
		t.Fatal(err)
	}
	manifest := TaintRecoveryTrustManifest{
		Version:            TaintRecoveryTrustManifestVersion,
		TrustEpoch:         epoch,
		AuthorityPrincipal: "principal-a/recovery-authority",
		AuthorityKeyID:     authorityKeyID,
		AuthorityPublicKey: base64.StdEncoding.EncodeToString(authorityPublic),
		WitnessPrincipal:   "principal-b/recovery-witness",
		WitnessKeyID:       witnessKeyID,
		WitnessPublicKey:   base64.StdEncoding.EncodeToString(witnessPublic),
	}
	signedManifest, err := SignTaintRecoveryTrustManifest(manifest, signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTaintRecoveryTrustRoot(signedManifest, signerPublic, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return taintRecoveryTrustFixture{
		authorityPublic:  authorityPublic,
		authorityPrivate: authorityPrivate,
		witnessPublic:    witnessPublic,
		witnessPrivate:   witnessPrivate,
		signerPublic:     signerPublic,
		signerPrivate:    signerPrivate,
		signedManifest:   signedManifest,
		root:             root,
	}
}

func TestTaintRecoveryTrustRootAcceptsOnlyPinnedRecoveryPrincipals(t *testing.T) {
	auth, _, _ := testTaintRecoveryAuthorization(t)
	fixture := newTaintRecoveryTrustFixture(t, 7)
	signed, err := SignJointTaintRecoveryAuthorization(
		auth,
		fixture.authorityPrivate,
		fixture.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := auth.NotBefore.Add(30 * time.Second)
	if err := fixture.root.Verify(signed, now); err != nil {
		t.Fatalf("trusted recovery principals rejected: %v", err)
	}

	_, alternateAuthorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := SignJointTaintRecoveryAuthorization(
		auth,
		alternateAuthorityPrivate,
		fixture.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.root.Verify(alternate, now); err == nil {
		t.Fatal("valid two-signature authorization with untrusted authority key was accepted")
	}

	_, alternateWitnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err = SignJointTaintRecoveryAuthorization(
		auth,
		fixture.authorityPrivate,
		alternateWitnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.root.Verify(alternate, now); err == nil {
		t.Fatal("valid two-signature authorization with untrusted witness key was accepted")
	}
}

func TestTaintRecoveryTrustRootRejectsManifestRollbackAndTamper(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 7)

	if _, err := NewTaintRecoveryTrustRoot(
		fixture.signedManifest,
		fixture.signerPublic,
		8,
	); err == nil {
		t.Fatal("recovery trust manifest below the relying-context epoch floor was accepted")
	}

	tampered := fixture.signedManifest
	tampered.Manifest.WitnessPrincipal = "principal-c/replacement-witness"
	if _, err := NewTaintRecoveryTrustRoot(
		tampered,
		fixture.signerPublic,
		7,
	); err == nil {
		t.Fatal("tampered recovery trust manifest was accepted")
	}

	otherSignerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaintRecoveryTrustRoot(
		fixture.signedManifest,
		otherSignerPublic,
		7,
	); err == nil {
		t.Fatal("recovery trust manifest verified under an unrelated signer root")
	}
}

func TestTaintRecoveryTrustManifestRejectsOneKeyForBothPrincipals(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := TaintRecoveryTrustManifest{
		Version:            TaintRecoveryTrustManifestVersion,
		TrustEpoch:         1,
		AuthorityPrincipal: "principal-a",
		AuthorityKeyID:     keyID,
		AuthorityPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		WitnessPrincipal:   "principal-b",
		WitnessKeyID:       keyID,
		WitnessPublicKey:   base64.StdEncoding.EncodeToString(publicKey),
	}
	if _, err := SignTaintRecoveryTrustManifest(manifest, signerPrivate); err == nil {
		t.Fatal("one key was accepted for both recovery trust principals")
	}
	_ = signerPublic
}
