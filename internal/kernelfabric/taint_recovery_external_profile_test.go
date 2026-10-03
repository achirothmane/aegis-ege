package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testProfiledWitnessPolicy struct {
	epoch uint64
	hash  string
	deny  bool
}

func (p testProfiledWitnessPolicy) AdmitTaintRecoveryWitness(
	context.Context,
	TaintRecoveryAuthorization,
) error {
	if p.deny {
		return errors.New("denied")
	}
	return nil
}

func (p testProfiledWitnessPolicy) RecoveryWitnessPolicyEpoch() uint64 {
	return p.epoch
}

func (p testProfiledWitnessPolicy) RecoveryWitnessPolicyHash() (string, error) {
	return p.hash, nil
}

func newExternalWitnessProfileFixture(
	t *testing.T,
	trust taintRecoveryTrustFixture,
	endpoint string,
	tlsPEM []byte,
	policyEpoch uint64,
	policyHash string,
	profileEpoch uint64,
) (*VerifiedExternalRecoveryWitnessProfile, SignedExternalRecoveryWitnessProfile) {
	t.Helper()
	tlsHash, err := TLSCertificatePEMSHA256(tlsPEM)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignExternalRecoveryWitnessProfile(
		ExternalRecoveryWitnessProfile{
			Version:              ExternalRecoveryWitnessProfileVersion,
			ProfileEpoch:         profileEpoch,
			WitnessID:            "external/recovery-witness-b",
			WitnessKeyID:         trust.signedManifest.Manifest.WitnessKeyID,
			Endpoint:             endpoint,
			TLSTrustAnchorSHA256: tlsHash,
			PolicyEpoch:          policyEpoch,
			PolicyHash:           policyHash,
		},
		trust.signerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyExternalRecoveryWitnessProfile(
		signed,
		trust.signerPublic,
		trust.root,
		profileEpoch,
		policyEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	return verified, signed
}

func TestExternalRecoveryWitnessProfileRejectsRollbackAndTamper(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 5)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	tlsPEM := []byte("test-trust-anchor")
	profile, signed := newExternalWitnessProfileFixture(
		t,
		trust,
		"https://witness.example",
		tlsPEM,
		7,
		policyHash,
		9,
	)
	if profile.Profile().PolicyEpoch != 7 {
		t.Fatalf("verified policy epoch=%d", profile.Profile().PolicyEpoch)
	}

	if _, err := VerifyExternalRecoveryWitnessProfile(
		signed,
		trust.signerPublic,
		trust.root,
		10,
		7,
	); err == nil {
		t.Fatal("profile epoch rollback was accepted")
	}
	if _, err := VerifyExternalRecoveryWitnessProfile(
		signed,
		trust.signerPublic,
		trust.root,
		9,
		8,
	); err == nil {
		t.Fatal("policy epoch rollback was accepted")
	}

	tampered := signed
	tampered.Profile.Endpoint = "https://replacement.example"
	if _, err := VerifyExternalRecoveryWitnessProfile(
		tampered,
		trust.signerPublic,
		trust.root,
		9,
		7,
	); err == nil {
		t.Fatal("post-signature witness endpoint change was accepted")
	}

	_, otherWitnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyID, err := BootstrapKeyID(otherWitnessPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	unpinned := signed.Profile
	unpinned.WitnessKeyID = otherKeyID
	unpinnedSigned, err := SignExternalRecoveryWitnessProfile(unpinned, trust.signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExternalRecoveryWitnessProfile(
		unpinnedSigned,
		trust.signerPublic,
		trust.root,
		9,
		7,
	); err == nil {
		t.Fatal("profile with unpinned witness key was accepted")
	}
}

func TestProfiledWitnessHandlerRejectsPolicyContinuityMismatch(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 2)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"pinned"}`))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := newExternalWitnessProfileFixture(
		t,
		trust,
		"https://witness.example",
		[]byte("tls-anchor"),
		3,
		policyHash,
		4,
	)

	if _, err := NewProfiledTaintRecoveryWitnessHandler(
		trust.root,
		trust.witnessPrivate,
		testProfiledWitnessPolicy{epoch: 4, hash: policyHash},
		profile,
		time.Now,
	); err == nil {
		t.Fatal("handler started with policy epoch different from pinned profile")
	}
	if _, err := NewProfiledTaintRecoveryWitnessHandler(
		trust.root,
		trust.witnessPrivate,
		testProfiledWitnessPolicy{epoch: 3, hash: "sha256:" + strings.Repeat("f", 64)},
		profile,
		time.Now,
	); err == nil {
		t.Fatal("handler started with policy hash different from pinned profile")
	}
}

func TestProfiledRemoteWitnessRejectsEndpointAndTLSSubstitution(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 3)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	tlsPEM := []byte("tls-anchor-a")
	profile, _ := newExternalWitnessProfileFixture(
		t,
		trust,
		"https://witness.example",
		tlsPEM,
		1,
		policyHash,
		1,
	)
	if _, err := NewProfiledRemoteTaintRecoveryWitness(
		"https://replacement.example",
		trust.root,
		profile,
		tlsPEM,
		&http.Client{},
	); err == nil {
		t.Fatal("profiled client accepted substituted endpoint")
	}
	if _, err := NewProfiledRemoteTaintRecoveryWitness(
		"https://witness.example",
		trust.root,
		profile,
		[]byte("tls-anchor-b"),
		&http.Client{},
	); err == nil {
		t.Fatal("profiled client accepted substituted TLS trust anchor")
	}
}

func TestWitnessRecoveryReceiptRejectsValidSignatureUnderDifferentProfile(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 4)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	joint, err := SignJointTaintRecoveryAuthorization(
		auth,
		trust.authorityPrivate,
		trust.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := JointTaintRecoveryCommitmentDigest(joint)
	if err != nil {
		t.Fatal(err)
	}
	policyHashA, _ := CanonicalJSONSHA256([]byte(`{"policy":"a"}`))
	policyHashB, _ := CanonicalJSONSHA256([]byte(`{"policy":"b"}`))
	profileA, _ := newExternalWitnessProfileFixture(
		t, trust, "https://witness.example", []byte("tls-a"), 8, policyHashA, 11,
	)
	profileB, _ := newExternalWitnessProfileFixture(
		t, trust, "https://witness.example", []byte("tls-a"), 9, policyHashB, 12,
	)
	receipt, err := signWitnessRecoveryReceipt(
		profileB.Profile(),
		auth.AuthorizationID,
		commitment,
		"nonce-1",
		time.Now().UTC(),
		trust.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWitnessRecoveryReceipt(
		receipt,
		profileA,
		joint,
		"nonce-1",
		trust.witnessPublic,
	); err == nil {
		t.Fatal("valid B-signed receipt from a different policy/profile continuity was accepted")
	}
}

func TestProfiledRemoteWitnessReturnsVerifiedReceipt(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 6)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"live"}`))
	if err != nil {
		t.Fatal(err)
	}
	policy := testProfiledWitnessPolicy{epoch: 5, hash: policyHash}

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
	profile, _ := newExternalWitnessProfileFixture(
		t,
		trust,
		server.URL,
		certPEM,
		policy.epoch,
		policy.hash,
		1,
	)
	inner, err = NewProfiledTaintRecoveryWitnessHandler(
		trust.root,
		trust.witnessPrivate,
		policy,
		profile,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewProfiledRemoteTaintRecoveryWitness(
		server.URL,
		trust.root,
		profile,
		certPEM,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := trust.root.SignAuthorityRequest(auth, trust.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	joint, receipt, err := remote.CoSignWithReceipt(context.Background(), partial)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.root.Verify(joint, now); err != nil {
		t.Fatal(err)
	}
	if receipt.PolicyEpoch != policy.epoch || receipt.PolicyHash != policy.hash {
		t.Fatalf("receipt policy continuity=%d/%s want=%d/%s",
			receipt.PolicyEpoch, receipt.PolicyHash, policy.epoch, policy.hash)
	}
}
