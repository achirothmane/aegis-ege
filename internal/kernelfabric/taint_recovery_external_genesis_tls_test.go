package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func externalWitnessGenesisEnvelopeWithTLSNameForTest(
	t *testing.T,
	authorityPublic ed25519.PublicKey,
	requiredWitnessID string,
	tlsServerName string,
) []byte {
	t.Helper()
	keyID, err := BootstrapKeyID(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"external_recovery_witness": ExternalRecoveryWitnessGenesisPolicy{
			Protocol:                  ExternalRecoveryWitnessGenesisPolicyVersion,
			ProfileAuthorityKeyID:     keyID,
			ProfileAuthorityPublicKey: base64.StdEncoding.EncodeToString(authorityPublic),
			RequiredWitnessID:         requiredWitnessID,
			TLSServerName:             tlsServerName,
			MinimumProfileEpoch:       1,
			MinimumPolicyEpoch:        1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testTLSServerName(t *testing.T, server *httptest.Server) string {
	t.Helper()
	certificate := server.Certificate()
	if len(certificate.DNSNames) > 0 {
		return certificate.DNSNames[0]
	}
	if len(certificate.IPAddresses) > 0 {
		return certificate.IPAddresses[0].String()
	}
	t.Fatal("httptest TLS certificate has no DNS or IP identity")
	return ""
}

func TestGenesisBoundRemoteWitnessUsesPinnedTLSServerName(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 11)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)

	profileAuthorityPublic, profileAuthorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"genesis-tls"}`))
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
	tlsServerName := testTLSServerName(t, server)
	envelope := externalWitnessGenesisEnvelopeWithTLSNameForTest(
		t,
		profileAuthorityPublic,
		"external/recovery-witness-b",
		tlsServerName,
	)
	binding, err := ParseGenesisExternalRecoveryWitnessBinding(
		envelope,
		genesisEnvelopeDigestForTest(envelope),
	)
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
			WitnessID:            "external/recovery-witness-b",
			WitnessKeyID:         trust.signedManifest.Manifest.WitnessKeyID,
			Endpoint:             server.URL,
			TLSTrustAnchorSHA256: tlsHash,
			PolicyEpoch:          policy.epoch,
			PolicyHash:           policy.hash,
		},
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := binding.VerifyProfile(signedProfile, trust.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.VerifyMountedTLSCertificate(certPEM, profile); err != nil {
		t.Fatalf("Genesis-pinned mounted TLS certificate rejected: %v", err)
	}
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
	remote, verified, err := binding.NewRemoteWitness(
		signedProfile,
		trust.root,
		certPEM,
		2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Profile() != profile.Profile() {
		t.Fatal("Genesis remote constructor changed verified profile")
	}
	partial, err := trust.root.SignAuthorityRequest(auth, trust.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := remote.CoSignWithReceipt(context.Background(), partial); err != nil {
		t.Fatalf("Genesis-pinned TLS witness co-sign failed: %v", err)
	}

	wrongEnvelope := externalWitnessGenesisEnvelopeWithTLSNameForTest(
		t,
		profileAuthorityPublic,
		"external/recovery-witness-b",
		"wrong-witness.example",
	)
	wrongBinding, err := ParseGenesisExternalRecoveryWitnessBinding(
		wrongEnvelope,
		genesisEnvelopeDigestForTest(wrongEnvelope),
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := wrongBinding.VerifyProfile(signedProfile, trust.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongBinding.VerifyMountedTLSCertificate(certPEM, wrongProfile); err == nil {
		t.Fatal("mounted witness TLS certificate satisfied substituted Genesis server name")
	}
	wrongRemote, _, err := wrongBinding.NewRemoteWitness(
		signedProfile,
		trust.root,
		certPEM,
		2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongRemote.CoSignWithReceipt(context.Background(), partial); err == nil {
		t.Fatal("remote witness completed TLS under substituted Genesis server name")
	}
}
