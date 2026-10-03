package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

type witnessSignerPublicFixture struct {
	publicPath        string
	endpointPath      string
	tlsCertPath       string
	tlsServerNamePath string
	privateKey        ed25519.PrivateKey
}

func newWitnessSignerPublicFixture(t *testing.T, dir string) witnessSignerPublicFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := witnessSignerPublicFixture{
		publicPath:        filepath.Join(dir, "witness-signer-public"),
		endpointPath:      filepath.Join(dir, "witness-signer-endpoint"),
		tlsCertPath:       filepath.Join(dir, "witness-signer-ca.pem"),
		tlsServerNamePath: filepath.Join(dir, "witness-signer-server-name"),
		privateKey:        privateKey,
	}
	files := map[string]string{
		fixture.publicPath:        base64.StdEncoding.EncodeToString(publicKey) + "\n",
		fixture.endpointPath:      "https://recovery-witness-signer.example:9443\n",
		fixture.tlsCertPath:       "-----BEGIN CERTIFICATE-----\nY2k=\n-----END CERTIFICATE-----\n",
		fixture.tlsServerNamePath: "recovery-witness-signer.example\n",
	}
	for path, value := range files {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func TestExternalProfileAuthorityCustodyBoundary(t *testing.T) {
	dir := t.TempDir()
	preparedPath := filepath.Join(dir, "prepared.json")
	unsignedPath := filepath.Join(dir, "unsigned.json")
	signedPath := filepath.Join(dir, "signed.json")
	publicPath := filepath.Join(dir, "profile-authority-public")
	missingSignedPath := filepath.Join(dir, "missing-signed.json")

	profilePublic, profilePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		publicPath,
		[]byte(base64.StdEncoding.EncodeToString(profilePublic)+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	signerFixture := newWitnessSignerPublicFixture(t, dir)
	if err := prepareTaintRecoveryWitness(
		preparedPath,
		unsignedPath,
		publicPath,
		signerFixture.publicPath,
		signerFixture.endpointPath,
		signerFixture.tlsCertPath,
		signerFixture.tlsServerNamePath,
	); err != nil {
		t.Fatal(err)
	}

	preparedRaw, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	privateEncoding := base64.StdEncoding.EncodeToString(profilePrivate)
	if strings.Contains(string(preparedRaw), privateEncoding) {
		t.Fatal("prepared activation bundle contains profile-authority private key")
	}
	if strings.Contains(string(preparedRaw), "profile_authority_private_key") {
		t.Fatal("prepared activation bundle exposes profile-authority private-key field")
	}

	witnessPrivateEncoding := base64.StdEncoding.EncodeToString(signerFixture.privateKey)
	if strings.Contains(string(preparedRaw), witnessPrivateEncoding) {
		t.Fatal("prepared activation bundle contains B witness signing private key")
	}
	if strings.Contains(string(preparedRaw), "witness_private_key") {
		t.Fatal("prepared activation bundle exposes B witness signing private-key field")
	}

	if _, err := verifyPreparedTaintRecoveryWitness(
		preparedPath,
		missingSignedPath,
	); err == nil {
		t.Fatal("activation preflight accepted missing external signed profile")
	}

	unsignedRaw, err := os.ReadFile(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	var unsigned kernelfabric.ExternalRecoveryWitnessProfile
	if err := json.Unmarshal(unsignedRaw, &unsigned); err != nil {
		t.Fatal(err)
	}

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigned, err := kernelfabric.SignExternalRecoveryWitnessProfile(
		unsigned,
		wrongPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(signedPath, wrongSigned, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPreparedTaintRecoveryWitness(
		preparedPath,
		signedPath,
	); err == nil {
		t.Fatal("activation preflight accepted profile signed outside Genesis authority")
	}

	correctSigned, err := kernelfabric.SignExternalRecoveryWitnessProfile(
		unsigned,
		profilePrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(signedPath, correctSigned, 0o644); err != nil {
		t.Fatal(err)
	}
	verified, err := verifyPreparedTaintRecoveryWitness(
		preparedPath,
		signedPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.signedWitnessProfile.SignerKeyID != correctSigned.SignerKeyID {
		t.Fatal("activation preflight changed external profile signer identity")
	}
	if verified.prepared.UnsignedWitnessProfile != unsigned {
		t.Fatal("activation preflight changed prepared witness profile")
	}
}

func TestExternalProfileAuthoritySignatureCannotRetargetPreparedActivation(t *testing.T) {
	dir := t.TempDir()
	preparedPath := filepath.Join(dir, "prepared.json")
	unsignedPath := filepath.Join(dir, "unsigned.json")
	signedPath := filepath.Join(dir, "signed.json")
	publicPath := filepath.Join(dir, "profile-authority-public")

	profilePublic, profilePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		publicPath,
		[]byte(base64.StdEncoding.EncodeToString(profilePublic)+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	signerFixture := newWitnessSignerPublicFixture(t, dir)
	if err := prepareTaintRecoveryWitness(
		preparedPath,
		unsignedPath,
		publicPath,
		signerFixture.publicPath,
		signerFixture.endpointPath,
		signerFixture.tlsCertPath,
		signerFixture.tlsServerNamePath,
	); err != nil {
		t.Fatal(err)
	}

	unsignedRaw, err := os.ReadFile(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	var profile kernelfabric.ExternalRecoveryWitnessProfile
	if err := json.Unmarshal(unsignedRaw, &profile); err != nil {
		t.Fatal(err)
	}
	profile.Endpoint = "https://retargeted.example.invalid"
	retargeted, err := kernelfabric.SignExternalRecoveryWitnessProfile(
		profile,
		profilePrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(signedPath, retargeted, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPreparedTaintRecoveryWitness(
		preparedPath,
		signedPath,
	); err == nil {
		t.Fatal("activation preflight accepted externally signed profile that retargeted prepared activation")
	}
}
