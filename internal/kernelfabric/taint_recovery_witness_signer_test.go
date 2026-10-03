package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteRecoveryWitnessSignerSignsOnlyPinnedDomains(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRecoveryWitnessSignerHandler(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	signer, err := NewRemoteRecoveryWitnessSigner(
		server.URL,
		keyID,
		publicKey,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{
		[]byte("aegis-ege/taint-recovery-joint/v1\x00payload"),
		[]byte("aegis-ege/witness-recovery-receipt/v1\x00payload"),
		[]byte("aegis-ege/taint-recovery-witness-response/v1\x00payload"),
	} {
		signature, err := signer.Sign(context.Background(), payload)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(publicKey, payload, signature) {
			t.Fatal("remote signer returned unverifiable allowed-domain signature")
		}
	}
	if _, err := signer.Sign(context.Background(), []byte("unscoped-payload")); err == nil {
		t.Fatal("remote signer accepted payload outside recovery witness signing domains")
	}
}

func TestRemoteRecoveryWitnessSignerRejectsWrongSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire recoveryWitnessSignerRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(wire.Payload)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(recoveryWitnessSignerResponse{
			Protocol:  RecoveryWitnessSignerProtocolV1,
			KeyID:     keyID,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPrivate, payload)),
		})
	}))
	defer server.Close()

	signer, err := NewRemoteRecoveryWitnessSigner(
		server.URL,
		keyID,
		publicKey,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(
		context.Background(),
		[]byte("aegis-ege/taint-recovery-joint/v1\x00payload"),
	); err == nil {
		t.Fatal("remote signer client accepted signature under a different key")
	}
}

type invalidRecoveryWitnessSigner struct {
	keyID string
}

func (s invalidRecoveryWitnessSigner) KeyID() string {
	return s.keyID
}

func (s invalidRecoveryWitnessSigner) Sign(
	context.Context,
	[]byte,
) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestProfiledWitnessFailsClosedOnInvalidExternalSigner(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 12)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)
	policyHash, err := CanonicalJSONSHA256([]byte(`{"policy":"external-signer"}`))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := newExternalWitnessProfileFixture(
		t,
		trust,
		"https://witness.example",
		[]byte("tls-anchor"),
		1,
		policyHash,
		1,
	)
	handler, err := NewProfiledTaintRecoveryWitnessHandlerWithSigner(
		trust.root,
		invalidRecoveryWitnessSigner{keyID: trust.signedManifest.Manifest.WitnessKeyID},
		testProfiledWitnessPolicy{epoch: 1, hash: policyHash},
		profile,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := trust.root.SignAuthorityRequest(auth, trust.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(remoteTaintRecoveryWitnessRequest{
		Protocol:      remoteTaintRecoveryWitnessProtocolV1,
		Authorization: partial,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"https://witness.example/v1/recovery/cosign",
		bytes.NewReader(body),
	)
	request.Header.Set(remoteTaintRecoveryWitnessNonceHeader, "nonce")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid external signer status=%d want=%d", recorder.Code, http.StatusServiceUnavailable)
	}
	if recorder.Body.Len() == 0 {
		t.Fatal("invalid external signer failure returned empty response")
	}
}
