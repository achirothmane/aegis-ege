package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExternalHeadWitnessSignerScopesHeadAndPolicyPayloads(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "external-head-key/test"
	signer, err := NewEd25519ExternalHeadWitnessSigner(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	policy := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 7,
		PolicyHash:   sha256Digest([]byte("external-head-signer-policy")),
	}
	headResponse := remoteHeadResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        "nonce-head",
		WitnessKeyID: keyID,
		Head: remoteHeadWire{
			JournalID:    "capability-root",
			Sequence:     3,
			HeadHash:     sha256Digest([]byte("head-3")),
			KeyID:        "head-key",
			StoreVersion: "rv-3",
		},
		Policy: &policy,
	}
	headPayload, err := remoteWitnessSigningPayload("load", headResponse)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindHead,
		"load",
		headPayload,
	)
	if err != nil {
		t.Fatalf("valid head statement was rejected: %v", err)
	}
	if !ed25519.Verify(publicKey, headPayload, signature) {
		t.Fatal("valid head signature did not verify")
	}

	if _, err := signer.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindHead,
		"advance",
		headPayload,
	); err == nil {
		t.Fatal("head signer accepted operation/payload mismatch")
	}
	if _, err := signer.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindHead,
		"load",
		[]byte(`{"arbitrary":"payload"}`),
	); err == nil {
		t.Fatal("head signer accepted arbitrary payload")
	}

	policyResponse := remotePolicyResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        "nonce-policy",
		WitnessKeyID: keyID,
		Policy:       policy,
	}
	policyPayload, err := remotePolicySigningPayload(
		"policy-current",
		policyResponse,
	)
	if err != nil {
		t.Fatal(err)
	}
	policySignature, err := signer.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindPolicy,
		"policy-current",
		policyPayload,
	)
	if err != nil {
		t.Fatalf("valid policy statement was rejected: %v", err)
	}
	if !ed25519.Verify(publicKey, policyPayload, policySignature) {
		t.Fatal("valid policy signature did not verify")
	}

	if _, err := signer.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindPolicy,
		"load",
		policyPayload,
	); err == nil {
		t.Fatal("policy signer accepted head operation")
	}
}

func TestRemoteExternalHeadWitnessSignerVerifiesCustodySignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "external-head-key/remote"
	handler, err := NewExternalHeadWitnessSignerHandler(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	remote, err := NewRemoteExternalHeadWitnessSigner(
		server.URL,
		keyID,
		publicKey,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 8,
		PolicyHash:   sha256Digest([]byte("remote-signer-policy")),
	}
	response := remotePolicyResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        "nonce-remote",
		WitnessKeyID: keyID,
		Policy:       policy,
	}
	payload, err := remotePolicySigningPayload("policy-current", response)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := remote.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindPolicy,
		"policy-current",
		payload,
	)
	if err != nil {
		t.Fatalf("remote signer failed: %v", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("remote custody signature did not verify")
	}

	if _, err := remote.Sign(
		context.Background(),
		"arbitrary",
		"policy-current",
		payload,
	); err == nil {
		t.Fatal("remote signer accepted arbitrary signing kind")
	}
}

func TestRemoteExternalHeadWitnessSignerRejectsWrongKeyResponse(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "external-head-key/wrong-response"

	server := httptest.NewTLSServer(http.HandlerFunc(func(
		rw http.ResponseWriter,
		request *http.Request,
	) {
		var wire externalHeadWitnessSignerRequest
		if err := json.NewDecoder(request.Body).Decode(&wire); err != nil {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(wire.Payload)
		if err != nil {
			http.Error(rw, "bad payload", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(rw).Encode(externalHeadWitnessSignerResponse{
			Protocol:  ExternalHeadWitnessSignerProtocolV1,
			KeyID:     keyID,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPrivate, payload)),
		})
	}))
	defer server.Close()

	remote, err := NewRemoteExternalHeadWitnessSigner(
		server.URL,
		keyID,
		publicKey,
		server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := QuorumPolicyState{
		Phase:        QuorumPolicyPhaseActive,
		GenesisEpoch: 9,
		PolicyHash:   sha256Digest([]byte("wrong-key-policy")),
	}
	response := remotePolicyResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        "nonce-wrong",
		WitnessKeyID: keyID,
		Policy:       policy,
	}
	payload, err := remotePolicySigningPayload("policy-current", response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Sign(
		context.Background(),
		ExternalHeadWitnessSigningKindPolicy,
		"policy-current",
		payload,
	); err == nil {
		t.Fatal("remote signer accepted signature under wrong key")
	}
}
