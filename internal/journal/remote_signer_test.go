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

func TestRemoteSignerUsesHTTPSAndReturnsSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "kms-key-v1"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sign" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			KeyID   string `json:"key_id"`
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.KeyID != keyID {
			t.Fatalf("unexpected key id %q", request.KeyID)
		}
		payload, err := base64.StdEncoding.DecodeString(request.Payload)
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		signature := ed25519.Sign(privateKey, payload)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":    keyID,
			"signature": base64.StdEncoding.EncodeToString(signature),
		})
	}))
	defer server.Close()

	signer, err := NewRemoteSigner(keyID, server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("anchor-payload")
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("remote signature did not verify")
	}
}

func TestRemoteSignerRejectsPlainHTTP(t *testing.T) {
	if _, err := NewRemoteSigner(
		"key",
		"http://127.0.0.1:8080",
		&http.Client{},
	); err == nil {
		t.Fatal("plain HTTP signer endpoint must be rejected")
	}
}

func TestRemoteSignerRejectsWrongReturnedKeyID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":    "different-key",
			"signature": base64.StdEncoding.EncodeToString([]byte("signature")),
		})
	}))
	defer server.Close()

	signer, err := NewRemoteSigner("expected-key", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), []byte("payload")); err == nil {
		t.Fatal("wrong returned key id must fail closed")
	}
}
