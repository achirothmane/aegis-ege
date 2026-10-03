package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type witnessTestState struct {
	mu      sync.Mutex
	head    ExternalHead
	exists  bool
	version uint64
	keyID   string
	priv    ed25519.PrivateKey
}

func newWitnessTestServer(t *testing.T, state *witnessTestState) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(remoteWitnessNonceHeader)
		if nonce == "" {
			http.Error(w, "nonce required", http.StatusBadRequest)
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/heads/"):
			if !state.exists {
				http.NotFound(w, r)
				return
			}
			writeSignedWitnessResponse(t, w, state, "load", nonce, state.head)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/advance"):
			var request remoteAdvanceRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if request.Protocol != remoteWitnessProtocolV1 {
				http.Error(w, "bad protocol", http.StatusBadRequest)
				return
			}

			expected := remoteWireToExternalHead(request.Expected)
			next := remoteWireToExternalHead(request.Next)
			if !state.exists {
				if expected.Sequence != 0 || expected.HeadHash != "" || expected.StoreVersion != "" {
					http.Error(w, "conflict", http.StatusConflict)
					return
				}
			} else if expected.Sequence != state.head.Sequence ||
				expected.HeadHash != state.head.HeadHash ||
				expected.KeyID != state.head.KeyID ||
				expected.StoreVersion != state.head.StoreVersion {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}

			state.version++
			next.StoreVersion = witnessTestVersion(state.version)
			state.head = next
			state.exists = true
			writeSignedWitnessResponse(t, w, state, "advance", nonce, state.head)

		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewTLSServer(handler)
}

func writeSignedWitnessResponse(
	t *testing.T,
	w http.ResponseWriter,
	state *witnessTestState,
	operation string,
	nonce string,
	head ExternalHead,
) {
	t.Helper()
	response := remoteHeadResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        nonce,
		WitnessKeyID: state.keyID,
		Head:         externalHeadToRemoteWire(head),
	}
	payload, err := remoteWitnessSigningPayload(operation, response)
	if err != nil {
		t.Fatal(err)
	}
	response.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(state.priv, payload))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.Fatal(err)
	}
}

func witnessTestVersion(n uint64) string {
	return "v" + strings.Repeat("x", int(n))
}

func TestRemoteHeadStoreLoadAndAdvanceWithPinnedWitness(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := &witnessTestState{
		keyID: Ed25519KeyID(pub),
		priv:  priv,
	}
	server := newWitnessTestServer(t, state)
	defer server.Close()

	store, err := NewRemoteHeadStore(server.URL, state.keyID, pub, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := store.Load(ctx, "capability-root"); err != ErrExternalHeadNotFound {
		t.Fatalf("Load absent = %v, want %v", err, ErrExternalHeadNotFound)
	}

	zero, err := store.CompareAndAdvance(
		ctx,
		ExternalHead{},
		ExternalHead{
			JournalID: "capability-root",
			Sequence:  0,
			KeyID:     "aegis-ege/capability-root-head/v1",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if zero.Sequence != 0 || zero.StoreVersion == "" {
		t.Fatalf("unexpected zero head: %+v", zero)
	}

	next, err := store.CompareAndAdvance(
		ctx,
		zero,
		ExternalHead{
			JournalID: "capability-root",
			Sequence:  1,
			HeadHash:  strings.Repeat("a", 64),
			KeyID:     "aegis-ege/capability-root-head/v1",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if next.Sequence != 1 || next.HeadHash != strings.Repeat("a", 64) || next.StoreVersion == "" {
		t.Fatalf("unexpected advanced head: %+v", next)
	}

	loaded, err := store.Load(ctx, "capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != next {
		t.Fatalf("Load = %+v, want %+v", loaded, next)
	}
}

func TestRemoteHeadStoreRejectsReplayedSignedResponseWithOldNonce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := Ed25519KeyID(pub)

	stale := remoteHeadResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        "old-request-nonce",
		WitnessKeyID: keyID,
		Head: remoteHeadWire{
			JournalID:    "capability-root",
			Sequence:     7,
			HeadHash:     strings.Repeat("b", 64),
			KeyID:        "aegis-ege/capability-root-head/v1",
			StoreVersion: "v7",
		},
	}
	payload, err := remoteWitnessSigningPayload("load", stale)
	if err != nil {
		t.Fatal(err)
	}
	stale.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(stale)
	}))
	defer server.Close()

	store, err := NewRemoteHeadStore(server.URL, keyID, pub, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), "capability-root"); err == nil ||
		!strings.Contains(err.Error(), "freshness nonce mismatch") {
		t.Fatalf("Load replayed signed response = %v, want nonce mismatch", err)
	}
}

func TestRemoteHeadStoreRejectsForgedWitnessSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := Ed25519KeyID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := remoteHeadResponse{
			Protocol:     remoteWitnessProtocolV1,
			Nonce:        r.Header.Get(remoteWitnessNonceHeader),
			WitnessKeyID: keyID,
			Head: remoteHeadWire{
				JournalID:    "capability-root",
				Sequence:     3,
				HeadHash:     strings.Repeat("c", 64),
				KeyID:        "aegis-ege/capability-root-head/v1",
				StoreVersion: "v3",
			},
		}
		payload, err := remoteWitnessSigningPayload("load", response)
		if err != nil {
			t.Fatal(err)
		}
		response.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPriv, payload))
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	store, err := NewRemoteHeadStore(server.URL, keyID, pub, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), "capability-root"); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("Load forged witness response = %v, want signature verification failure", err)
	}
}

func TestRemoteHeadStoreMapsStaleCASConflict(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := &witnessTestState{
		exists: true,
		head: ExternalHead{
			JournalID:    "capability-root",
			Sequence:     2,
			HeadHash:     strings.Repeat("d", 64),
			KeyID:        "aegis-ege/capability-root-head/v1",
			StoreVersion: "v2",
		},
		version: 2,
		keyID:   Ed25519KeyID(pub),
		priv:    priv,
	}
	server := newWitnessTestServer(t, state)
	defer server.Close()

	store, err := NewRemoteHeadStore(server.URL, state.keyID, pub, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CompareAndAdvance(
		context.Background(),
		ExternalHead{
			JournalID:    "capability-root",
			Sequence:     1,
			HeadHash:     strings.Repeat("a", 64),
			KeyID:        "aegis-ege/capability-root-head/v1",
			StoreVersion: "v1",
		},
		ExternalHead{
			JournalID: "capability-root",
			Sequence:  2,
			HeadHash:  strings.Repeat("e", 64),
			KeyID:     "aegis-ege/capability-root-head/v1",
		},
	)
	if err != ErrExternalHeadConflict {
		t.Fatalf("CompareAndAdvance stale expected = %v, want %v", err, ErrExternalHeadConflict)
	}
}

func TestRemoteHeadStoreRequiresHTTPSAndPinnedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRemoteHeadStore("http://witness.invalid", "w1", pub, &http.Client{}); err == nil {
		t.Fatal("expected HTTP endpoint rejection")
	}
	if _, err := NewRemoteHeadStore("https://witness.invalid", "", pub, &http.Client{}); err == nil {
		t.Fatal("expected empty witness key id rejection")
	}
	if _, err := NewRemoteHeadStore("https://witness.invalid", "w1", nil, &http.Client{}); err == nil {
		t.Fatal("expected missing witness key rejection")
	}
}
