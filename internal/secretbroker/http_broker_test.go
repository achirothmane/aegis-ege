package secretbroker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/governedaction"
)

func brokerBinding(destination string) governedaction.CredentialUseBinding {
	return governedaction.CredentialUseBinding{
		HandleID:       "credh_01",
		ActionRevision: "action-revision-abc",
		EffectID:       "effect-001",
		Audience:       "crm-api",
		Destination:    destination,
		Scope:          "customer:update",
		TrustEpoch:     "credential-epoch-4",
		ValidUntil:     time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC),
	}
}

func TestHTTPBrokerInjectsSecretOnlyAtBoundDestination(t *testing.T) {
	const secret = "server-only-token"
	var calls atomic.Int32
	var seenAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	binding := brokerBinding(server.URL)
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: binding, RawSecret: []byte(secret)}},
		server.Client(),
		func() time.Time { return binding.ValidUntil.Add(-time.Minute) },
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	response, err := broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  binding,
		Method:   http.MethodPost,
		URL:      server.URL + "/customers/17",
		Header:   http.Header{"Content-Type": []string{"application/json"}},
		Body:     []byte(`{"name":"updated"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("requests=%d; want 1", got)
	}
	if seenAuth != "Bearer "+secret {
		t.Fatalf("destination did not receive injected credential")
	}
	if response.Request != nil && response.Request.Header.Get("Authorization") != "" {
		t.Fatal("caller can recover injected Authorization from returned response")
	}
}

func TestHTTPBrokerRejectsEffectReplayBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	admitted := brokerBinding(server.URL)
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: admitted, RawSecret: []byte("secret")}},
		server.Client(),
		func() time.Time { return admitted.ValidUntil.Add(-time.Minute) },
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	replay := admitted
	replay.EffectID = "effect-002"
	_, err = broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  replay,
		Method:   http.MethodPost,
		URL:      server.URL + "/customers/17",
	})
	if !errors.Is(err, governedaction.ErrCredentialBindingChanged) {
		t.Fatalf("error=%v; want credential binding changed", err)
	}
	if calls.Load() != 0 {
		t.Fatal("replayed surrogate reached the network")
	}
}

func TestHTTPBrokerRejectsAudienceConfusionBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	admitted := brokerBinding(server.URL)
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: admitted, RawSecret: []byte("secret")}},
		server.Client(),
		func() time.Time { return admitted.ValidUntil.Add(-time.Minute) },
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	confused := admitted
	confused.Audience = "calendar-api"
	_, err = broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  confused,
		Method:   http.MethodPost,
		URL:      server.URL + "/customers/17",
	})
	if !errors.Is(err, governedaction.ErrCredentialBindingChanged) {
		t.Fatalf("error=%v; want credential binding changed", err)
	}
	if calls.Load() != 0 {
		t.Fatal("wrong-audience credential request reached the network")
	}
}

func TestHTTPBrokerRejectsCallerCredentialHeaders(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	binding := brokerBinding(server.URL)
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: binding, RawSecret: []byte("secret")}},
		server.Client(),
		func() time.Time { return binding.ValidUntil.Add(-time.Minute) },
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  binding,
		URL:      server.URL,
		Header:   http.Header{"Authorization": []string{"Bearer attacker-controlled"}},
	})
	if !errors.Is(err, ErrCallerCredentialHeader) {
		t.Fatalf("error=%v; want caller credential header rejection", err)
	}
	if calls.Load() != 0 {
		t.Fatal("caller credential header reached network")
	}
}

func TestHTTPBrokerDoesNotFollowCredentialRedirect(t *testing.T) {
	var redirectedCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	var firstCalls atomic.Int32
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer redirector.Close()

	binding := brokerBinding(redirector.URL)
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: binding, RawSecret: []byte("secret")}},
		redirector.Client(),
		func() time.Time { return binding.ValidUntil.Add(-time.Minute) },
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	response, err := broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  binding,
		URL:      redirector.URL + "/start",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusFound {
		t.Fatalf("status=%d; want redirect returned to caller", response.StatusCode)
	}
	if firstCalls.Load() != 1 || redirectedCalls.Load() != 0 {
		t.Fatalf("redirect followed with credential: first=%d redirected=%d", firstCalls.Load(), redirectedCalls.Load())
	}
}

func TestHTTPBrokerErrorsNeverContainRawSecret(t *testing.T) {
	const secret = "never-log-this-secret"
	binding := brokerBinding("https://api.example.test")
	broker, err := NewHTTPBroker(
		[]StaticCredential{{Binding: binding, RawSecret: []byte(secret)}},
		&http.Client{},
		func() time.Time { return binding.ValidUntil.Add(-time.Minute) },
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	current := binding
	current.Audience = "wrong-audience"
	_, err = broker.Do(context.Background(), HTTPRequest{
		HandleID: "credh_01",
		Binding:  current,
		URL:      "https://api.example.test/",
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("raw secret leaked into error")
	}
}

func TestDrainAndClose(t *testing.T) {
	response := &http.Response{Body: io.NopCloser(strings.NewReader("ok"))}
	if err := DrainAndClose(response); err != nil {
		t.Fatal(err)
	}
}
