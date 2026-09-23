package prometheusprobe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestBinaryNodeHealthProbeReadsPrometheusVector(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 40, 0, 0, time.UTC)
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("query"); !strings.Contains(got, "node-7") {
			t.Fatalf("query missing node target: %q", got)
		}
		fmt.Fprintf(w, "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"1\"]}]}}", float64(now.Unix()))
	})
	defer server.Close()

	probe := NewBinaryNodeHealthProbe(server.URL, server.Client())
	outcome, err := probe.Acquire(context.Background(), decision.Request{Target: "node/node-7"})
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	if len(outcome.Evidence) != 1 {
		t.Fatalf("expected one observation, got %+v", outcome)
	}
	got := outcome.Evidence[0]
	if got.Claim != "node_health" || got.Source != DefaultSource || got.Value != "healthy" {
		t.Fatalf("unexpected observation: %+v", got)
	}
	if !got.ObservedAt.Equal(now) {
		t.Fatalf("expected sample time %s, got %s", now, got.ObservedAt)
	}
}

func TestBinaryNodeHealthProbeMapsZeroToUnhealthy(t *testing.T) {
	now := time.Date(2026, 9, 23, 17, 40, 0, 0, time.UTC)
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"0\"]}]}}", float64(now.Unix()))
	})
	defer server.Close()

	probe := NewBinaryNodeHealthProbe(server.URL, server.Client())
	outcome, err := probe.Acquire(context.Background(), decision.Request{Target: "node/node-7"})
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	if got := outcome.Evidence[0].Value; got != "unhealthy" {
		t.Fatalf("expected unhealthy, got %q", got)
	}
}

func TestBinaryNodeHealthProbeFailsClosedOnAmbiguousSeries(t *testing.T) {
	now := float64(time.Now().Unix())
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"1\"]},{\"value\":[%f,\"1\"]}]}}", now, now)
	})
	defer server.Close()

	probe := NewBinaryNodeHealthProbe(server.URL, server.Client())
	_, err := probe.Acquire(context.Background(), decision.Request{Target: "node/node-7"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected ambiguous series error, got %v", err)
	}
}

func TestBinaryNodeHealthProbeRejectsUnknownMetricValue(t *testing.T) {
	now := float64(time.Now().Unix())
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"0.5\"]}]}}", now)
	})
	defer server.Close()

	probe := NewBinaryNodeHealthProbe(server.URL, server.Client())
	_, err := probe.Acquire(context.Background(), decision.Request{Target: "node/node-7"})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported metric value error, got %v", err)
	}
}

func TestBinaryNodeHealthProbeRejectsHTTPFailure(t *testing.T) {
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	defer server.Close()

	probe := NewBinaryNodeHealthProbe(server.URL, server.Client())
	_, err := probe.Acquire(context.Background(), decision.Request{Target: "node/node-7"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected HTTP failure, got %v", err)
	}
}

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}
