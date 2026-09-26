package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestPrometheusEvidenceContributorAllowsAgreement(t *testing.T) {
	now := time.Date(2026, 9, 26, 21, 0, 0, 0, time.UTC)
	server := newPrometheusNodeHealthServer(t, now.Add(-time.Second), "1")
	defer server.Close()

	contributor, err := newPrometheusNodeHealthEvidenceContributor(
		server.URL,
		"external-observability",
		10*time.Second,
		server.Client(),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := contributor.Contribute(
		context.Background(),
		"intent-1",
		egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		prometheusPrimaryProduction(now, "healthy"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s reasons=%v", result.Decision, result.ReasonCodes)
	}
	if result.EvidenceDigest == "" || len(result.EvidenceClasses) != 1 {
		t.Fatalf("expected bound Prometheus evidence, got %+v", result)
	}
}

func TestPrometheusEvidenceContributorBlocksContradiction(t *testing.T) {
	now := time.Date(2026, 9, 26, 21, 0, 0, 0, time.UTC)
	server := newPrometheusNodeHealthServer(t, now.Add(-time.Second), "0")
	defer server.Close()

	contributor, err := newPrometheusNodeHealthEvidenceContributor(
		server.URL,
		"external-observability",
		10*time.Second,
		server.Client(),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := contributor.Contribute(
		context.Background(),
		"intent-2",
		egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		prometheusPrimaryProduction(now, "healthy"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", result.Decision)
	}
	if len(result.ReasonCodes) != 1 || result.ReasonCodes[0] != decision.EvidenceContradicted {
		t.Fatalf("unexpected reasons: %v", result.ReasonCodes)
	}
}

func TestPrometheusEvidenceContributorBlocksStaleSample(t *testing.T) {
	now := time.Date(2026, 9, 26, 21, 0, 0, 0, time.UTC)
	server := newPrometheusNodeHealthServer(t, now.Add(-30*time.Second), "1")
	defer server.Close()

	contributor, err := newPrometheusNodeHealthEvidenceContributor(
		server.URL,
		"external-observability",
		10*time.Second,
		server.Client(),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := contributor.Contribute(
		context.Background(),
		"intent-3",
		egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		prometheusPrimaryProduction(now, "healthy"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", result.Decision)
	}
	if len(result.ReasonCodes) != 1 || result.ReasonCodes[0] != decision.EvidenceStale {
		t.Fatalf("unexpected reasons: %v", result.ReasonCodes)
	}
}

func TestPrometheusEvidenceContributorRequiresDistinctTrustDomain(t *testing.T) {
	_, err := newPrometheusNodeHealthEvidenceContributor(
		"http://example.invalid",
		egeNodeDrainTrustDomain,
		time.Second,
		nil,
		time.Now,
	)
	if err == nil {
		t.Fatal("expected same trust domain as Kubernetes control plane to fail")
	}
}

func prometheusPrimaryProduction(observedAt time.Time, health string) egeEvidenceProduction {
	return egeEvidenceProduction{
		Decision:        decision.Allow,
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"kubernetes.authoritative-state"},
		PermitBinding: &egePermitBinding{
			Action:          "drain",
			ResourceVersion: "100",
			EvidenceDigest:  "sha256:kubernetes",
			PlanDigest:      "sha256:plan",
			ValidUntil:      observedAt.Add(time.Minute),
		},
		Snapshot: &snapshotDTO{
			ResourceVersion: "100",
			NodeHealth:      health,
			ObservedAt:      observedAt,
		},
	}
}

func newPrometheusNodeHealthServer(
	t *testing.T,
	sampleTime time.Time,
	value string,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(
			w,
			"{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,%q]}]}}",
			float64(sampleTime.Unix()),
			value,
		)
	}))
}
