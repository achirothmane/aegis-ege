//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/prometheusprobe"
)

func TestKindIndependentPrometheusAgreementAllows(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2-agree")
	server := prometheusHealthServer(t, observedAt.Add(time.Second), "1")
	defer server.Close()

	req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
	initial := decision.Evaluate(req)
	if initial.Decision != decision.Escalate {
		t.Fatalf("expected initial ESCALATE, got %s reasons=%v", initial.Decision, initial.ReasonCodes)
	}

	probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
	resolved := decision.ResolveUnknown(context.Background(), req, []decision.EvidenceProbe{probe}, 1)

	if resolved.Final.Decision != decision.Allow {
		t.Fatalf(
			"expected independent agreeing evidence to ALLOW, got %s reasons=%v attempts=%+v",
			resolved.Final.Decision,
			resolved.Final.ReasonCodes,
			resolved.Attempts,
		)
	}
	if resolved.Final.Authorization == nil {
		t.Fatal("agreement must mint authorization only after independent evidence")
	}
	if len(resolved.EffectiveRequest.Evidence) != 2 {
		t.Fatalf("expected two independent observations, got %+v", resolved.EffectiveRequest.Evidence)
	}
	if resolved.EffectiveRequest.Evidence[0].Source == resolved.EffectiveRequest.Evidence[1].Source {
		t.Fatalf("expected independent sources, got %+v", resolved.EffectiveRequest.Evidence)
	}
}

func TestKindIndependentPrometheusContradictionBlocks(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2-conflict")
	server := prometheusHealthServer(t, observedAt.Add(time.Second), "0")
	defer server.Close()

	req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
	probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
	resolved := decision.ResolveUnknown(context.Background(), req, []decision.EvidenceProbe{probe}, 1)

	if resolved.Final.Decision != decision.Block {
		t.Fatalf(
			"expected independent contradiction to BLOCK, got %s reasons=%v attempts=%+v",
			resolved.Final.Decision,
			resolved.Final.ReasonCodes,
			resolved.Attempts,
		)
	}
	if len(resolved.Final.ReasonCodes) != 1 ||
		resolved.Final.ReasonCodes[0] != decision.EvidenceContradicted {
		t.Fatalf("expected %s, got %v", decision.EvidenceContradicted, resolved.Final.ReasonCodes)
	}
	if resolved.Final.Authorization != nil {
		t.Fatal("contradiction must never mint authorization")
	}
}

func TestKindPrometheusProbeFailureRemainsEscalate(t *testing.T) {
	env, node, observedAt := prepareM2ReadyNode(t, "m2-failure")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
	probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
	resolved := decision.ResolveUnknown(context.Background(), req, []decision.EvidenceProbe{probe}, 1)

	if resolved.Final.Decision != decision.Escalate {
		t.Fatalf("expected failed independent probe to remain ESCALATE, got %s reasons=%v", resolved.Final.Decision, resolved.Final.ReasonCodes)
	}
	if resolved.Final.Authorization != nil {
		t.Fatal("failed probe must not mint authorization")
	}
}

func prepareM2ReadyNode(
	t *testing.T,
	suffix string,
) (kindIntegrationEnv, *corev1.Node, time.Time) {
	t.Helper()
	env := newKindIntegrationEnv(t, suffix)
	ctx := context.Background()

	node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get synthetic node: %v", err)
	}
	nowMeta := metav1.Now()
	node.Status.Conditions = []corev1.NodeCondition{{
		Type:               corev1.NodeReady,
		Status:             corev1.ConditionTrue,
		LastHeartbeatTime:  nowMeta,
		LastTransitionTime: nowMeta,
	}}
	node, err = env.client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("mark synthetic node Ready: %v", err)
	}
	return env, node, time.Now().UTC().Truncate(time.Second)
}

func m2Request(
	nodeName string,
	resourceVersion string,
	observedAt time.Time,
	kubernetesValue string,
) decision.Request {
	return decision.Request{
		ActionID:            "act-kind-m2",
		Action:              "drain",
		Target:              "node/" + nodeName,
		ResourceVersion:     resourceVersion,
		RequestedAt:         observedAt,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []decision.EvidenceObservation{{
			Claim:      nodeHealthClaim,
			Source:     "kubernetes-api-live",
			Value:      kubernetesValue,
			ObservedAt: observedAt,
		}},
	}
}

func prometheusHealthServer(
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
		if r.URL.Query().Get("query") == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
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
