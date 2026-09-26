//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

func TestKindPrometheusFalsificationBlocksWhatKubernetesAloneWouldAllow(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("KUBECONFIG is required")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	nodeName := "aegis-prometheus-falsification-node"
	_, err = client.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:               corev1.NodeReady,
				Status:             corev1.ConditionTrue,
				LastHeartbeatTime:  metav1.Now(),
				LastTransitionTime: metav1.Now(),
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create synthetic node: %v", err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
	})

	adapter, err := kubeadapter.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	policy := kubeadapter.NodeDrainPolicy{
		MaxEvidenceAge:      15 * time.Second,
		RequiredSourceCount: 1,
		MaxBlastRadius:      10,
		AuthorizationTTL:    30 * time.Second,
	}

	intentID := "prometheus-falsification-v1"
	payload := []byte(
		"{\"intent_id\":\"" + intentID +
			"\",\"kind\":\"" + egeNodeDrainKind +
			"\",\"target\":{\"type\":\"" + egeNodeTarget +
			"\",\"name\":\"" + nodeName + "\"}}",
	)

	baselineAPI, err := New(adapter, nil, Config{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	baselineServer := httptest.NewServer(baselineAPI.Handler())
	defer baselineServer.Close()

	baseline := prepareEGEUntilStable(
		t,
		baselineServer.Client(),
		baselineServer.URL,
		payload,
	)
	if baseline.Decision != decision.Allow || baseline.Permit == nil {
		t.Fatalf("expected Kubernetes-only baseline ALLOW with permit, got %+v", baseline)
	}
	if baseline.EvidenceManifest == nil || len(baseline.EvidenceManifest.Sources) != 1 {
		t.Fatalf("expected one-source Kubernetes baseline evidence, got %+v", baseline.EvidenceManifest)
	}

	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(
			w,
			"{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"0\"]}]}}",
			float64(time.Now().UTC().Unix()),
		)
	}))
	defer prometheus.Close()

	composedAPI, err := New(adapter, nil, Config{
		Policy:                                policy,
		EGEPrometheusNodeHealthURL:            prometheus.URL,
		EGEPrometheusNodeHealthTrustDomain:    "external-observability",
		EGEPrometheusHTTPClient:               prometheus.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	composedServer := httptest.NewServer(composedAPI.Handler())
	defer composedServer.Close()

	composed := postEGEPrepareForFalsification(
		t,
		composedServer.Client(),
		composedServer.URL,
		payload,
	)

	if composed.Decision != decision.Block {
		t.Fatalf(
			"expected independent Prometheus contradiction to BLOCK, got %s reasons=%v",
			composed.Decision,
			composed.ReasonCodes,
		)
	}
	if !hasServerReason(composed.ReasonCodes, decision.EvidenceContradicted) {
		t.Fatalf("expected EVIDENCE_CONTRADICTED, got %v", composed.ReasonCodes)
	}
	if composed.Permit != nil {
		t.Fatal("contradicted evidence must not mint an execution permit")
	}

	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("falsification scenario must not mutate the node")
	}
}

func postEGEPrepareForFalsification(
	t *testing.T,
	client *http.Client,
	baseURL string,
	payload []byte,
) egePrepareResponse {
	t.Helper()
	for attempt := 0; attempt < 12; attempt++ {
		resp, err := client.Post(
			baseURL+"/v1/ege/prepare",
			"application/json",
			bytes.NewReader(payload),
		)
		if err != nil {
			t.Fatal(err)
		}
		var preparation egePrepareResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&preparation)
		_ = resp.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("EGE prepare status=%d response=%+v", resp.StatusCode, preparation)
		}

		if preparation.Decision == decision.Block ||
			preparation.Decision == decision.Allow {
			return preparation
		}
		if preparation.Decision == decision.Escalate &&
			hasServerReason(preparation.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return preparation
	}
	t.Fatal("EGE falsification prepare remained unstable after retries")
	return egePrepareResponse{}
}
