//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/tls"
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

func TestKindAegisEGEAuthenticatedIntentMutationAndReplayRejection(t *testing.T) {
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

	nodeName := "aegis-ege-v0-api-node"
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

	adapter, err := kubeadapter.NewForConfigWithExperimentalMutations(config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(
			w,
			"{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"value\":[%f,\"1\"]}]}}",
			float64(time.Now().UTC().Unix()),
		)
	}))
	defer prometheus.Close()

	identity := "spiffe://aegis-ege.test/operator"
	authorizer, err := NewMTLSAuthorizer(AuthzFile{
		Principals: map[string][]Permission{
			identity: {PermissionPrepare, PermissionExecute},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, clientCertificate := generateClientCertificate(t, identity)
	serverTLS, err := MutualTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}

	api, err := New(
		adapter,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			Policy: kubeadapter.NodeDrainPolicy{
				MaxEvidenceAge:         15 * time.Second,
				RequiredSourceCount:    1,
				MaxBlastRadius:         10,
				AuthorizationTTL:       30 * time.Second,
				ExecutionLockNamespace: "kube-system",
				ExecutionLockDuration:  30 * time.Second,
			},
			MutationsEnabled:      true,
			RequireAuthentication: true,
			Authorizer:            authorizer,
			ReplayGuard:                       replay,
			EGEPrometheusNodeHealthURL:         prometheus.URL,
			EGEPrometheusNodeHealthTrustDomain: "external-observability",
			EGEPrometheusHTTPClient:            prometheus.Client(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	testServer := httptest.NewUnstartedServer(api.Handler())
	testServer.TLS = serverTLS
	testServer.StartTLS()
	defer testServer.Close()

	clientHTTP := testServer.Client()
	transport := clientHTTP.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	clientHTTP.Transport = transport

	intentID := "ege-kind-v0"
	preparePayload := []byte("{\"intent_id\":\"" + intentID + "\",\"kind\":\"" + egeNodeDrainKind + "\",\"target\":{\"type\":\"" + egeNodeTarget + "\",\"name\":\"" + nodeName + "\"}}")

	var executePayload []byte
	var execution egeExecuteResponse
	for attempt := 0; attempt < 12; attempt++ {
		preparation := prepareEGEUntilStable(
			t,
			clientHTTP,
			testServer.URL,
			preparePayload,
		)
		if preparation.APIVersion != egeAPIVersion ||
			preparation.IntentID != intentID ||
			preparation.Kind != egeNodeDrainKind ||
			preparation.Target.Type != egeNodeTarget ||
			preparation.Target.Name != nodeName {
			t.Fatalf("unexpected Aegis-EGE preparation envelope: %+v", preparation)
		}
		if preparation.EvidenceManifest == nil || len(preparation.EvidenceManifest.Sources) != 2 {
			t.Fatalf("expected Kubernetes + Prometheus composed evidence, got %+v", preparation.EvidenceManifest)
		}
		sourceNames := map[string]bool{}
		trustDomains := map[string]bool{}
		for _, source := range preparation.EvidenceManifest.Sources {
			sourceNames[source.Name] = true
			trustDomains[source.TrustDomain] = true
		}
		if !sourceNames[egeNodeDrainEvidenceSource] ||
			!sourceNames[egePrometheusNodeHealthEvidenceSource] ||
			len(trustDomains) != 2 {
			t.Fatalf("expected two distinct evidence sources/domains, got %+v", preparation.EvidenceManifest.Sources)
		}

		executePayload, err = json.Marshal(egeExecuteRequest{
			IntentID: intentID,
			Kind:     egeNodeDrainKind,
			Target: egeTargetDTO{
				Type: egeNodeTarget,
				Name: nodeName,
			},
			Permit: *preparation.Permit,
		})
		if err != nil {
			t.Fatal(err)
		}

		executeResp, err := clientHTTP.Post(
			testServer.URL+"/v1/ege/execute",
			"application/json",
			bytes.NewReader(executePayload),
		)
		if err != nil {
			t.Fatal(err)
		}
		if executeResp.StatusCode != http.StatusOK {
			_ = executeResp.Body.Close()
			t.Fatalf("EGE execute status=%d", executeResp.StatusCode)
		}
		execution = egeExecuteResponse{}
		if err := json.NewDecoder(executeResp.Body).Decode(&execution); err != nil {
			_ = executeResp.Body.Close()
			t.Fatal(err)
		}
		_ = executeResp.Body.Close()

		if execution.Decision == decision.Allow {
			break
		}
		if execution.Decision == decision.Escalate &&
			(hasServerReason(execution.ReasonCodes, decision.ResourceVersionChanged) ||
				hasServerReason(execution.ReasonCodes, decision.ExecutionPlanChanged)) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf("unexpected Aegis-EGE execution result: %+v", execution)
	}
	if execution.Decision != decision.Allow {
		t.Fatalf("Aegis-EGE execution did not stabilize to ALLOW: %+v", execution)
	}

	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Spec.Unschedulable {
		t.Fatal("Aegis-EGE authorized execution did not cordon node")
	}

	replayResp, err := clientHTTP.Post(
		testServer.URL+"/v1/ege/execute",
		"application/json",
		bytes.NewReader(executePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected EGE replay 409, got %d", replayResp.StatusCode)
	}
	var replayError errorResponse
	if err := json.NewDecoder(replayResp.Body).Decode(&replayError); err != nil {
		t.Fatal(err)
	}
	if replayError.Code != "EXECUTION_REPLAY_REJECTED" {
		t.Fatalf("unexpected EGE replay error: %+v", replayError)
	}
}

func prepareEGEUntilStable(
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
		if preparation.Decision == decision.Allow && preparation.Permit != nil && preparation.EvidenceManifest != nil {
			return preparation
		}
		if preparation.Decision == decision.Escalate &&
			hasServerReason(preparation.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf("EGE prepare did not reach stable ALLOW: %+v", preparation)
	}
	t.Fatal("EGE prepare remained unstable after retries")
	return egePrepareResponse{}
}
