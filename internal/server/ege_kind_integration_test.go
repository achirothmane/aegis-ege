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
	"k8s.io/client-go/util/retry"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
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
		if preparation.EvidenceManifest.Composition == nil {
			t.Fatal("expected signed evidence-composition assessment")
		}
		if preparation.EvidenceManifest.Composition.RequiredIndependence != egeproto.EvidenceIndependenceUnknown ||
			preparation.EvidenceManifest.Composition.OverallIndependence != egeproto.EvidenceIndependenceUnknown ||
			preparation.EvidenceManifest.Composition.IndependentSourceCount != 0 {
			t.Fatalf(
				"label-only Prometheus composition must keep independence UNKNOWN: %+v",
				preparation.EvidenceManifest.Composition,
			)
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

func TestKindAegisEGERejectsStateDriftBetweenPrepareAndExecute(t *testing.T) {
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

	nodeName := "aegis-ege-state-drift-node"
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

	policy := kubeadapter.NodeDrainPolicy{
		MaxEvidenceAge:         15 * time.Second,
		RequiredSourceCount:    1,
		MaxBlastRadius:         10,
		AuthorizationTTL:       30 * time.Second,
		ExecutionLockNamespace: "kube-system",
		ExecutionLockDuration:  30 * time.Second,
	}

	api, err := New(
		adapter,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			Policy:                policy,
			MutationsEnabled:      true,
			RequireAuthentication: true,
			Authorizer:            allowAuthorizer{},
			ReplayGuard:           replay,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	testServer := httptest.NewServer(api.Handler())
	defer testServer.Close()

	intentID := "ege-state-drift"
	preparePayload := []byte(
		"{\"intent_id\":\"" + intentID +
			"\",\"kind\":\"" + egeNodeDrainKind +
			"\",\"target\":{\"type\":\"" + egeNodeTarget +
			"\",\"name\":\"" + nodeName + "\"}}",
	)

	preparation := prepareEGEUntilStable(
		t,
		testServer.Client(),
		testServer.URL,
		preparePayload,
	)
	if preparation.Permit == nil {
		t.Fatal("expected signed permit before state drift")
	}
	boundResourceVersion := preparation.Permit.Claims.ResourceVersion

	var changed *corev1.Node
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		now := metav1.Now()
		current.Status.Conditions = []corev1.NodeCondition{{
			Type:               corev1.NodeReady,
			Status:             corev1.ConditionFalse,
			LastHeartbeatTime:  now,
			LastTransitionTime: now,
		}}
		updated, err := client.CoreV1().Nodes().UpdateStatus(
			ctx,
			current,
			metav1.UpdateOptions{},
		)
		if err == nil {
			changed = updated
		}
		return err
	})
	if err != nil {
		t.Fatalf("update node health between prepare and execute after conflict-safe re-read: %v", err)
	}
	if changed == nil {
		t.Fatal("node health update completed without returning the changed node")
	}
	if changed.ResourceVersion == boundResourceVersion {
		t.Fatalf("expected state drift to change resourceVersion, remained %q", changed.ResourceVersion)
	}

	executePayload, err := json.Marshal(egeExecuteRequest{
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

	executeResp, err := testServer.Client().Post(
		testServer.URL+"/v1/ege/execute",
		"application/json",
		bytes.NewReader(executePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer executeResp.Body.Close()
	if executeResp.StatusCode != http.StatusOK {
		t.Fatalf("EGE execute status=%d", executeResp.StatusCode)
	}

	var execution egeExecuteResponse
	if err := json.NewDecoder(executeResp.Body).Decode(&execution); err != nil {
		t.Fatal(err)
	}
	if execution.Decision != decision.Escalate {
		t.Fatalf(
			"expected state drift to ESCALATE before mutation, got %s reasons=%v",
			execution.Decision,
			execution.ReasonCodes,
		)
	}
	if !hasServerReason(execution.ReasonCodes, decision.ResourceVersionChanged) {
		t.Fatalf("expected %s, got %v", decision.ResourceVersionChanged, execution.ReasonCodes)
	}
	if !hasServerReason(execution.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got %v", decision.ExecutionPlanChanged, execution.ReasonCodes)
	}
	if len(execution.Steps) != 0 {
		t.Fatalf("state drift must stop before mutation steps, got %+v", execution.Steps)
	}

	after, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Spec.Unschedulable {
		t.Fatal("state-drift rejection must not cordon the node")
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
