//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/kubeadapter"
)

func TestKindM7DaemonPreparesButCannotMutateByDefault(t *testing.T) {
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

	nodeName := "state-latch-m7-api-node"
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
	api, err := New(adapter, nil, Config{
		Policy: kubeadapter.NodeDrainPolicy{
			MaxEvidenceAge:      15 * time.Second,
			RequiredSourceCount: 1,
			MaxBlastRadius:      10,
			AuthorizationTTL:    5 * time.Second,
		},
		MutationsEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpServer := httptest.NewServer(api.Handler())
	defer httpServer.Close()

	preparePayload := []byte(`{"action_id":"m7-kind","node_name":"state-latch-m7-api-node"}`)
	preparation := prepareUntilStable(
		t,
		http.DefaultClient,
		httpServer.URL,
		preparePayload,
	)

	executePayload, err := json.Marshal(executeRequest{
		NodeName:       nodeName,
		Authorization: *preparation.Authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	executeResp, err := http.Post(
		httpServer.URL+"/v1/node-drains/execute",
		"application/json",
		bytes.NewReader(executePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer executeResp.Body.Close()

	if executeResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected execute 503 while mutations disabled, got %d", executeResp.StatusCode)
	}

	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("M7 daemon mutated node while mutations were disabled")
	}
}
