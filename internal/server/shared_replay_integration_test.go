//go:build integration

package server

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestKindM9SharedReplayGuardRejectsAcrossInstances(t *testing.T) {
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
	namespace := "state-latch-m9-replay"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create replay namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	})

	guardA, err := NewKubernetesReplayGuard(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	guardB, err := NewKubernetesReplayGuard(client, namespace)
	if err != nil {
		t.Fatal(err)
	}

	auth := decision.Authorization{
		ActionID:        "m9-shared-replay",
		Action:          "drain",
		Target:          "node/node-7",
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ValidUntil:      time.Now().UTC().Add(time.Minute),
	}

	if err := guardA.Claim(ctx, auth); err != nil {
		t.Fatalf("replica A claim: %v", err)
	}
	if err := guardB.Claim(ctx, auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("replica B must observe shared replay claim, got %v", err)
	}
}
