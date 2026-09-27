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

	"github.com/achirothmane/aegis-ege/internal/decision"
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


func TestKindSharedCapabilityClaimLifecycleAcrossInstances(t *testing.T) {
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
	namespace := "state-latch-capability-lifecycle"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create lifecycle namespace: %v", err)
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
		ActionID:           "shared-capability-lifecycle",
		Action:             "drain",
		Target:             "node/node-7",
		ResourceVersion:    "100",
		EvidenceDigest:     "sha256:evidence",
		PlanDigest:         "sha256:plan",
		AuthorityDomain:    "kind/control-plane",
		AuthorityTerm:      3,
		DecisionEpoch:      11,
		RevocationEpoch:    2,
		TargetIdentity:     "uid-node-7",
		StateBindingDigest: "sha256:state",
		ValidUntil:         time.Now().UTC().Add(time.Minute),
	}

	if err := guardA.Issue(ctx, auth); err != nil {
		t.Fatalf("replica A issue: %v", err)
	}
	record, err := guardB.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimIssued {
		t.Fatalf("replica B expected ISSUED, got %+v", record)
	}

	if err := guardB.Claim(ctx, auth); err != nil {
		t.Fatalf("replica B claim: %v", err)
	}
	record, err = guardA.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimClaimed {
		t.Fatalf("replica A expected CLAIMED, got %+v", record)
	}

	if err := guardA.Consume(ctx, auth, "ALLOW"); err != nil {
		t.Fatalf("replica A consume: %v", err)
	}
	record, err = guardB.State(ctx, auth)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != ExecutionClaimConsumed || record.Outcome != "ALLOW" {
		t.Fatalf("replica B expected CONSUMED/ALLOW, got %+v", record)
	}
	if err := guardB.Claim(ctx, auth); !errors.Is(err, ErrExecutionReplay) {
		t.Fatalf("consumed shared capability must reject replay, got %v", err)
	}
}


func TestKindSharedCapabilityClaimAllowsExactlyOneReplica(t *testing.T) {
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
	namespace := "state-latch-capability-race"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create race namespace: %v", err)
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
		ActionID:           "shared-capability-race",
		Action:             "drain",
		Target:             "node/node-7",
		ResourceVersion:    "100",
		EvidenceDigest:     "sha256:evidence",
		PlanDigest:         "sha256:plan",
		AuthorityDomain:    "kind/control-plane",
		AuthorityTerm:      3,
		DecisionEpoch:      12,
		RevocationEpoch:    2,
		TargetIdentity:     "uid-node-7",
		StateBindingDigest: "sha256:state",
		ValidUntil:         time.Now().UTC().Add(time.Minute),
	}
	if err := guardA.Issue(ctx, auth); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	go func() { results <- guardA.Claim(ctx, auth) }()
	go func() { results <- guardB.Claim(ctx, auth) }()

	successes := 0
	replays := 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrExecutionReplay):
			replays++
		default:
			t.Fatalf("unexpected shared claim error: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("expected one shared winner and one replay rejection, got successes=%d replays=%d", successes, replays)
	}
}
