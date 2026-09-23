//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestKindServerDryRunAcceptsPlanWithoutPersistingMutations(t *testing.T) {
	env := newKindIntegrationEnv(t, "dryrun")

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		context.Background(),
		"act-kind-dryrun",
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}
	if preparation.Authorization == nil || preparation.PlanDigest == "" {
		t.Fatalf("expected plan-bound authorization, got auth=%v digest=%q", preparation.Authorization, preparation.PlanDigest)
	}
	if preparation.DryRun == nil || !preparation.DryRun.Passed {
		t.Fatalf("expected server dry-run to pass, got %+v", preparation.DryRun)
	}

	node, err := env.client.CoreV1().Nodes().Get(context.Background(), env.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node after dry-run: %v", err)
	}
	if node.Spec.Unschedulable {
		t.Fatal("server dry-run cordon must not persist spec.unschedulable=true")
	}

	if _, err := env.client.CoreV1().Pods(env.namespace).Get(
		context.Background(),
		env.podName,
		metav1.GetOptions{},
	); err != nil {
		t.Fatalf("server dry-run eviction must leave pod present: %v", err)
	}
}

func TestKindPDBBlocksRealServerDryRunEvictionAndStateLatchPreparation(t *testing.T) {
	env := newKindIntegrationEnv(t, "pdb")
	ctx := context.Background()

	zero := intstr.FromInt(0)
	pdb, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Create(
		ctx,
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-all",
				Namespace: env.namespace,
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &zero,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "state-latch-it"},
				},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("create PDB: %v", err)
	}

	waitForPDBStatus(t, env.client, env.namespace, pdb.Name, func(current *policyv1.PodDisruptionBudget) bool {
		return current.Status.ObservedGeneration == current.Generation &&
			current.Status.DisruptionsAllowed == 0
	})

	pod, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}

	reader := NewClientGoReader(env.client)
	err = reader.DryRunEvictPod(ctx, PodStateRef{
		Namespace:       pod.Namespace,
		Name:            pod.Name,
		UID:             string(pod.UID),
		ResourceVersion: pod.ResourceVersion,
	})
	if err == nil {
		t.Fatal("expected Kubernetes Eviction API to reject dry-run under zero-disruption PDB")
	}
	if !apierrors.IsTooManyRequests(err) {
		t.Fatalf("expected TooManyRequests from PDB-protected eviction, got %v", err)
	}

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		ctx,
		"act-kind-pdb",
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Block {
		t.Fatalf("expected StateLatch BLOCK, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}
	if !hasReason(preparation.ReasonCodes, decision.ReasonCode(FindingPDBDisruptionBlocked)) {
		t.Fatalf("expected %s, got %v", FindingPDBDisruptionBlocked, preparation.ReasonCodes)
	}
	if preparation.Authorization != nil {
		t.Fatal("PDB-blocked preparation must not expose authorization")
	}
}

func TestKindLiveRevalidationDetectsPodResourceVersionDrift(t *testing.T) {
	env := newKindIntegrationEnv(t, "drift")
	ctx := context.Background()

	preparation, err := env.adapter.PrepareNodeDrainExecution(
		ctx,
		"act-kind-drift",
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("PrepareNodeDrainExecution returned error: %v", err)
	}
	if preparation.Decision != decision.Allow || preparation.Authorization == nil {
		t.Fatalf("expected initial ALLOW, got %s reasons=%v", preparation.Decision, preparation.ReasonCodes)
	}

	before, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod before drift: %v", err)
	}

	patch := []byte(`{"metadata":{"annotations":{"state-latch.dev/drift":"changed"}}}`)
	after, err := env.client.CoreV1().Pods(env.namespace).Patch(
		ctx,
		env.podName,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	)
	if err != nil {
		t.Fatalf("patch pod to create state drift: %v", err)
	}
	if after.ResourceVersion == before.ResourceVersion {
		t.Fatalf("expected pod resourceVersion to change, remained %q", after.ResourceVersion)
	}

	revalidation, err := env.adapter.RevalidateNodeDrainAuthorization(
		ctx,
		*preparation.Authorization,
		env.nodeName,
		integrationPolicy(),
	)
	if err != nil {
		t.Fatalf("RevalidateNodeDrainAuthorization returned error: %v", err)
	}
	if revalidation.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE after live pod drift, got %s reasons=%v", revalidation.Decision, revalidation.ReasonCodes)
	}
	if !hasReason(revalidation.ReasonCodes, decision.ExecutionPlanChanged) {
		t.Fatalf("expected %s, got %v", decision.ExecutionPlanChanged, revalidation.ReasonCodes)
	}
}

type kindIntegrationEnv struct {
	client    kubernetes.Interface
	adapter   *Adapter
	namespace string
	nodeName  string
	podName   string
}

func newKindIntegrationEnv(t *testing.T, suffix string) kindIntegrationEnv {
	t.Helper()

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Fatal("KUBECONFIG is required for KinD integration tests")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("build clientset: %v", err)
	}
	adapter, err := NewForConfig(config)
	if err != nil {
		t.Fatalf("build StateLatch adapter: %v", err)
	}

	namespace := "sl-it-" + suffix
	nodeName := "sl-it-node-" + suffix
	podName := "workload"

	ctx := context.Background()
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := client.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create synthetic node: %v", err)
	}

	controller := true
	if _, err := client.CoreV1().Pods(namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels:    map[string]string{"app": "state-latch-it"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "synthetic-owner",
					UID:        types.UID("synthetic-owner-" + suffix),
					Controller: &controller,
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Name:  "hold",
					Image: "registry.k8s.io/pause:3.10",
				},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create test pod: %v", err)
	}

	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
		_ = client.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
	})

	return kindIntegrationEnv{
		client:    client,
		adapter:   adapter,
		namespace: namespace,
		nodeName:  nodeName,
		podName:   podName,
	}
}

func integrationPolicy() NodeDrainPolicy {
	return NodeDrainPolicy{
		MaxEvidenceAge:      30 * time.Second,
		RequiredSourceCount: 1,
		MaxBlastRadius:      5,
		AuthorizationTTL:    30 * time.Second,
		IgnoreDaemonSets:    true,
	}
}

func waitForPDBStatus(
	t *testing.T,
	client kubernetes.Interface,
	namespace string,
	name string,
	ready func(*policyv1.PodDisruptionBudget) bool,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var last *policyv1.PodDisruptionBudget
	for {
		current, err := client.PolicyV1().PodDisruptionBudgets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			last = current
			if ready(current) {
				return
			}
		}

		select {
		case <-ctx.Done():
			if last == nil {
				t.Fatalf("PDB status did not become observable: %v", ctx.Err())
			}
			t.Fatalf(
				"PDB status did not converge: generation=%d observed=%d disruptionsAllowed=%d",
				last.Generation,
				last.Status.ObservedGeneration,
				last.Status.DisruptionsAllowed,
			)
		case <-ticker.C:
		}
	}
}

var _ = fmt.Sprintf
