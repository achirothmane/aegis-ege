//go:build integration

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/journal"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestKindCapabilityRootExternalHeadRejectsFullLocalRollback(t *testing.T) {
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
	namespace := "aegis-capability-root"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Namespaces().Delete(
			context.Background(),
			namespace,
			metav1.DeleteOptions{},
		)
	})

	headStore, err := journal.NewKubernetesHeadStore(client, namespace)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := NewExternalHeadCapabilityRootAnchor(
		headStore,
		"capability-effect-authority",
	)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "capability-root.log")
	root, err := NewAnchoredFileCapabilityMonotonicRoot(rootPath, anchor)
	if err != nil {
		t.Fatal(err)
	}

	scope := anchoredCapabilityScope()
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authority.Issue(ctx, scope); err != nil {
		t.Fatalf("issue T1: %v", err)
	}
	t1Ledger, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}

	t2Issue := t1Issue
	t2Issue.DecisionEpoch++
	t2 := capabilityAuthoritySnapshotFromIssue(t2Issue)
	mutable.issue = t2Issue
	mutable.coordination = t2
	mutable.witness = t2
	if _, err := authority.Issue(ctx, scope); err != nil {
		t.Fatalf("issue T2: %v", err)
	}

	external, err := headStore.Load(ctx, "capability-effect-authority")
	if err != nil {
		t.Fatal(err)
	}
	if external.Sequence != 2 || !isCapabilityRootDigest(external.HeadHash) {
		t.Fatalf("unexpected protected external head: %+v", external)
	}

	// Restore every local/mutable view to T1 while the Kubernetes control-plane
	// head remains committed to T2.
	mutable.issue = t1Issue
	mutable.coordination = t1
	mutable.witness = t1
	if err := os.WriteFile(rootPath, t1Ledger, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authority.Current(ctx, scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("rolled-back Current error = %v, want %v", err, ErrCapabilityRootRollback)
	}
	if _, err := authority.Issue(ctx, scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("rolled-back reissue error = %v, want %v", err, ErrCapabilityRootRollback)
	}

	stillExternal, err := headStore.Load(ctx, "capability-effect-authority")
	if err != nil {
		t.Fatal(err)
	}
	if stillExternal.Sequence != external.Sequence ||
		stillExternal.HeadHash != external.HeadHash {
		t.Fatalf(
			"rollback attempt changed protected external head: before=%+v after=%+v",
			external,
			stillExternal,
		)
	}
}
