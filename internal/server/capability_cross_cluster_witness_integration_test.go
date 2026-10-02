//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/journal"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const kubernetesCapabilityIssueKey = "issue.json"

type kubernetesCapabilityFenceAuthority struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

func (a *kubernetesCapabilityFenceAuthority) Issue(
	ctx context.Context,
	_ CapabilityFenceScope,
) (CapabilityFenceIssue, error) {
	return a.load(ctx)
}

func (a *kubernetesCapabilityFenceAuthority) Current(
	ctx context.Context,
	_ CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	issue, err := a.load(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	return capabilityAuthoritySnapshotFromIssue(issue), nil
}

func (a *kubernetesCapabilityFenceAuthority) load(
	ctx context.Context,
) (CapabilityFenceIssue, error) {
	cm, err := a.client.CoreV1().ConfigMaps(a.namespace).Get(
		ctx,
		a.name,
		metav1.GetOptions{},
	)
	if err != nil {
		return CapabilityFenceIssue{}, fmt.Errorf("load mutable capability authority: %w", err)
	}
	payload, ok := cm.Data[kubernetesCapabilityIssueKey]
	if !ok {
		return CapabilityFenceIssue{}, errors.New("mutable capability authority payload is missing")
	}
	var issue CapabilityFenceIssue
	if err := json.Unmarshal([]byte(payload), &issue); err != nil {
		return CapabilityFenceIssue{}, fmt.Errorf("decode mutable capability authority: %w", err)
	}
	if err := validateCapabilityAuthoritySnapshot(capabilityAuthoritySnapshotFromIssue(issue)); err != nil {
		return CapabilityFenceIssue{}, fmt.Errorf("invalid mutable capability authority: %w", err)
	}
	return issue, nil
}

func replaceKubernetesCapabilityIssue(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	name string,
	issue CapabilityFenceIssue,
) error {
	payload, err := json.Marshal(issue)
	if err != nil {
		return err
	}
	configMaps := client.CoreV1().ConfigMaps(namespace)
	current, err := configMaps.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = configMaps.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Data: map[string]string{kubernetesCapabilityIssueKey: string(payload)},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	current.Data = map[string]string{kubernetesCapabilityIssueKey: string(payload)}
	_, err = configMaps.Update(ctx, current, metav1.UpdateOptions{})
	return err
}

func provisionNamespacedServiceAccount(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	name string,
	verbs []string,
) (string, error) {
	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(
		ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}},
		metav1.CreateOptions{},
	); err != nil {
		return "", fmt.Errorf("create service account %s/%s: %w", namespace, name, err)
	}

	roleName := name + "-configmaps"
	if _, err := client.RbacV1().Roles(namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     verbs,
			}},
		},
		metav1.CreateOptions{},
	); err != nil {
		return "", fmt.Errorf("create role %s/%s: %w", namespace, roleName, err)
	}
	if _, err := client.RbacV1().RoleBindings(namespace).Create(
		ctx,
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			}},
		},
		metav1.CreateOptions{},
	); err != nil {
		return "", fmt.Errorf("create role binding %s/%s: %w", namespace, roleName, err)
	}

	token, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		name,
		&authenticationv1.TokenRequest{},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("create service account token %s/%s: %w", namespace, name, err)
	}
	if token.Status.Token == "" {
		return "", fmt.Errorf("service account token %s/%s is empty", namespace, name)
	}
	return token.Status.Token, nil
}

func serviceAccountConfig(base *rest.Config, bearerToken string) *rest.Config {
	return &rest.Config{
		Host:        base.Host,
		BearerToken: bearerToken,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:     base.CAFile,
			CAData:     append([]byte(nil), base.CAData...),
			Insecure:   base.Insecure,
			ServerName: base.ServerName,
		},
	}
}

func serviceAccountClient(base *rest.Config, bearerToken string) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(serviceAccountConfig(base, bearerToken))
}

func TestKindCrossClusterWitnessRejectsWorkloadAuthorityRollback(t *testing.T) {
	workloadKubeconfig := os.Getenv("KUBECONFIG")
	witnessKubeconfig := os.Getenv("WITNESS_KUBECONFIG")
	if workloadKubeconfig == "" || witnessKubeconfig == "" {
		t.Skip("KUBECONFIG and WITNESS_KUBECONFIG are required")
	}

	workloadConfig, err := clientcmd.BuildConfigFromFlags("", workloadKubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	witnessConfig, err := clientcmd.BuildConfigFromFlags("", witnessKubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if workloadConfig.Host == witnessConfig.Host {
		t.Fatalf("workload and witness kubeconfigs resolve to the same API server: %s", workloadConfig.Host)
	}

	workloadAdmin, err := kubernetes.NewForConfig(workloadConfig)
	if err != nil {
		t.Fatal(err)
	}
	witnessAdmin, err := kubernetes.NewForConfig(witnessConfig)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	workloadNamespace := "aegis-capability-workload"
	witnessNamespace := "aegis-capability-witness"
	for _, target := range []struct {
		client    kubernetes.Interface
		namespace string
	}{
		{workloadAdmin, workloadNamespace},
		{witnessAdmin, witnessNamespace},
	} {
		if _, err := target.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: target.namespace},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create namespace %s: %v", target.namespace, err)
		}
		client := target.client
		namespace := target.namespace
		t.Cleanup(func() {
			_ = client.CoreV1().Namespaces().Delete(
				context.Background(),
				namespace,
				metav1.DeleteOptions{},
			)
		})
	}

	workloadToken, err := provisionNamespacedServiceAccount(
		ctx,
		workloadAdmin,
		workloadNamespace,
		"workload-operator",
		[]string{"get", "list", "create", "update", "delete"},
	)
	if err != nil {
		t.Fatal(err)
	}
	rootWriterToken, err := provisionNamespacedServiceAccount(
		ctx,
		witnessAdmin,
		witnessNamespace,
		"capability-root-writer",
		[]string{"get", "list", "create", "update"},
	)
	if err != nil {
		t.Fatal(err)
	}

	workloadClient, err := serviceAccountClient(workloadConfig, workloadToken)
	if err != nil {
		t.Fatal(err)
	}
	rootWriterClient, err := serviceAccountClient(witnessConfig, rootWriterToken)
	if err != nil {
		t.Fatal(err)
	}

	// Credential separation is executable, not documentary: the workload
	// cluster's ServiceAccount token is presented directly to the witness API
	// server. Because the clusters have separate signing roots, that credential
	// must not authenticate there.
	foreignWorkloadClient, err := serviceAccountClient(witnessConfig, workloadToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignWorkloadClient.CoreV1().ConfigMaps(witnessNamespace).List(
		ctx,
		metav1.ListOptions{},
	); err == nil || (!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
		t.Fatalf("workload credential unexpectedly crossed witness trust domain: %v", err)
	}

	// Prove the inverse separation too: the witness root-writer credential must
	// not authenticate against the workload API server.
	foreignRootWriterClient, err := serviceAccountClient(workloadConfig, rootWriterToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignRootWriterClient.CoreV1().ConfigMaps(workloadNamespace).List(
		ctx,
		metav1.ListOptions{},
	); err == nil || (!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
		t.Fatalf("witness credential unexpectedly crossed workload trust domain: %v", err)
	}

	const authorityName = "mutable-capability-authority"
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   17,
		DecisionEpoch:   41,
		RevocationEpoch: 6,
	}
	if err := replaceKubernetesCapabilityIssue(
		ctx,
		workloadClient,
		workloadNamespace,
		authorityName,
		t1Issue,
	); err != nil {
		t.Fatalf("create T1 mutable authority: %v", err)
	}

	mutable := &kubernetesCapabilityFenceAuthority{
		client:    workloadClient,
		namespace: workloadNamespace,
		name:      authorityName,
	}
	headStore, err := journal.NewKubernetesHeadStore(rootWriterClient, witnessNamespace)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := NewExternalHeadCapabilityRootAnchor(
		headStore,
		"cross-cluster-capability-root",
	)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "capability-root.log")
	root, err := NewAnchoredFileCapabilityMonotonicRoot(rootPath, anchor)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}
	scope := anchoredCapabilityScope()

	if _, err := authority.Issue(ctx, scope); err != nil {
		t.Fatalf("issue T1: %v", err)
	}
	t1Ledger, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}

	t2Issue := t1Issue
	t2Issue.DecisionEpoch++
	if err := replaceKubernetesCapabilityIssue(
		ctx,
		workloadClient,
		workloadNamespace,
		authorityName,
		t2Issue,
	); err != nil {
		t.Fatalf("advance mutable authority to T2: %v", err)
	}
	if _, err := authority.Issue(ctx, scope); err != nil {
		t.Fatalf("issue T2: %v", err)
	}

	witnessT2, err := headStore.Load(ctx, "cross-cluster-capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if witnessT2.Sequence != 2 || !isCapabilityRootDigest(witnessT2.HeadHash) {
		t.Fatalf("unexpected witness head at T2: %+v", witnessT2)
	}

	// The workload operator can destructively replace its own mutable state in
	// cluster A, but it still cannot authenticate to the witness control plane.
	if err := workloadClient.CoreV1().ConfigMaps(workloadNamespace).Delete(
		ctx,
		authorityName,
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatalf("delete workload authority object: %v", err)
	}
	if err := replaceKubernetesCapabilityIssue(
		ctx,
		workloadClient,
		workloadNamespace,
		authorityName,
		t1Issue,
	); err != nil {
		t.Fatalf("recreate historical T1 authority object: %v", err)
	}
	if err := os.WriteFile(rootPath, t1Ledger, 0o600); err != nil {
		t.Fatalf("restore local root ledger to T1: %v", err)
	}

	if _, err := authority.Current(ctx, scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("Current after cross-cluster rollback = %v, want %v", err, ErrCapabilityRootRollback)
	}
	if _, err := authority.Issue(ctx, scope); !errors.Is(err, ErrCapabilityRootRollback) {
		t.Fatalf("Issue after cross-cluster rollback = %v, want %v", err, ErrCapabilityRootRollback)
	}

	witnessStillT2, err := headStore.Load(ctx, "cross-cluster-capability-root")
	if err != nil {
		t.Fatal(err)
	}
	if witnessStillT2.Sequence != witnessT2.Sequence ||
		witnessStillT2.HeadHash != witnessT2.HeadHash {
		t.Fatalf(
			"workload rollback changed independent witness: before=%+v after=%+v",
			witnessT2,
			witnessStillT2,
		)
	}
}
