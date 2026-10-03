package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/achirothmane/aegis-ege/internal/journal"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	workloadNamespace = "aegis-capability-workload"
	witnessNamespace  = "aegis-capability-witness"

	workloadServiceAccount = "workload-operator"
	witnessServiceAccount  = "capability-root-writer"

	witnessJournalID = "cross-cluster-capability-root"
	witnessKeyID     = "aegis-ege/capability-root-head/v1"
	witnessHeadName  = "state-latch-journal-head-cross-cluster-capability"
)

func main() {
	ctx := context.Background()
	workloadAdminPath := requireEnv("WORKLOAD_ADMIN_KUBECONFIG")
	witnessAdminPath := requireEnv("WITNESS_ADMIN_KUBECONFIG")
	workloadRuntimePath := requireEnv("WORKLOAD_RUNTIME_KUBECONFIG")
	witnessRuntimePath := requireEnv("WITNESS_RUNTIME_KUBECONFIG")

	workloadConfig, err := clientcmd.BuildConfigFromFlags("", workloadAdminPath)
	must(err)
	witnessConfig, err := clientcmd.BuildConfigFromFlags("", witnessAdminPath)
	must(err)
	if workloadConfig.Host == witnessConfig.Host {
		panic("workload and witness admin kubeconfigs resolve to the same API server")
	}

	workloadAdmin, err := kubernetes.NewForConfig(workloadConfig)
	must(err)
	witnessAdmin, err := kubernetes.NewForConfig(witnessConfig)
	must(err)

	must(ensureNamespace(ctx, workloadAdmin, workloadNamespace))
	must(ensureNamespace(ctx, witnessAdmin, witnessNamespace))

	workloadToken, err := provisionServiceAccount(
		ctx,
		workloadAdmin,
		workloadNamespace,
		workloadServiceAccount,
		[]rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "create", "update", "delete"},
		}},
	)
	must(err)

	headStore, err := journal.NewKubernetesHeadStore(witnessAdmin, witnessNamespace)
	must(err)
	zero := journal.ExternalHead{
		JournalID: witnessJournalID,
		Sequence:  0,
		HeadHash:  "",
		KeyID:     witnessKeyID,
	}
	if _, err := headStore.CompareAndAdvance(ctx, journal.ExternalHead{}, zero); err != nil &&
		!errors.Is(err, journal.ErrExternalHeadConflict) {
		panic(fmt.Sprintf("initialize witness head: %v", err))
	}

	witnessToken, err := provisionServiceAccount(
		ctx,
		witnessAdmin,
		witnessNamespace,
		witnessServiceAccount,
		[]rbacv1.PolicyRule{{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{witnessHeadName},
			Verbs:         []string{"get", "update"},
		}},
	)
	must(err)

	must(writeRuntimeKubeconfig(workloadRuntimePath, workloadConfig, workloadToken, workloadNamespace))
	must(writeRuntimeKubeconfig(witnessRuntimePath, witnessConfig, witnessToken, witnessNamespace))
}

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(name + " is required")
	}
	return value
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func ensureNamespace(ctx context.Context, client kubernetes.Interface, namespace string) error {
	_, err := client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	_, err = client.CoreV1().Namespaces().Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
		metav1.CreateOptions{},
	)
	return err
}

func provisionServiceAccount(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	name string,
	rules []rbacv1.PolicyRule,
) (string, error) {
	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(
		ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}

	roleName := name + "-runtime"
	if _, err := client.RbacV1().Roles(namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			Rules:      rules,
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
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
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}

	token, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		name,
		&authenticationv1.TokenRequest{},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", err
	}
	if token.Status.Token == "" {
		return "", errors.New("service account token is empty")
	}
	return token.Status.Token, nil
}

func writeRuntimeKubeconfig(
	path string,
	base *rest.Config,
	token string,
	namespace string,
) error {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["runtime"] = &clientcmdapi.Cluster{
		Server:                   base.Host,
		CertificateAuthority:     base.CAFile,
		CertificateAuthorityData: append([]byte(nil), base.CAData...),
		InsecureSkipTLSVerify:    base.Insecure,
		TLSServerName:            base.ServerName,
	}
	cfg.AuthInfos["runtime"] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts["runtime"] = &clientcmdapi.Context{
		Cluster:   "runtime",
		AuthInfo:  "runtime",
		Namespace: namespace,
	}
	cfg.CurrentContext = "runtime"

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return clientcmd.WriteToFile(*cfg, path)
}
