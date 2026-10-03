package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/achirothmane/aegis-ege/internal/recoverywitnessprofile"
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

	recoveryWitnessSecretName     = "taint-recovery-witness-key"
	recoveryWitnessConfigName     = "taint-recovery-witness-config"
	recoveryWitnessDeploymentName = "taint-recovery-witness"
	recoveryWitnessServiceName    = "taint-recovery-witness"
	recoveryWitnessImage          = "aegis-taint-recovery-witness:ci"
	recoveryWitnessServerName       = "aegis-witness.local"
	recoveryWitnessExternalEndpoint = "https://127.0.0.1:30443"
	recoveryWitnessNodePort   int32  = 30443

	controllerBundleVersion = "aegis.ege/taint-recovery-controller-bundle/v4"
)

type controllerBundle struct {
	Version                       string                                             `json:"version"`
	AuthorityPrivateKey           string                                             `json:"authority_private_key"`
	SignedTrust                   kernelfabric.SignedTaintRecoveryTrustManifest     `json:"signed_trust"`
	SignedWitnessProfile          kernelfabric.SignedExternalRecoveryWitnessProfile `json:"signed_witness_profile"`
	GenesisCapabilityEnvelopeBase64 string                                            `json:"genesis_capability_envelope_base64"`
	GenesisCapabilityEnvelopeHash   string                                            `json:"genesis_capability_envelope_hash"`
	TrustSignerPublicKey          string                                             `json:"trust_signer_public_key"`
	WitnessCAPEM                  string                                             `json:"witness_ca_pem"`
	WitnessTLSServerName          string                                             `json:"witness_tls_server_name"`
	Policy                        recoverywitnessprofile.StaticPolicy                `json:"policy"`
}

type recoveryGenesisCapabilityEnvelope struct {
	ExternalRecoveryWitness kernelfabric.ExternalRecoveryWitnessGenesisPolicy `json:"external_recovery_witness"`
}

func main() {
	switch requireEnv("PROVISION_PHASE") {
	case "prepare":
		must(prepareTaintRecoveryWitness(
			requireEnv("TAINT_RECOVERY_PREPARED_BUNDLE"),
			requireEnv("UNSIGNED_WITNESS_PROFILE_PATH"),
			requireEnv("PROFILE_AUTHORITY_PUBLIC_KEY_PATH"),
		))
		return
	case "activate":
	default:
		panic("PROVISION_PHASE must be prepare or activate")
	}

	ctx := context.Background()
	workloadAdminPath := requireEnv("WORKLOAD_ADMIN_KUBECONFIG")
	witnessAdminPath := requireEnv("WITNESS_ADMIN_KUBECONFIG")
	workloadRuntimePath := requireEnv("WORKLOAD_RUNTIME_KUBECONFIG")
	witnessRuntimePath := requireEnv("WITNESS_RUNTIME_KUBECONFIG")
	controllerBundlePath := requireEnv("TAINT_RECOVERY_CONTROLLER_BUNDLE")
	externalHeadBundlePath := requireEnv("EXTERNAL_HEAD_WITNESS_CLIENT_BUNDLE")
	preparedBundlePath := requireEnv("TAINT_RECOVERY_PREPARED_BUNDLE")
	signedProfilePath := requireEnv("SIGNED_WITNESS_PROFILE_PATH")

	verifiedWitness, err := verifyPreparedTaintRecoveryWitness(
		preparedBundlePath,
		signedProfilePath,
	)
	must(err)

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

	must(activateVerifiedTaintRecoveryWitness(
		ctx,
		witnessAdmin,
		controllerBundlePath,
		verifiedWitness,
	))
	must(activateExternalHeadWitness(
		ctx,
		witnessAdmin,
		externalHeadBundlePath,
	))

	must(writeRuntimeKubeconfig(workloadRuntimePath, workloadConfig, workloadToken, workloadNamespace))
	must(writeRuntimeKubeconfig(witnessRuntimePath, witnessConfig, witnessToken, witnessNamespace))
}

func newWitnessTLSCertificate(serverName string) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		nil
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

func int32Ptr(value int32) *int32 {
	return &value
}
