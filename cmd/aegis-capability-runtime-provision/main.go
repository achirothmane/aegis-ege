package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/achirothmane/aegis-ege/internal/recoverywitnessprofile"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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

	controllerBundleVersion = "aegis.ege/taint-recovery-controller-bundle/v2"
)

type controllerBundle struct {
	Version              string                                            `json:"version"`
	AuthorityPrivateKey  string                                            `json:"authority_private_key"`
	SignedTrust          kernelfabric.SignedTaintRecoveryTrustManifest    `json:"signed_trust"`
	SignedWitnessProfile kernelfabric.SignedExternalRecoveryWitnessProfile `json:"signed_witness_profile"`
	TrustSignerPublicKey string                                            `json:"trust_signer_public_key"`
	WitnessCAPEM         string                                            `json:"witness_ca_pem"`
	WitnessTLSServerName string                                            `json:"witness_tls_server_name"`
	Policy               recoverywitnessprofile.StaticPolicy               `json:"policy"`
}

func main() {
	ctx := context.Background()
	workloadAdminPath := requireEnv("WORKLOAD_ADMIN_KUBECONFIG")
	witnessAdminPath := requireEnv("WITNESS_ADMIN_KUBECONFIG")
	workloadRuntimePath := requireEnv("WORKLOAD_RUNTIME_KUBECONFIG")
	witnessRuntimePath := requireEnv("WITNESS_RUNTIME_KUBECONFIG")
	controllerBundlePath := requireEnv("TAINT_RECOVERY_CONTROLLER_BUNDLE")

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

	must(provisionTaintRecoveryWitness(ctx, witnessAdmin, controllerBundlePath))

	must(writeRuntimeKubeconfig(workloadRuntimePath, workloadConfig, workloadToken, workloadNamespace))
	must(writeRuntimeKubeconfig(witnessRuntimePath, witnessConfig, witnessToken, witnessNamespace))
}

func provisionTaintRecoveryWitness(
	ctx context.Context,
	witnessAdmin kubernetes.Interface,
	controllerBundlePath string,
) error {
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	trustSignerPublic, trustSignerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	authorityKeyID, err := kernelfabric.BootstrapKeyID(authorityPublic)
	if err != nil {
		return err
	}
	recoveryWitnessKeyID, err := kernelfabric.BootstrapKeyID(witnessPublic)
	if err != nil {
		return err
	}
	const trustEpoch uint64 = 1
	signedTrust, err := kernelfabric.SignTaintRecoveryTrustManifest(
		kernelfabric.TaintRecoveryTrustManifest{
			Version:            kernelfabric.TaintRecoveryTrustManifestVersion,
			TrustEpoch:         trustEpoch,
			AuthorityPrincipal: "workload/recovery-controller",
			AuthorityKeyID:     authorityKeyID,
			AuthorityPublicKey: base64.StdEncoding.EncodeToString(authorityPublic),
			WitnessPrincipal:   "witness/control-plane-b",
			WitnessKeyID:       recoveryWitnessKeyID,
			WitnessPublicKey:   base64.StdEncoding.EncodeToString(witnessPublic),
		},
		trustSignerPrivate,
	)
	if err != nil {
		return err
	}

	policy := recoverywitnessprofile.StaticPolicy{
		Version:       recoverywitnessprofile.StaticPolicyVersion,
		PolicyEpoch:   1,
		PlanDigest:    "sha256:" + strings.Repeat("c", 64),
		CgroupID:      4242,
		BPFFSRoot:     "/sys/fs/bpf/aegis-ege/taint-ci",
		BootIDHash:    "sha256:" + strings.Repeat("d", 64),
		FromEpoch:     11,
		ToEpoch:       12,
		ExpectedDirty: 7,
	}
	if err := policy.Validate(); err != nil {
		return err
	}

	trustPayload, err := json.Marshal(signedTrust)
	if err != nil {
		return err
	}
	policyPayload, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	tlsCertPEM, tlsKeyPEM, err := newWitnessTLSCertificate(recoveryWitnessServerName)
	if err != nil {
		return err
	}
	policyHash, err := policy.RecoveryWitnessPolicyHash()
	if err != nil {
		return err
	}
	tlsTrustAnchorHash, err := kernelfabric.TLSCertificatePEMSHA256(tlsCertPEM)
	if err != nil {
		return err
	}
	signedWitnessProfile, err := kernelfabric.SignExternalRecoveryWitnessProfile(
		kernelfabric.ExternalRecoveryWitnessProfile{
			Version:              kernelfabric.ExternalRecoveryWitnessProfileVersion,
			ProfileEpoch:         1,
			WitnessID:            "witness/control-plane-b",
			WitnessKeyID:         recoveryWitnessKeyID,
			Endpoint:             recoveryWitnessExternalEndpoint,
			TLSTrustAnchorSHA256: tlsTrustAnchorHash,
			PolicyEpoch:          policy.PolicyEpoch,
			PolicyHash:           policyHash,
		},
		trustSignerPrivate,
	)
	if err != nil {
		return err
	}
	witnessProfilePayload, err := json.Marshal(signedWitnessProfile)
	if err != nil {
		return err
	}

	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessSecretName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		StringData: map[string]string{
			"witness-private-key": base64.StdEncoding.EncodeToString(witnessPrivate),
			"tls.crt":             string(tlsCertPEM),
			"tls.key":             string(tlsKeyPEM),
		},
	}
	if _, err := witnessAdmin.CoreV1().Secrets(witnessNamespace).Create(
		ctx,
		secret,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness secret: %w", err)
	}

	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessConfigName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		Data: map[string]string{
			"trust-manifest.json":       string(trustPayload),
			"external-profile.json":     string(witnessProfilePayload),
			"trust-signer-public-key":  base64.StdEncoding.EncodeToString(trustSignerPublic),
			"policy.json":               string(policyPayload),
		},
	}
	if _, err := witnessAdmin.CoreV1().ConfigMaps(witnessNamespace).Create(
		ctx,
		config,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness config: %w", err)
	}

	falseValue := false
	replicas := int32(1)
	labels := map[string]string{"app": recoveryWitnessDeploymentName}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessDeploymentName,
			Namespace: witnessNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &falseValue,
					Containers: []corev1.Container{{
						Name:            "witness",
						Image:           recoveryWitnessImage,
						ImagePullPolicy: corev1.PullNever,
						Env: []corev1.EnvVar{
							{Name: "WITNESS_PRIVATE_KEY_PATH", Value: "/run/aegis-witness/secret/witness-private-key"},
							{Name: "TRUST_MANIFEST_PATH", Value: "/run/aegis-witness/config/trust-manifest.json"},
							{Name: "EXTERNAL_WITNESS_PROFILE_PATH", Value: "/run/aegis-witness/config/external-profile.json"},
							{Name: "TRUST_SIGNER_PUBLIC_KEY_PATH", Value: "/run/aegis-witness/config/trust-signer-public-key"},
							{Name: "WITNESS_POLICY_PATH", Value: "/run/aegis-witness/config/policy.json"},
							{Name: "TLS_CERT_PATH", Value: "/run/aegis-witness/secret/tls.crt"},
							{Name: "TLS_KEY_PATH", Value: "/run/aegis-witness/secret/tls.key"},
							{Name: "LISTEN_ADDR", Value: ":8443"},
						},
						Ports: []corev1.ContainerPort{{
							Name:          "https",
							ContainerPort: 8443,
							Protocol:      corev1.ProtocolTCP,
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   intstr.FromInt(8443),
									Scheme: corev1.URISchemeHTTPS,
								},
							},
							PeriodSeconds:    1,
							FailureThreshold: 30,
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "secret", MountPath: "/run/aegis-witness/secret", ReadOnly: true},
							{Name: "config", MountPath: "/run/aegis-witness/config", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  recoveryWitnessSecretName,
									DefaultMode: int32Ptr(0o400),
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: recoveryWitnessConfigName},
									DefaultMode:          int32Ptr(0o400),
								},
							},
						},
					},
				},
			},
		},
	}
	if _, err := witnessAdmin.AppsV1().Deployments(witnessNamespace).Create(
		ctx,
		deployment,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness deployment: %w", err)
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessServiceName,
			Namespace: witnessNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Protocol:   corev1.ProtocolTCP,
				Port:       443,
				TargetPort: intstr.FromInt(8443),
				NodePort:   recoveryWitnessNodePort,
			}},
		},
	}
	if _, err := witnessAdmin.CoreV1().Services(witnessNamespace).Create(
		ctx,
		service,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness service: %w", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		current, err := witnessAdmin.AppsV1().Deployments(witnessNamespace).Get(
			ctx,
			recoveryWitnessDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			return err
		}
		if current.Status.ReadyReplicas >= 1 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recovery witness deployment did not become ready")
		}
		time.Sleep(time.Second)
	}

	bundle := controllerBundle{
		Version:              controllerBundleVersion,
		AuthorityPrivateKey:  base64.StdEncoding.EncodeToString(authorityPrivate),
		SignedTrust:          signedTrust,
		SignedWitnessProfile: signedWitnessProfile,
		TrustSignerPublicKey: base64.StdEncoding.EncodeToString(trustSignerPublic),
		WitnessCAPEM:         string(tlsCertPEM),
		WitnessTLSServerName: recoveryWitnessServerName,
		Policy:               policy,
	}
	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(controllerBundlePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(controllerBundlePath, payload, 0o600)
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
