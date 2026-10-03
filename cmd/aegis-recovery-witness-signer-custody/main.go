package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	witnessNamespace      = "aegis-capability-witness"
	signerSecretName      = "recovery-witness-signer-key"
	signerDeploymentName  = "recovery-witness-signer"
	signerServiceName     = "recovery-witness-signer"
	signerImage           = "aegis-recovery-witness-signer:ci"
	signerTLSServerName   = "aegis-recovery-witness-signer.local"
	signerServiceEndpoint = "https://recovery-witness-signer.aegis-capability-witness.svc:9443"
)

func main() {
	switch requireEnv("WITNESS_SIGNER_CUSTODY_MODE") {
	case "generate":
		must(generate())
	case "install":
		must(install(context.Background()))
	default:
		panic("WITNESS_SIGNER_CUSTODY_MODE must be generate or install")
	}
}

func generate() error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := newTLSCertificate(signerTLSServerName)
	if err != nil {
		return err
	}
	if err := writePrivate(
		requireEnv("WITNESS_SIGNER_PRIVATE_KEY_PATH"),
		base64.StdEncoding.EncodeToString(privateKey),
	); err != nil {
		return err
	}
	if err := writePublic(
		requireEnv("WITNESS_SIGNER_PUBLIC_KEY_PATH"),
		base64.StdEncoding.EncodeToString(publicKey),
	); err != nil {
		return err
	}
	if path := strings.TrimSpace(os.Getenv("WITNESS_SIGNER_ALGORITHM_PATH")); path != "" {
		if err := writePublic(path, "ed25519"); err != nil {
			return err
		}
	}
	if err := writePublic(requireEnv("WITNESS_SIGNER_TLS_CERT_PATH"), string(certPEM)); err != nil {
		return err
	}
	if err := writePrivate(requireEnv("WITNESS_SIGNER_TLS_KEY_PATH"), string(keyPEM)); err != nil {
		return err
	}
	if path := strings.TrimSpace(os.Getenv("WITNESS_SIGNER_ENDPOINT_PATH")); path != "" {
		if err := writePublic(path, signerServiceEndpoint); err != nil {
			return err
		}
	}
	if path := strings.TrimSpace(os.Getenv("WITNESS_SIGNER_TLS_SERVER_NAME_PATH")); path != "" {
		if err := writePublic(path, signerTLSServerName); err != nil {
			return err
		}
	}
	return nil
}

func install(ctx context.Context) error {
	config, err := clientcmd.BuildConfigFromFlags("", requireEnv("WITNESS_ADMIN_KUBECONFIG"))
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	if _, err := client.CoreV1().Namespaces().Get(ctx, witnessNamespace, metav1.GetOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		if _, err := client.CoreV1().Namespaces().Create(
			ctx,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: witnessNamespace}},
			metav1.CreateOptions{},
		); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	privateKey, err := os.ReadFile(requireEnv("WITNESS_SIGNER_PRIVATE_KEY_PATH"))
	if err != nil {
		return err
	}
	tlsCert, err := os.ReadFile(requireEnv("WITNESS_SIGNER_TLS_CERT_PATH"))
	if err != nil {
		return err
	}
	tlsKey, err := os.ReadFile(requireEnv("WITNESS_SIGNER_TLS_KEY_PATH"))
	if err != nil {
		return err
	}

	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: signerSecretName, Namespace: witnessNamespace},
		Immutable:  &immutable,
		StringData: map[string]string{
			"witness-signing-private-key": strings.TrimSpace(string(privateKey)),
			"tls.crt":                     string(tlsCert),
			"tls.key":                     string(tlsKey),
		},
	}
	if _, err := client.CoreV1().Secrets(witnessNamespace).Create(
		ctx,
		secret,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create signer custody secret: %w", err)
	}

	falseValue := false
	replicas := int32(1)
	labels := map[string]string{"app": signerDeploymentName}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: signerDeploymentName, Namespace: witnessNamespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &falseValue,
					Containers: []corev1.Container{{
						Name:            "signer",
						Image:           signerImage,
						ImagePullPolicy: corev1.PullNever,
						Env: []corev1.EnvVar{
							{Name: "WITNESS_SIGNER_PRIVATE_KEY_PATH", Value: "/run/aegis-signer/secret/witness-signing-private-key"},
							{Name: "TLS_CERT_PATH", Value: "/run/aegis-signer/secret/tls.crt"},
							{Name: "TLS_KEY_PATH", Value: "/run/aegis-signer/secret/tls.key"},
							{Name: "LISTEN_ADDR", Value: ":9443"},
						},
						Ports: []corev1.ContainerPort{{
							Name:          "https",
							ContainerPort: 9443,
							Protocol:      corev1.ProtocolTCP,
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								TCPSocket: &corev1.TCPSocketAction{
									Port: intstr.FromInt(9443),
								},
							},
							PeriodSeconds:    1,
							FailureThreshold: 30,
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "signer-secret",
							MountPath: "/run/aegis-signer/secret",
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "signer-secret",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  signerSecretName,
								DefaultMode: int32Ptr(0o400),
							},
						},
					}},
				},
			},
		},
	}
	if _, err := client.AppsV1().Deployments(witnessNamespace).Create(
		ctx,
		deployment,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create signer custody deployment: %w", err)
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: signerServiceName, Namespace: witnessNamespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Protocol:   corev1.ProtocolTCP,
				Port:       9443,
				TargetPort: intstr.FromInt(9443),
			}},
		},
	}
	if _, err := client.CoreV1().Services(witnessNamespace).Create(
		ctx,
		service,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create signer custody service: %w", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		current, err := client.AppsV1().Deployments(witnessNamespace).Get(
			ctx,
			signerDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			return err
		}
		if current.Status.ReadyReplicas >= 1 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recovery witness signer did not become ready")
		}
		time.Sleep(time.Second)
	}
}

func newTLSCertificate(serverName string) ([]byte, []byte, error) {
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

func writePrivate(path string, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}

func writePublic(path string, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}

func requireEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		panic(name + " is required")
	}
	return value
}

func int32Ptr(value int32) *int32 {
	return &value
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
