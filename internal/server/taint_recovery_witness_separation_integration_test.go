//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/achirothmane/aegis-ege/internal/recoverywitnessprofile"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	recoveryWitnessSecretNameIntegration     = "taint-recovery-witness-key"
	recoveryWitnessConfigNameIntegration     = "taint-recovery-witness-config"
	recoveryWitnessDeploymentNameIntegration = "taint-recovery-witness"
	controllerBundleVersionIntegration        = "aegis.ege/taint-recovery-controller-bundle/v2"
)

type recoveryControllerBundleIntegration struct {
	Version              string                                             `json:"version"`
	AuthorityPrivateKey  string                                             `json:"authority_private_key"`
	SignedTrust          kernelfabric.SignedTaintRecoveryTrustManifest     `json:"signed_trust"`
	SignedWitnessProfile kernelfabric.SignedExternalRecoveryWitnessProfile `json:"signed_witness_profile"`
	TrustSignerPublicKey string                                             `json:"trust_signer_public_key"`
	WitnessCAPEM         string                                             `json:"witness_ca_pem"`
	WitnessTLSServerName string                                             `json:"witness_tls_server_name"`
	Policy               recoverywitnessprofile.StaticPolicy                `json:"policy"`
}

func TestKindTaintRecoveryWitnessControlPlaneSeparation(t *testing.T) {
	workloadPath := os.Getenv("KUBECONFIG")
	witnessPath := os.Getenv("WITNESS_KUBECONFIG")
	bundlePath := os.Getenv("TAINT_RECOVERY_CONTROLLER_BUNDLE")
	endpoint := os.Getenv("TAINT_RECOVERY_WITNESS_ENDPOINT")
	if workloadPath == "" || witnessPath == "" || bundlePath == "" || endpoint == "" {
		t.Skip("runtime kubeconfigs, controller bundle, and witness endpoint are required")
	}

	workloadConfig, err := clientcmd.BuildConfigFromFlags("", workloadPath)
	if err != nil {
		t.Fatal(err)
	}
	witnessConfig, err := clientcmd.BuildConfigFromFlags("", witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if workloadConfig.Host == witnessConfig.Host {
		t.Fatalf("workload and witness runtime credentials resolve to one API server: %s", workloadConfig.Host)
	}

	ctx := context.Background()
	witnessRuntime, err := kubernetes.NewForConfig(witnessConfig)
	if err != nil {
		t.Fatal(err)
	}
	foreignWorkload, err := kubernetes.NewForConfig(
		runtimeConfigForForeignAPI(witnessConfig, workloadConfig.BearerToken),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := foreignWorkload.CoreV1().Secrets(witnessNamespace).Get(
		ctx,
		recoveryWitnessSecretNameIntegration,
		metav1.GetOptions{},
	); err == nil || (!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
		t.Fatalf("workload runtime credential read witness private-key secret: %v", err)
	}

	if _, err := witnessRuntime.CoreV1().Secrets(witnessNamespace).Get(
		ctx,
		recoveryWitnessSecretNameIntegration,
		metav1.GetOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("witness root-writer credential read witness private-key secret: %v", err)
	}

	_, err = witnessRuntime.CoreV1().ConfigMaps(witnessNamespace).Update(
		ctx,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      recoveryWitnessConfigNameIntegration,
				Namespace: witnessNamespace,
			},
			Data: map[string]string{"policy.json": "{}"},
		},
		metav1.UpdateOptions{},
	)
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("witness root-writer credential changed recovery witness policy: %v", err)
	}

	if _, err := witnessRuntime.AppsV1().Deployments(witnessNamespace).Update(
		ctx,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      recoveryWitnessDeploymentNameIntegration,
				Namespace: witnessNamespace,
			},
		},
		metav1.UpdateOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("witness root-writer credential changed signer deployment: %v", err)
	}

	bundlePayload, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(bundlePayload, &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["witness_private_key"]; exists {
		t.Fatal("controller bundle contains witness private key")
	}

	var bundle recoveryControllerBundleIntegration
	if err := json.Unmarshal(bundlePayload, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Version != controllerBundleVersionIntegration {
		t.Fatalf("controller bundle version=%q", bundle.Version)
	}
	authorityPrivateRaw, err := base64.StdEncoding.DecodeString(bundle.AuthorityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorityPrivateRaw) != ed25519.PrivateKeySize {
		t.Fatalf("authority private key size=%d want=%d", len(authorityPrivateRaw), ed25519.PrivateKeySize)
	}
	trustSignerRaw, err := base64.StdEncoding.DecodeString(bundle.TrustSignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(trustSignerRaw) != ed25519.PublicKeySize {
		t.Fatalf("trust signer public key size=%d want=%d", len(trustSignerRaw), ed25519.PublicKeySize)
	}
	root, err := kernelfabric.NewTaintRecoveryTrustRoot(
		bundle.SignedTrust,
		ed25519.PublicKey(trustSignerRaw),
		bundle.SignedTrust.Manifest.TrustEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	witnessProfile, err := kernelfabric.VerifyExternalRecoveryWitnessProfile(
		bundle.SignedWitnessProfile,
		ed25519.PublicKey(trustSignerRaw),
		root,
		bundle.SignedWitnessProfile.Profile.ProfileEpoch,
		bundle.SignedWitnessProfile.Profile.PolicyEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	if witnessProfile.Profile().Endpoint != endpoint {
		t.Fatalf("profile endpoint=%q runtime endpoint=%q", witnessProfile.Profile().Endpoint, endpoint)
	}
	policyHash, err := bundle.Policy.RecoveryWitnessPolicyHash()
	if err != nil {
		t.Fatal(err)
	}
	if witnessProfile.Profile().PolicyEpoch != bundle.Policy.PolicyEpoch ||
		witnessProfile.Profile().PolicyHash != policyHash {
		t.Fatalf("controller policy continuity does not match signed witness profile")
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(bundle.WitnessCAPEM)); !ok {
		t.Fatal("controller bundle witness CA is invalid")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
				ServerName: bundle.WitnessTLSServerName,
			},
		},
		Timeout: 10 * time.Second,
	}
	remote, err := kernelfabric.NewProfiledRemoteTaintRecoveryWitness(
		endpoint,
		root,
		witnessProfile,
		[]byte(bundle.WitnessCAPEM),
		httpClient,
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	allowed := kernelfabric.TaintRecoveryAuthorization{
		Version:         kernelfabric.TaintRecoveryAuthorizationVersion,
		AuthorizationID: "control-plane-separated-allow",
		PlanDigest:      bundle.Policy.PlanDigest,
		CgroupID:        bundle.Policy.CgroupID,
		BPFFSRoot:       bundle.Policy.BPFFSRoot,
		BootIDHash:      bundle.Policy.BootIDHash,
		FromEpoch:       bundle.Policy.FromEpoch,
		ToEpoch:         bundle.Policy.ToEpoch,
		ExpectedDirty:   bundle.Policy.ExpectedDirty,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(2 * time.Minute),
	}
	partial, err := root.SignAuthorityRequest(allowed, ed25519.PrivateKey(authorityPrivateRaw))
	if err != nil {
		t.Fatal(err)
	}
	joint, receipt, err := remote.CoSignWithReceipt(ctx, partial)
	if err != nil {
		t.Fatalf("remote witness rejected allowed authorization: %v", err)
	}
	if err := root.Verify(joint, now); err != nil {
		t.Fatalf("remote witness returned untrusted joint authorization: %v", err)
	}
	if receipt.WitnessID != witnessProfile.Profile().WitnessID ||
		receipt.ProfileEpoch != witnessProfile.Profile().ProfileEpoch ||
		receipt.PolicyEpoch != witnessProfile.Profile().PolicyEpoch ||
		receipt.PolicyHash != witnessProfile.Profile().PolicyHash ||
		receipt.TLSTrustAnchorSHA256 != witnessProfile.Profile().TLSTrustAnchorSHA256 {
		t.Fatalf("witness receipt continuity does not match pinned external profile")
	}

	denied := allowed
	denied.AuthorizationID = "control-plane-separated-policy-deny"
	denied.PlanDigest = "sha256:" + strings.Repeat("e", 64)
	partialDenied, err := root.SignAuthorityRequest(
		denied,
		ed25519.PrivateKey(authorityPrivateRaw),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := remote.CoSignWithReceipt(ctx, partialDenied); err == nil ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("witness policy bypass result=%v, want HTTP 403", err)
	}
}
