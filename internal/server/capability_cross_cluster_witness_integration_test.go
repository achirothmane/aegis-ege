//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/journal"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const externalHeadWitnessBundleVersionIntegration = "aegis-ege/external-head-witness-client/v1"

type externalHeadWitnessClientBundleIntegration struct {
	Version          string                    `json:"version"`
	Endpoint         string                    `json:"endpoint"`
	TLSServerName    string                    `json:"tls_server_name"`
	CAPEM            string                    `json:"ca_pem"`
	WitnessKeyID     string                    `json:"witness_key_id"`
	WitnessPublicKey string                    `json:"witness_public_key"`
	Policy           journal.QuorumPolicyState `json:"policy"`
	JournalID        string                    `json:"journal_id"`
	StateName        string                    `json:"state_name"`
}

const (
	kubernetesCapabilityIssueKey = "issue.json"
	workloadNamespace            = "aegis-capability-workload"
	witnessNamespace             = "aegis-capability-witness"
	witnessHeadConfigMapName     = "state-latch-journal-head-cross-cluster-capability"
)

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
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Data:       map[string]string{kubernetesCapabilityIssueKey: string(payload)},
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

func runtimeConfigForForeignAPI(base *rest.Config, token string) *rest.Config {
	return &rest.Config{
		Host:        base.Host,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:     base.CAFile,
			CAData:     append([]byte(nil), base.CAData...),
			Insecure:   base.Insecure,
			ServerName: base.ServerName,
		},
	}
}

func TestKindCrossClusterWitnessRejectsWorkloadAuthorityRollback(t *testing.T) {
	workloadPath := os.Getenv("KUBECONFIG")
	witnessPath := os.Getenv("WITNESS_KUBECONFIG")
	externalHeadBundlePath := os.Getenv("EXTERNAL_HEAD_WITNESS_CLIENT_BUNDLE")
	if workloadPath == "" || witnessPath == "" || externalHeadBundlePath == "" {
		t.Skip("runtime kubeconfigs and external head witness bundle are required")
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
		t.Fatalf("workload and witness kubeconfigs resolve to the same API server: %s", workloadConfig.Host)
	}
	if workloadConfig.BearerToken == "" || witnessConfig.BearerToken == "" {
		t.Fatal("runtime kubeconfigs must contain bearer tokens")
	}

	workloadClient, err := kubernetes.NewForConfig(workloadConfig)
	if err != nil {
		t.Fatal(err)
	}
	rootWriterClient, err := kubernetes.NewForConfig(witnessConfig)
	if err != nil {
		t.Fatal(err)
	}

	bundlePayload, err := os.ReadFile(externalHeadBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var witnessBundle externalHeadWitnessClientBundleIntegration
	if err := json.Unmarshal(bundlePayload, &witnessBundle); err != nil {
		t.Fatal(err)
	}
	if witnessBundle.Version != externalHeadWitnessBundleVersionIntegration {
		t.Fatalf("external head witness bundle version=%q", witnessBundle.Version)
	}
	if witnessBundle.JournalID != "cross-cluster-capability-root" {
		t.Fatalf("external head witness journal=%q", witnessBundle.JournalID)
	}
	witnessPublicRaw, err := base64.StdEncoding.DecodeString(
		witnessBundle.WitnessPublicKey,
	)
	if err != nil || len(witnessPublicRaw) != ed25519.PublicKeySize {
		t.Fatalf("invalid external head witness public key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(witnessBundle.CAPEM)) {
		t.Fatal("external head witness CA PEM is invalid")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
				ServerName: witnessBundle.TLSServerName,
			},
		},
		Timeout: 10 * time.Second,
	}
	remoteHeadStore, err := journal.NewRemoteHeadStore(
		witnessBundle.Endpoint,
		witnessBundle.WitnessKeyID,
		ed25519.PublicKey(witnessPublicRaw),
		httpClient,
	)
	if err != nil {
		t.Fatal(err)
	}
	headStore, err := journal.NewPolicyBoundExternalHeadStore(
		remoteHeadStore,
		witnessBundle.Policy,
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Runtime credentials must not retain provisioning authority.
	if _, err := workloadClient.CoreV1().Namespaces().Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "must-not-create"}},
		metav1.CreateOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("workload runtime credential retained cluster-admin authority: %v", err)
	}
	if _, err := rootWriterClient.CoreV1().Namespaces().Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "must-not-create"}},
		metav1.CreateOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("witness runtime credential retained cluster-admin authority: %v", err)
	}

	foreignWorkload, err := kubernetes.NewForConfig(
		runtimeConfigForForeignAPI(witnessConfig, workloadConfig.BearerToken),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignWorkload.CoreV1().ConfigMaps(witnessNamespace).Get(
		ctx,
		witnessBundle.StateName,
		metav1.GetOptions{},
	); err == nil || (!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
		t.Fatalf("workload runtime credential crossed witness trust domain: %v", err)
	}

	foreignWitness, err := kubernetes.NewForConfig(
		runtimeConfigForForeignAPI(workloadConfig, witnessConfig.BearerToken),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignWitness.CoreV1().ConfigMaps(workloadNamespace).List(
		ctx,
		metav1.ListOptions{},
	); err == nil || (!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
		t.Fatalf("witness runtime credential crossed workload trust domain: %v", err)
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

	// The exported witness runtime credential is no longer the persistence
	// writer. Only the in-Pod external-head witness service account can touch
	// the governed state object.
	if _, err := rootWriterClient.CoreV1().ConfigMaps(witnessNamespace).Get(
		ctx,
		witnessBundle.StateName,
		metav1.GetOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("exported witness credential read governed witness state: %v", err)
	}
	if err := rootWriterClient.CoreV1().ConfigMaps(witnessNamespace).Delete(
		ctx,
		witnessBundle.StateName,
		metav1.DeleteOptions{},
	); err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("exported witness credential deleted governed witness state: %v", err)
	}

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
