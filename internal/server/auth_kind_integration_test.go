//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/kubeadapter"
)

func TestKindM8AuthenticatedMutationAndReplayRejection(t *testing.T) {
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

	nodeName := "state-latch-m8-auth-node"
	_, err = client.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:               corev1.NodeReady,
				Status:             corev1.ConditionTrue,
				LastHeartbeatTime:  metav1.Now(),
				LastTransitionTime: metav1.Now(),
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create synthetic node: %v", err)
	}
	t.Cleanup(func() {
		_ = client.CoreV1().Nodes().Delete(context.Background(), nodeName, metav1.DeleteOptions{})
	})

	adapter, err := kubeadapter.NewForConfigWithExperimentalMutations(config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	identity := "spiffe://state-latch.test/operator"
	authorizer, err := NewMTLSAuthorizer(AuthzFile{
		Principals: map[string][]Permission{
			identity: {PermissionPrepare, PermissionExecute},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, clientCertificate := generateClientCertificate(t, identity)
	serverTLS, err := MutualTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}

	api, err := New(
		adapter,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			Policy: kubeadapter.NodeDrainPolicy{
				MaxEvidenceAge:         15 * time.Second,
				RequiredSourceCount:    1,
				MaxBlastRadius:         10,
				AuthorizationTTL:       30 * time.Second,
				ExecutionLockNamespace: "kube-system",
				ExecutionLockDuration:  30 * time.Second,
			},
			MutationsEnabled:      true,
			RequireAuthentication: true,
			Authorizer:            authorizer,
			ReplayGuard:           replay,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	testServer := httptest.NewUnstartedServer(api.Handler())
	testServer.TLS = serverTLS
	testServer.StartTLS()
	defer testServer.Close()

	clientHTTP := testServer.Client()
	transport := clientHTTP.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	clientHTTP.Transport = transport

	preparePayload := []byte("{\"action_id\":\"m8-kind\",\"node_name\":\"" + nodeName + "\"}")
	preparation := prepareUntilStable(
		t,
		clientHTTP,
		testServer.URL,
		preparePayload,
	)

	executePayload, err := json.Marshal(executeRequest{
		NodeName:       nodeName,
		Authorization: *preparation.Authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	executeResp, err := clientHTTP.Post(
		testServer.URL+"/v1/node-drains/execute",
		"application/json",
		bytes.NewReader(executePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer executeResp.Body.Close()
	if executeResp.StatusCode != http.StatusOK {
		t.Fatalf("execute status=%d", executeResp.StatusCode)
	}
	var execution executeResponse
	if err := json.NewDecoder(executeResp.Body).Decode(&execution); err != nil {
		t.Fatal(err)
	}
	if execution.Decision != decision.Allow {
		t.Fatalf("expected authenticated execution ALLOW, got %+v", execution)
	}

	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !node.Spec.Unschedulable {
		t.Fatal("authenticated execution did not cordon node")
	}

	replayResp, err := clientHTTP.Post(
		testServer.URL+"/v1/node-drains/execute",
		"application/json",
		bytes.NewReader(executePayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected replay 409, got %d", replayResp.StatusCode)
	}
	var replayError errorResponse
	if err := json.NewDecoder(replayResp.Body).Decode(&replayError); err != nil {
		t.Fatal(err)
	}
	if replayError.Code != "EXECUTION_REPLAY_REJECTED" {
		t.Fatalf("unexpected replay error: %+v", replayError)
	}
}

func generateClientCertificate(t *testing.T, identity string) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now().UTC()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "StateLatch Test Client CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ignored-cn"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{uri},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
	certificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return caPEM, certificate
}
