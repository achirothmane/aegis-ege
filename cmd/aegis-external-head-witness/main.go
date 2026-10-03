package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	ctx := context.Background()
	namespace := requireEnv("WITNESS_STATE_NAMESPACE")
	stateName := requireEnv("WITNESS_STATE_NAME")
	keyID := requireEnv("WITNESS_KEY_ID")

	var expectedPolicy journal.QuorumPolicyState
	mustJSONFile("WITNESS_POLICY_PATH", &expectedPolicy)

	signerPublic := decodePublicKey(
		requireFile("HEAD_WITNESS_SIGNER_PUBLIC_KEY_PATH"),
	)
	expectedKeyID, err := kernelfabric.BootstrapKeyID(signerPublic)
	must(err)
	if expectedKeyID != keyID {
		log.Fatalf(
			"external head witness signer public key id=%q want=%q",
			expectedKeyID,
			keyID,
		)
	}
	signerRoots := x509.NewCertPool()
	if !signerRoots.AppendCertsFromPEM(
		requireFile("HEAD_WITNESS_SIGNER_TLS_CA_PATH"),
	) {
		log.Fatal("external head witness signer CA is invalid")
	}
	signerClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    signerRoots,
				ServerName: requireEnv("HEAD_WITNESS_SIGNER_TLS_SERVER_NAME"),
			},
		},
		Timeout: 5 * time.Second,
	}
	signer, err := journal.NewRemoteExternalHeadWitnessSigner(
		requireEnv("HEAD_WITNESS_SIGNER_ENDPOINT"),
		keyID,
		signerPublic,
		signerClient,
	)
	must(err)

	config, err := rest.InClusterConfig()
	must(err)
	client, err := kubernetes.NewForConfig(config)
	must(err)
	stateStore, err := journal.NewKubernetesGovernedWitnessStateStore(
		client,
		namespace,
		stateName,
	)
	must(err)
	if _, err := journal.InitializeGovernedWitnessState(
		ctx,
		stateStore,
		expectedPolicy,
	); err != nil {
		log.Fatalf("verify governed witness startup state: %v", err)
	}

	handler, err := journal.NewGovernedRemoteWitnessHandlerWithSigner(
		stateStore,
		keyID,
		signer,
	)
	must(err)

	mux := http.NewServeMux()
	mux.Handle("/v1/", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if _, err := stateStore.Load(r.Context()); err != nil {
			http.Error(w, "witness state unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = ":8443"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("external head witness listening on %s", addr)
	if err := server.ListenAndServeTLS(
		requireEnv("TLS_CERT_PATH"),
		requireEnv("TLS_KEY_PATH"),
	); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func requireEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func requireFile(envName string) []byte {
	payload, err := os.ReadFile(requireEnv(envName))
	must(err)
	return payload
}

func mustJSONFile(envName string, target any) {
	if err := json.Unmarshal(requireFile(envName), target); err != nil {
		log.Fatalf("decode %s: %v", envName, err)
	}
}

func decodePublicKey(payload []byte) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	must(err)
	if len(raw) != ed25519.PublicKeySize {
		log.Fatalf(
			"external head witness signer public key size=%d want=%d",
			len(raw),
			ed25519.PublicKeySize,
		)
	}
	return ed25519.PublicKey(raw)
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("external head witness: %w", err))
	}
}
