package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	ctx := context.Background()
	namespace := requireEnv("WITNESS_STATE_NAMESPACE")
	stateName := requireEnv("WITNESS_STATE_NAME")
	keyID := requireEnv("WITNESS_KEY_ID")
	privateKey := decodePrivateKey(requireFile("WITNESS_PRIVATE_KEY_PATH"))

	var expectedPolicy journal.QuorumPolicyState
	mustJSONFile("WITNESS_POLICY_PATH", &expectedPolicy)

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

	handler, err := journal.NewGovernedRemoteWitnessHandler(
		stateStore,
		keyID,
		privateKey,
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

func decodePrivateKey(payload []byte) ed25519.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	must(err)
	if len(raw) != ed25519.PrivateKeySize {
		log.Fatalf(
			"witness private key size=%d want=%d",
			len(raw),
			ed25519.PrivateKeySize,
		)
	}
	return ed25519.PrivateKey(raw)
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("external head witness: %w", err))
	}
}
