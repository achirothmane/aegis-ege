package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const kubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func main() {
	if _, err := os.Stat(kubernetesServiceAccountTokenPath); err == nil {
		log.Fatalf("refusing to start: Kubernetes service account token is mounted")
	} else if !os.IsNotExist(err) {
		log.Fatalf("inspect Kubernetes service account token path: %v", err)
	}

	privateKey := mustDecodeEd25519Private(
		requireFile("HEAD_WITNESS_SIGNER_PRIVATE_KEY_PATH"),
	)
	keyID, err := kernelfabric.BootstrapKeyID(
		privateKey.Public().(ed25519.PublicKey),
	)
	must(err)
	handler, err := journal.NewExternalHeadWitnessSignerHandler(
		keyID,
		privateKey,
	)
	must(err)

	mux := http.NewServeMux()
	mux.Handle("/v1/sign", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = ":9444"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("external head witness signer listening on %s", addr)
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

func mustDecodeEd25519Private(payload []byte) ed25519.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	must(err)
	if len(raw) != ed25519.PrivateKeySize {
		log.Fatalf(
			"external head witness signer private key size=%d want=%d",
			len(raw),
			ed25519.PrivateKeySize,
		)
	}
	return ed25519.PrivateKey(raw)
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("external head witness signer: %w", err))
	}
}
