package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/achirothmane/aegis-ege/internal/recoverywitnessprofile"
)

const kubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func main() {
	if _, err := os.Stat(kubernetesServiceAccountTokenPath); err == nil {
		log.Fatalf("refusing to start: Kubernetes service account token is mounted")
	} else if !os.IsNotExist(err) {
		log.Fatalf("inspect Kubernetes service account token path: %v", err)
	}

	witnessPrivate := mustDecodeEd25519Private(requireFile("WITNESS_PRIVATE_KEY_PATH"))
	var signedTrust kernelfabric.SignedTaintRecoveryTrustManifest
	mustJSONFile("TRUST_MANIFEST_PATH", &signedTrust)
	trustSignerPublic := mustDecodeEd25519Public(requireFile("TRUST_SIGNER_PUBLIC_KEY_PATH"))

	root, err := kernelfabric.NewTaintRecoveryTrustRoot(
		signedTrust,
		trustSignerPublic,
		signedTrust.Manifest.TrustEpoch,
	)
	must(err)

	var policy recoverywitnessprofile.StaticPolicy
	mustJSONFile("WITNESS_POLICY_PATH", &policy)
	must(policy.Validate())

	handler, err := kernelfabric.NewTaintRecoveryWitnessHandler(
		root,
		witnessPrivate,
		policy,
		time.Now,
	)
	must(err)

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = ":8443"
	}
	certPath := requireEnv("TLS_CERT_PATH")
	keyPath := requireEnv("TLS_KEY_PATH")
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("taint recovery witness listening on %s", addr)
	if err := server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
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
	path := requireEnv(envName)
	payload, err := os.ReadFile(path)
	must(err)
	return payload
}

func mustJSONFile(envName string, target any) {
	payload := requireFile(envName)
	if err := json.Unmarshal(payload, target); err != nil {
		log.Fatalf("decode %s: %v", envName, err)
	}
}

func mustDecodeEd25519Private(payload []byte) ed25519.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	must(err)
	if len(raw) != ed25519.PrivateKeySize {
		log.Fatalf("witness private key size=%d want=%d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw)
}

func mustDecodeEd25519Public(payload []byte) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(payload)))
	must(err)
	if len(raw) != ed25519.PublicKeySize {
		log.Fatalf("trust signer public key size=%d want=%d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw)
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("taint recovery witness: %w", err))
	}
}
