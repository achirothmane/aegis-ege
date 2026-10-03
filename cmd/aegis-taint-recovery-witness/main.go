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

	var signedTrust kernelfabric.SignedTaintRecoveryTrustManifest
	mustJSONFile("TRUST_MANIFEST_PATH", &signedTrust)
	trustSignerPublic := mustDecodeEd25519Public(requireFile("TRUST_SIGNER_PUBLIC_KEY_PATH"))

	root, err := kernelfabric.NewTaintRecoveryTrustRoot(
		signedTrust,
		trustSignerPublic,
		signedTrust.Manifest.TrustEpoch,
	)
	must(err)
	genesisCapabilityEnvelope := requireFile("GENESIS_CAPABILITY_ENVELOPE_PATH")
	genesisCapabilityEnvelopeHash := strings.TrimSpace(
		string(requireFile("GENESIS_CAPABILITY_ENVELOPE_HASH_PATH")),
	)
	genesisBinding, err := kernelfabric.ParseGenesisExternalRecoveryWitnessBinding(
		genesisCapabilityEnvelope,
		genesisCapabilityEnvelopeHash,
	)
	must(err)
	var signedWitnessProfile kernelfabric.SignedExternalRecoveryWitnessProfile
	mustJSONFile("EXTERNAL_WITNESS_PROFILE_PATH", &signedWitnessProfile)
	witnessProfile, err := genesisBinding.VerifyProfile(
		signedWitnessProfile,
		root,
	)
	must(err)
	tlsCertPath := requireEnv("TLS_CERT_PATH")
	tlsCertPEM, err := os.ReadFile(tlsCertPath)
	must(err)
	must(genesisBinding.VerifyMountedTLSCertificate(
		tlsCertPEM,
		witnessProfile,
	))

	var policy recoverywitnessprofile.StaticPolicy
	mustJSONFile("WITNESS_POLICY_PATH", &policy)
	must(policy.Validate())

	witnessPublic := mustDecodeEd25519Public([]byte(signedTrust.Manifest.WitnessPublicKey))
	signerEndpoint := strings.TrimSpace(string(requireFile("WITNESS_SIGNER_ENDPOINT_PATH")))
	signerCAPEM := requireFile("WITNESS_SIGNER_CA_PATH")
	signerServerName := strings.TrimSpace(
		string(requireFile("WITNESS_SIGNER_TLS_SERVER_NAME_PATH")),
	)
	signerRoots := x509.NewCertPool()
	if ok := signerRoots.AppendCertsFromPEM(signerCAPEM); !ok {
		log.Fatal("witness signer TLS CA is invalid")
	}
	signerHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    signerRoots,
				ServerName: signerServerName,
			},
		},
		Timeout: 5 * time.Second,
	}
	witnessSigner, err := kernelfabric.NewRemoteRecoveryWitnessSigner(
		signerEndpoint,
		signedTrust.Manifest.WitnessKeyID,
		witnessPublic,
		signerHTTPClient,
	)
	must(err)

	handler, err := kernelfabric.NewProfiledTaintRecoveryWitnessHandlerWithSigner(
		root,
		witnessSigner,
		policy,
		witnessProfile,
		time.Now,
	)
	must(err)
	mux := http.NewServeMux()
	mux.Handle("/v1/recovery/cosign", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = ":8443"
	}
	certPath := tlsCertPath
	keyPath := requireEnv("TLS_KEY_PATH")
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
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
