package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const kubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func main() {
	if _, err := os.Stat(kubernetesServiceAccountTokenPath); err == nil {
		log.Fatalf("refusing to start: Kubernetes service account token is mounted")
	} else if !os.IsNotExist(err) {
		log.Fatalf("inspect Kubernetes service account token path: %v", err)
	}

	tpmPath := strings.TrimSpace(os.Getenv("TPM_DEVICE_PATH"))
	if tpmPath == "" {
		tpmPath = "/dev/tpmrm0"
	}
	mode := requireEnv("WITNESS_TPM_SIGNER_MODE")
	if mode == "hardware-proof" {
		must(runHardwareProof(tpmPath))
		return
	}

	tpm, err := legacytpm2.OpenTPM(tpmPath)
	must(err)

	ownerAuth := readOptionalSecret("TPM_OWNER_AUTH_PATH")
	keyAuth := readOptionalSecret("WITNESS_TPM_KEY_AUTH_PATH")
	signer, err := kernelfabric.NewTPMRecoveryWitnessSignerWithAuth(
		tpm,
		ownerAuth,
		keyAuth,
	)
	must(err)
	defer signer.Close()

	switch mode {
	case "identity":
		encodedPublicKey, err := signer.Verifier().EncodedPublicKey()
		must(err)
		must(writePublic(
			requireEnv("WITNESS_SIGNER_ALGORITHM_PATH"),
			signer.Verifier().Algorithm(),
		))
		must(writePublic(
			requireEnv("WITNESS_SIGNER_PUBLIC_KEY_PATH"),
			encodedPublicKey,
		))
		must(writePublic(
			requireEnv("WITNESS_SIGNER_KEY_ID_PATH"),
			signer.KeyID(),
		))
		return
	case "serve":
	default:
		log.Fatal("WITNESS_TPM_SIGNER_MODE must be identity, serve, or hardware-proof")
	}

	if expectedPath := strings.TrimSpace(os.Getenv("EXPECTED_WITNESS_KEY_ID_PATH")); expectedPath != "" {
		expectedRaw, err := os.ReadFile(expectedPath)
		must(err)
		expected := strings.TrimSpace(string(expectedRaw))
		if expected == "" || expected != signer.KeyID() {
			log.Fatalf("TPM witness key identity changed: got=%q want=%q", signer.KeyID(), expected)
		}
	}

	handler, err := kernelfabric.NewRecoveryWitnessSignerHandlerWithSigner(signer)
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
		addr = ":9443"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("TPM-backed recovery witness signer key_id=%s listening on %s", signer.KeyID(), addr)
	if err := server.ListenAndServeTLS(
		requireEnv("TLS_CERT_PATH"),
		requireEnv("TLS_KEY_PATH"),
	); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func runHardwareProof(tpmPath string) error {
	hardware, err := kernelfabric.CaptureTPMHardwareIdentityEvidence(tpmPath)
	if err != nil {
		return err
	}
	expectedEK, err := readRequiredTrimmedFile("EXPECTED_TPM_EK_SHA256_PATH")
	if err != nil {
		return err
	}
	if hardware.EKSPKISHA256 != expectedEK {
		return fmt.Errorf(
			"TPM EK identity changed: got=%q want=%q",
			hardware.EKSPKISHA256,
			expectedEK,
		)
	}

	tpm, err := legacytpm2.OpenTPM(tpmPath)
	if err != nil {
		return err
	}
	signer, err := kernelfabric.NewTPMRecoveryWitnessSignerWithAuth(
		tpm,
		readOptionalSecret("TPM_OWNER_AUTH_PATH"),
		readOptionalSecret("WITNESS_TPM_KEY_AUTH_PATH"),
	)
	if err != nil {
		_ = tpm.Close()
		return err
	}
	defer signer.Close()

	expectedKeyID, err := readRequiredTrimmedFile("EXPECTED_WITNESS_KEY_ID_PATH")
	if err != nil {
		return err
	}
	if signer.KeyID() != expectedKeyID {
		return fmt.Errorf(
			"TPM witness key identity changed: got=%q want=%q",
			signer.KeyID(),
			expectedKeyID,
		)
	}
	challenge, err := kernelfabric.NewTPMHardwareEvidenceChallenge()
	if err != nil {
		return err
	}
	receipt, err := kernelfabric.CreateTPMRecoveryWitnessHardwareReceipt(
		context.Background(),
		signer,
		hardware,
		challenge,
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if err := kernelfabric.VerifyTPMRecoveryWitnessHardwareReceipt(receipt); err != nil {
		return fmt.Errorf("self-verify TPM hardware receipt: %w", err)
	}
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return writePublic(
		requireEnv("TPM_HARDWARE_RECEIPT_PATH"),
		string(payload),
	)
}

func readRequiredTrimmedFile(envName string) (string, error) {
	path := requireEnv(envName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", envName, err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%s is empty", envName)
	}
	return value, nil
}

func readOptionalSecret(envName string) string {
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	must(err)
	return strings.TrimSpace(string(raw))
}

func writePublic(path string, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(value)+"\n"), 0o644)
}

func requireEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("TPM recovery witness signer: %w", err))
	}
}
