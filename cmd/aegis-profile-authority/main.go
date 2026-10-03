package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	switch requireEnv("PROFILE_AUTHORITY_MODE") {
	case "generate":
		must(generate())
	case "sign":
		must(sign())
	default:
		panic("PROFILE_AUTHORITY_MODE must be generate or sign")
	}
}

func generate() error {
	privatePath := requireEnv("PROFILE_AUTHORITY_PRIVATE_KEY_PATH")
	publicPath := requireEnv("PROFILE_AUTHORITY_PUBLIC_KEY_PATH")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writePrivate(privatePath, base64.StdEncoding.EncodeToString(privateKey)); err != nil {
		return err
	}
	return writePublic(publicPath, base64.StdEncoding.EncodeToString(publicKey))
}

func sign() error {
	privatePath := requireEnv("PROFILE_AUTHORITY_PRIVATE_KEY_PATH")
	unsignedProfilePath := requireEnv("UNSIGNED_WITNESS_PROFILE_PATH")
	signedProfilePath := requireEnv("SIGNED_WITNESS_PROFILE_PATH")

	privateRaw, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("read profile authority private key: %w", err)
	}
	decodedPrivate, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateRaw)))
	if err != nil || len(decodedPrivate) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid profile authority private key")
	}

	unsignedRaw, err := os.ReadFile(unsignedProfilePath)
	if err != nil {
		return fmt.Errorf("read unsigned witness profile: %w", err)
	}
	var profile kernelfabric.ExternalRecoveryWitnessProfile
	if err := json.Unmarshal(unsignedRaw, &profile); err != nil {
		return fmt.Errorf("decode unsigned witness profile: %w", err)
	}
	signed, err := kernelfabric.SignExternalRecoveryWitnessProfile(
		profile,
		ed25519.PrivateKey(decodedPrivate),
	)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(signedProfilePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(signedProfilePath, payload, 0o644)
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}
