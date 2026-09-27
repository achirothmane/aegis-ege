package main

import (
	"fmt"
	"os"
	"strings"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func loadEBAApprovalVerifier(
	requireConformance bool,
	publicKeyFile string,
) (egeproto.SignatureVerifier, error) {
	publicKeyFile = strings.TrimSpace(publicKeyFile)
	if !requireConformance {
		return nil, nil
	}
	if publicKeyFile == "" {
		return nil, fmt.Errorf("eba-approval-public-key-file is required when require-eba-conformance is enabled")
	}
	data, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read EBA approval public key: %w", err)
	}
	verifier, err := egeproto.NewEd25519PublicKeyVerifierPEM(data)
	if err != nil {
		return nil, fmt.Errorf("load EBA approval public key: %w", err)
	}
	return verifier, nil
}
