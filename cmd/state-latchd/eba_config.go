package main

import (
	"fmt"
	"os"
	"strings"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func validateEBADaemonConfig(
	requireConformance bool,
	mutationsEnabled bool,
	publicKeyFile string,
) error {
	if !requireConformance {
		return nil
	}
	if !mutationsEnabled {
		return fmt.Errorf("require-eba-conformance requires enable-mutations")
	}
	if strings.TrimSpace(publicKeyFile) == "" {
		return fmt.Errorf("eba-approval-public-key-file is required when require-eba-conformance is enabled")
	}
	return nil
}

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
