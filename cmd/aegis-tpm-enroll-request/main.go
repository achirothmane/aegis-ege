//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	deviceID := flag.String("device", "", "stable device identifier")
	akPath := flag.String("ak", "", "persistent TPM AK blob path")
	attestorPub := flag.String("bootstrap-attestor-pub", "", "bootstrap attestor Ed25519 public key")
	out := flag.String("out", "tpm-enrollment-request.json", "request output")
	flag.Parse()
	if *deviceID == "" || *akPath == "" || *attestorPub == "" {
		fatalf("-device, -ak and -bootstrap-attestor-pub are required")
	}
	req, err := kernelfabric.ProvisionTPMEnrollmentRequest(
		*deviceID, *akPath, *attestorPub, time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, req, 0o600); err != nil {
		fatalf("write request: %v", err)
	}
	fmt.Printf("TPM enrollment request: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-tpm-enroll-request: "+format+"\n", args...)
	os.Exit(1)
}
