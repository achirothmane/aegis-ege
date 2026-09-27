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
	akPath := flag.String("ak", "", "persistent TPM AK blob path")
	requestPath := flag.String("request", "", "original TPM enrollment request")
	challengePath := flag.String("challenge", "", "enrollment challenge")
	out := flag.String("out", "tpm-enrollment-proof.json", "proof output")
	flag.Parse()
	if *akPath == "" || *requestPath == "" || *challengePath == "" {
		fatalf("-ak, -request and -challenge are required")
	}
	request, err := cliio.ReadJSON[kernelfabric.TPMEnrollmentRequest](*requestPath)
	if err != nil {
		fatalf("%v", err)
	}
	challenge, err := cliio.ReadJSON[kernelfabric.TPMEnrollmentChallenge](*challengePath)
	if err != nil {
		fatalf("%v", err)
	}
	proof, err := kernelfabric.ActivateTPMEnrollmentChallenge(
		*akPath, request, challenge, time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, proof, 0o600); err != nil {
		fatalf("write proof: %v", err)
	}
	fmt.Printf("TPM enrollment proof: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-tpm-enroll-activate: "+format+"\n", args...)
	os.Exit(1)
}
