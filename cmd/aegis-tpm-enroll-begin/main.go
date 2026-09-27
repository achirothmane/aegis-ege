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
	requestPath := flag.String("request", "", "TPM enrollment request")
	allowedEK := flag.String("allow-ek-spki", "", "allowed EK SPKI SHA-256 (sha256:<hex>)")
	challengeOut := flag.String("challenge-out", "tpm-enrollment-challenge.json", "public challenge output")
	pendingOut := flag.String("pending-out", "tpm-enrollment-pending.json", "server-private pending state output")
	ttl := flag.Duration("ttl", 2*time.Minute, "credential activation challenge TTL")
	flag.Parse()
	if *requestPath == "" || *allowedEK == "" {
		fatalf("-request and -allow-ek-spki are required")
	}
	req, err := cliio.ReadJSON[kernelfabric.TPMEnrollmentRequest](*requestPath)
	if err != nil {
		fatalf("%v", err)
	}
	challenge, pending, err := kernelfabric.BeginTPMEnrollment(
		req,
		kernelfabric.TPMEnrollmentTrustPolicy{
			AllowedEKSPKI: map[string]struct{}{*allowedEK: {}},
		},
		*ttl,
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*challengeOut, challenge, 0o644); err != nil {
		fatalf("write challenge: %v", err)
	}
	if err := cliio.WriteJSON(*pendingOut, pending, 0o600); err != nil {
		fatalf("write pending state: %v", err)
	}
	fmt.Printf("enrollment challenge: %s\n", *challengeOut)
	fmt.Printf("private pending state: %s\n", *pendingOut)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-tpm-enroll-begin: "+format+"\n", args...)
	os.Exit(1)
}
