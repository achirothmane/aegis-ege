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
	pendingPath := flag.String("pending", "", "server-private pending enrollment state")
	proofPath := flag.String("proof", "", "TPM enrollment proof")
	out := flag.String("out", "enrolled-tpm-identity.json", "enrolled identity output")
	flag.Parse()
	if *pendingPath == "" || *proofPath == "" {
		fatalf("-pending and -proof are required")
	}
	pending, err := cliio.ReadJSON[kernelfabric.PendingTPMEnrollment](*pendingPath)
	if err != nil {
		fatalf("%v", err)
	}
	proof, err := cliio.ReadJSON[kernelfabric.TPMEnrollmentProof](*proofPath)
	if err != nil {
		fatalf("%v", err)
	}
	identity, err := kernelfabric.CompleteTPMEnrollment(pending, proof, time.Now().UTC())
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, identity, 0o600); err != nil {
		fatalf("write identity: %v", err)
	}
	fmt.Printf("enrolled TPM identity: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-tpm-enroll-complete: "+format+"\n", args...)
	os.Exit(1)
}
