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
	challengePath := flag.String("challenge", "", "remote attestation challenge")
	receiptPath := flag.String("bootstrap-receipt", "", "signed BPF bootstrap receipt")
	imaPath := flag.String("ima", kernelfabric.DefaultIMASHA256MeasurementsPath, "IMA SHA-256 measurement log")
	out := flag.String("out", "remote-attestation-evidence.json", "evidence output")
	flag.Parse()
	if *akPath == "" || *challengePath == "" || *receiptPath == "" {
		fatalf("-ak, -challenge and -bootstrap-receipt are required")
	}
	challenge, err := cliio.ReadJSON[kernelfabric.RemoteAttestationChallenge](*challengePath)
	if err != nil {
		fatalf("%v", err)
	}
	receipt, err := cliio.ReadJSON[kernelfabric.SignedBootstrapReceipt](*receiptPath)
	if err != nil {
		fatalf("%v", err)
	}
	evidence, err := kernelfabric.CollectRemoteAttestationEvidence(
		*akPath, challenge, receipt, *imaPath, time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, evidence, 0o600); err != nil {
		fatalf("write evidence: %v", err)
	}
	fmt.Printf("remote attestation evidence: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-attest-collect: "+format+"\n", args...)
	os.Exit(1)
}
