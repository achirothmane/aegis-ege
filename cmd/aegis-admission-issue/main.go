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
	requestPath := flag.String("request", "", "workload admission request")
	decisionPath := flag.String("remote-decision", "", "signed remote attestation decision")
	verifierPublicKeyPath := flag.String("remote-verifier-pub", "", "remote attestation verifier public key")
	issuerPrivateKeyPath := flag.String("issuer-key", "", "admission issuer Ed25519 private key (0600)")
	issuerID := flag.String("issuer-id", "", "admission issuer authority id")
	maxAge := flag.Duration("max-attestation-age", kernelfabric.DefaultAdmissionAttestationMaxAge, "maximum accepted remote attestation age")
	ttl := flag.Duration("ttl", kernelfabric.DefaultAdmissionGrantTTL, "workload admission grant lifetime")
	out := flag.String("out", "workload-admission-grant.json", "signed grant output")
	flag.Parse()

	if *requestPath == "" || *decisionPath == "" || *verifierPublicKeyPath == "" ||
		*issuerPrivateKeyPath == "" || *issuerID == "" {
		fatalf("-request, -remote-decision, -remote-verifier-pub, -issuer-key and -issuer-id are required")
	}
	req, err := cliio.ReadJSON[kernelfabric.WorkloadAdmissionRequest](*requestPath)
	if err != nil {
		fatalf("read admission request: %v", err)
	}
	decision, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*decisionPath)
	if err != nil {
		fatalf("read remote attestation decision: %v", err)
	}
	verifierKey, err := kernelfabric.LoadEd25519PublicKey(*verifierPublicKeyPath)
	if err != nil {
		fatalf("load remote verifier public key: %v", err)
	}
	issuerKey, err := kernelfabric.LoadEd25519PrivateKey(*issuerPrivateKeyPath)
	if err != nil {
		fatalf("load admission issuer key: %v", err)
	}
	grant, err := kernelfabric.IssueWorkloadAdmissionGrant(
		req,
		decision,
		kernelfabric.WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: verifierKey,
			AdmissionIssuerKey:      issuerKey,
			AdmissionIssuerID:       *issuerID,
			MaxAttestationAge:       *maxAge,
			GrantTTL:                *ttl,
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, grant, 0o600); err != nil {
		fatalf("write signed admission grant: %v", err)
	}
	fmt.Printf("workload admission grant: %s\n", *out)
	fmt.Printf("expires at: %s\n", grant.Grant.ExpiresAt.Format(time.RFC3339Nano))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-admission-issue: "+format+"\n", args...)
	os.Exit(1)
}
