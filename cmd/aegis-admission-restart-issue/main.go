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
	requestPath := flag.String("request", "", "fresh workload admission request")
	remotePath := flag.String("remote-decision", "", "signed remote attestation decision")
	restartPath := flag.String("restart-decision", "", "signed lifecycle restart decision")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	remoteVerifierPubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	issuerKeyPath := flag.String("issuer-key", "", "admission issuer private key (0600)")
	issuerID := flag.String("issuer-id", "", "admission issuer id")
	maxAge := flag.Duration("max-attestation-age", kernelfabric.DefaultAdmissionAttestationMaxAge, "maximum accepted attestation age")
	ttl := flag.Duration("ttl", kernelfabric.DefaultAdmissionGrantTTL, "fresh restart grant TTL")
	out := flag.String("out", "workload-restart-admission-grant.json", "signed fresh restart grant output")
	flag.Parse()

	if *requestPath == "" || *remotePath == "" || *restartPath == "" ||
		*lifecyclePubPath == "" || *remoteVerifierPubPath == "" ||
		*issuerKeyPath == "" || *issuerID == "" {
		fatalf("all request, decision, trust-key and issuer flags are required")
	}
	req, err := cliio.ReadJSON[kernelfabric.WorkloadAdmissionRequest](*requestPath)
	if err != nil { fatalf("read admission request: %v", err) }
	remote, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
	if err != nil { fatalf("read remote decision: %v", err) }
	restart, err := cliio.ReadJSON[kernelfabric.SignedWorkloadRestartDecision](*restartPath)
	if err != nil { fatalf("read restart decision: %v", err) }
	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle authority public key: %v", err) }
	remoteVerifierPub, err := kernelfabric.LoadEd25519PublicKey(*remoteVerifierPubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	issuerKey, err := kernelfabric.LoadEd25519PrivateKey(*issuerKeyPath)
	if err != nil { fatalf("load admission issuer private key: %v", err) }

	now := time.Now().UTC()
	grant, err := kernelfabric.IssueRestartWorkloadAdmissionGrant(
		req,
		remote,
		restart,
		lifecyclePub,
		kernelfabric.WorkloadAdmissionPolicy{
			RemoteVerifierPublicKey: remoteVerifierPub,
			AdmissionIssuerKey:      issuerKey,
			AdmissionIssuerID:       *issuerID,
			MaxAttestationAge:       *maxAge,
			GrantTTL:                *ttl,
			Now:                     func() time.Time { return now },
		},
		now,
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, grant, 0o600); err != nil {
		fatalf("write restart admission grant: %v", err)
	}
	fmt.Printf("fresh restart admission grant: %s\n", *out)
	fmt.Printf("expires at: %s\n", grant.Grant.ExpiresAt.Format(time.RFC3339Nano))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-admission-restart-issue: "+format+"\n", args...)
	os.Exit(1)
}
