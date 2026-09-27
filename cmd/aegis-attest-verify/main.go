package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	identityPath := flag.String("identity", "", "enrolled TPM identity")
	challengePath := flag.String("challenge", "", "remote attestation challenge")
	evidencePath := flag.String("evidence", "", "remote attestation evidence")
	verifierKeyPath := flag.String("verifier-key", "", "Ed25519 verifier private key (0600)")
	verifierID := flag.String("verifier-id", "", "verifier authority identifier")
	lockdown := flag.String("require-lockdown", "integrity,confidentiality", "comma-separated accepted kernel lockdown modes; empty disables check")
	requireEventLog := flag.Bool("require-event-log", true, "require TCG platform event-log replay")
	requireIMA := flag.Bool("require-ima", true, "require IMA PCR10 replay")
	requireBPFIMA := flag.Bool("require-bpf-ima", true, "require BPF artifact digest in verified IMA log")
	out := flag.String("out", "remote-attestation-decision.json", "signed decision output")
	flag.Parse()
	if *identityPath == "" || *challengePath == "" || *evidencePath == "" ||
		*verifierKeyPath == "" || *verifierID == "" {
		fatalf("-identity, -challenge, -evidence, -verifier-key and -verifier-id are required")
	}
	identity, err := cliio.ReadJSON[kernelfabric.EnrolledTPMIdentity](*identityPath)
	if err != nil { fatalf("%v", err) }
	challenge, err := cliio.ReadJSON[kernelfabric.RemoteAttestationChallenge](*challengePath)
	if err != nil { fatalf("%v", err) }
	evidence, err := cliio.ReadJSON[kernelfabric.RemoteAttestationEvidence](*evidencePath)
	if err != nil { fatalf("%v", err) }
	verifierKey, err := kernelfabric.LoadEd25519PrivateKey(*verifierKeyPath)
	if err != nil { fatalf("load verifier key: %v", err) }

	modes := map[string]struct{}{}
	for _, mode := range strings.Split(*lockdown, ",") {
		mode = strings.TrimSpace(mode)
		if mode != "" { modes[mode] = struct{}{} }
	}
	decision, err := kernelfabric.VerifyRemoteAttestation(
		challenge, identity, evidence,
		kernelfabric.RemoteAttestationPolicy{
			RequiredLockdownModes:               modes,
			RequirePlatformEventLog:             *requireEventLog,
			RequireIMAReplay:                    *requireIMA,
			RequireBootstrapArtifactMeasurement: *requireBPFIMA,
			VerifierKey:                         verifierKey,
			VerifierID:                          *verifierID,
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write decision: %v", err)
	}
	fmt.Printf("remote attestation decision: %s (%s)\n", decision.Decision.Decision, *out)
	if decision.Decision.Decision != "ALLOW" {
		os.Exit(2)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-attest-verify: "+format+"\n", args...)
	os.Exit(1)
}
