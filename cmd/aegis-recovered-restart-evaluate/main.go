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
	lifecycleDir := flag.String("lifecycle-dir", "", "durable workload lifecycle directory")
	deviceID := flag.String("device", "", "device id")
	workloadID := flag.String("workload", "", "workload id")
	priorGrantPath := flag.String("prior-grant", "", "prior signed workload admission grant")
	activationPath := flag.String("activation", "", "prior signed activation receipt")
	reconciliationPath := flag.String("reconciliation", "", "signed reconciliation decision")
	remotePath := flag.String("remote-decision", "", "current signed remote attestation decision")
	remoteVerifierPubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	admissionIssuerPubPath := flag.String("admission-issuer-pub", "", "admission issuer public key")
	hostAttestorPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	maxRestarts := flag.Uint("max-restarts", 3, "maximum restarts in window")
	window := flag.Duration("restart-window", 10*time.Minute, "restart budget window")
	baseBackoff := flag.Duration("base-backoff", time.Second, "base restart backoff")
	maxBackoff := flag.Duration("max-backoff", time.Minute, "maximum restart backoff")
	reattestAfter := flag.Duration("reattest-after", kernelfabric.DefaultAdmissionAttestationMaxAge, "maximum accepted post-recovery attestation age")
	decisionTTL := flag.Duration("decision-ttl", time.Minute, "restart decision lifetime")
	out := flag.String("out", "workload-recovered-restart-decision.json", "signed restart decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*priorGrantPath == "" || *activationPath == "" || *reconciliationPath == "" ||
		*remotePath == "" || *remoteVerifierPubPath == "" ||
		*admissionIssuerPubPath == "" || *hostAttestorPubPath == "" ||
		*lifecycleKeyPath == "" || *lifecycleID == "" {
		fatalf("all lifecycle, lineage, decision, trust-key and authority flags are required")
	}
	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil { fatalf("read lifecycle state: %v", err) }
	if !exists { fatalf("lifecycle state not found") }

	priorGrant, err := cliio.ReadJSON[kernelfabric.SignedWorkloadAdmissionGrant](*priorGrantPath)
	if err != nil { fatalf("read prior grant: %v", err) }
	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	reconciliation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadReconciliationDecision](*reconciliationPath)
	if err != nil { fatalf("read reconciliation decision: %v", err) }
	remote, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
	if err != nil { fatalf("read remote decision: %v", err) }
	remotePub, err := kernelfabric.LoadEd25519PublicKey(*remoteVerifierPubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	admissionPub, err := kernelfabric.LoadEd25519PublicKey(*admissionIssuerPubPath)
	if err != nil { fatalf("load admission issuer public key: %v", err) }
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostAttestorPubPath)
	if err != nil { fatalf("load host attestor public key: %v", err) }
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil { fatalf("load lifecycle authority key: %v", err) }

	decision, err := kernelfabric.EvaluateRecoveredWorkloadRestart(
		state,
		priorGrant,
		activation,
		reconciliation,
		remote,
		kernelfabric.WorkloadRestartPolicy{
			MaxRestartsPerWindow:     uint32(*maxRestarts),
			RestartWindow:            *window,
			BaseBackoff:              *baseBackoff,
			MaxBackoff:               *maxBackoff,
			ReattestAfter:            *reattestAfter,
			DecisionTTL:              *decisionTTL,
			LifecycleAuthorityKey:    lifecycleKey,
			LifecycleAuthorityID:     *lifecycleID,
			RemoteVerifierPublicKey:  remotePub,
			AdmissionIssuerPublicKey: admissionPub,
			HostAttestorPublicKey:    hostPub,
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write recovered restart decision: %v", err)
	}
	fmt.Printf("recovered restart decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("not before: %s\n", decision.Decision.NotBefore.Format(time.RFC3339Nano))
	fmt.Printf("decision: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-recovered-restart-evaluate: "+format+"\n", args...)
	os.Exit(1)
}
