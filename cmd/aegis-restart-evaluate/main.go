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
	activationPath := flag.String("activation", "", "prior signed workload activation receipt")
	exitPath := flag.String("exit", "", "prior signed workload exit receipt")
	remotePath := flag.String("remote-decision", "", "current signed remote attestation decision")
	remoteVerifierPubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	admissionIssuerPubPath := flag.String("admission-issuer-pub", "", "admission issuer public key")
	hostAttestorPubPath := flag.String("host-attestor-pub", "", "enrolled host attestor public key")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleAuthorityID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	maxRestarts := flag.Uint("max-restarts", 3, "maximum restarts in the configured window")
	window := flag.Duration("restart-window", 10*time.Minute, "restart budget window")
	baseBackoff := flag.Duration("base-backoff", time.Second, "base exponential restart backoff")
	maxBackoff := flag.Duration("max-backoff", time.Minute, "maximum restart backoff")
	reattestAfter := flag.Duration("reattest-after", kernelfabric.DefaultAdmissionAttestationMaxAge, "maximum age before re-attestation is required")
	reattestNonZero := flag.Bool("reattest-on-nonzero", true, "require re-attestation after non-zero exit")
	reattestSignal := flag.Bool("reattest-on-signal", true, "require re-attestation after signal exit")
	allowClean := flag.Bool("allow-clean-restart", false, "allow restart after a clean exit")
	decisionTTL := flag.Duration("decision-ttl", time.Minute, "restart decision validity")
	out := flag.String("out", "workload-restart-decision.json", "signed restart decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*priorGrantPath == "" || *activationPath == "" || *exitPath == "" ||
		*remotePath == "" || *remoteVerifierPubPath == "" ||
		*admissionIssuerPubPath == "" || *hostAttestorPubPath == "" ||
		*lifecycleKeyPath == "" || *lifecycleAuthorityID == "" {
		fatalf("all lifecycle, lineage, trust-key and authority flags are required")
	}

	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil {
		fatalf("read lifecycle state: %v", err)
	}
	if !exists {
		fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID)
	}

	priorGrant, err := cliio.ReadJSON[kernelfabric.SignedWorkloadAdmissionGrant](*priorGrantPath)
	if err != nil { fatalf("read prior grant: %v", err) }
	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	exit, err := cliio.ReadJSON[kernelfabric.SignedWorkloadExitReceipt](*exitPath)
	if err != nil { fatalf("read exit receipt: %v", err) }
	remote, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
	if err != nil { fatalf("read remote decision: %v", err) }

	remoteVerifierPub, err := kernelfabric.LoadEd25519PublicKey(*remoteVerifierPubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	admissionIssuerPub, err := kernelfabric.LoadEd25519PublicKey(*admissionIssuerPubPath)
	if err != nil { fatalf("load admission issuer public key: %v", err) }
	hostAttestorPub, err := kernelfabric.LoadEd25519PublicKey(*hostAttestorPubPath)
	if err != nil { fatalf("load host attestor public key: %v", err) }
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil { fatalf("load lifecycle authority key: %v", err) }

	decision, err := kernelfabric.EvaluateWorkloadRestart(
		state,
		priorGrant,
		activation,
		exit,
		remote,
		kernelfabric.WorkloadRestartPolicy{
			MaxRestartsPerWindow:     uint32(*maxRestarts),
			RestartWindow:            *window,
			BaseBackoff:              *baseBackoff,
			MaxBackoff:               *maxBackoff,
			ReattestAfter:            *reattestAfter,
			ReattestOnNonZero:        *reattestNonZero,
			ReattestOnSignal:         *reattestSignal,
			AllowCleanExitRestart:    *allowClean,
			DecisionTTL:              *decisionTTL,
			LifecycleAuthorityKey:    lifecycleKey,
			LifecycleAuthorityID:     *lifecycleAuthorityID,
			RemoteVerifierPublicKey:  remoteVerifierPub,
			AdmissionIssuerPublicKey: admissionIssuerPub,
			HostAttestorPublicKey:    hostAttestorPub,
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write restart decision: %v", err)
	}
	fmt.Printf("restart decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("not before: %s\n", decision.Decision.NotBefore.Format(time.RFC3339Nano))
	fmt.Printf("decision: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-restart-evaluate: "+format+"\n", args...)
	os.Exit(1)
}
