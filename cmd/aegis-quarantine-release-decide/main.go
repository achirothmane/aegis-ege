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
	priorGrantPath := flag.String("prior-grant", "", "prior signed admission grant")
	activationPath := flag.String("activation", "", "signed activation receipt")
	quarantinePath := flag.String("quarantine-decision", "", "signed quarantine reconciliation decision")
	clearancePath := flag.String("clearance-observation", "", "signed clearance observation")
	remotePath := flag.String("remote-decision", "", "fresh signed remote attestation decision")
	approvalPath := flag.String("operator-approval", "", "signed operator approval")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	hostPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	remotePubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	admissionPubPath := flag.String("admission-issuer-pub", "", "admission issuer public key")
	operatorPubPath := flag.String("operator-pub", "", "trusted operator public key")
	ttl := flag.Duration("ttl", kernelfabric.DefaultQuarantineReleaseTTL, "release decision lifetime")
	out := flag.String("out", "quarantine-release-decision.json", "signed release decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*priorGrantPath == "" || *activationPath == "" || *quarantinePath == "" ||
		*clearancePath == "" || *remotePath == "" || *approvalPath == "" ||
		*lifecyclePubPath == "" || *lifecycleKeyPath == "" || *lifecycleID == "" ||
		*hostPubPath == "" || *remotePubPath == "" || *admissionPubPath == "" ||
		*operatorPubPath == "" {
		fatalf("all lifecycle, evidence, trust and authority flags are required")
	}

	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil { fatalf("read lifecycle state: %v", err) }
	if !exists { fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID) }

	priorGrant, err := cliio.ReadJSON[kernelfabric.SignedWorkloadAdmissionGrant](*priorGrantPath)
	if err != nil { fatalf("read prior grant: %v", err) }
	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	quarantine, err := cliio.ReadJSON[kernelfabric.SignedWorkloadReconciliationDecision](*quarantinePath)
	if err != nil { fatalf("read quarantine decision: %v", err) }
	clearance, err := cliio.ReadJSON[kernelfabric.SignedWorkloadRecoveryObservation](*clearancePath)
	if err != nil { fatalf("read clearance observation: %v", err) }
	remote, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
	if err != nil { fatalf("read remote decision: %v", err) }
	approval, err := cliio.ReadJSON[kernelfabric.SignedQuarantineOperatorApproval](*approvalPath)
	if err != nil { fatalf("read operator approval: %v", err) }

	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle public key: %v", err) }
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil { fatalf("load lifecycle private key: %v", err) }
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil { fatalf("load host public key: %v", err) }
	remotePub, err := kernelfabric.LoadEd25519PublicKey(*remotePubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	admissionPub, err := kernelfabric.LoadEd25519PublicKey(*admissionPubPath)
	if err != nil { fatalf("load admission issuer public key: %v", err) }
	operatorPub, err := kernelfabric.LoadEd25519PublicKey(*operatorPubPath)
	if err != nil { fatalf("load operator public key: %v", err) }

	decision, err := kernelfabric.EvaluateQuarantineRelease(
		state, priorGrant, activation, quarantine, clearance, remote, approval,
		kernelfabric.QuarantineReleaseTrust{
			LifecycleAuthorityPublicKey: lifecyclePub,
			HostAttestorPublicKey:       hostPub,
			RemoteVerifierPublicKey:     remotePub,
			AdmissionIssuerPublicKey:    admissionPub,
			OperatorPublicKey:           operatorPub,
		},
		lifecycleKey,
		*lifecycleID,
		*ttl,
		time.Now().UTC(),
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write release decision: %v", err)
	}
	fmt.Printf("quarantine release decision: %s\n", *out)
	fmt.Printf("new lifecycle epoch: %d\n", decision.Decision.NewLifecycleEpoch)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-quarantine-release-decide: "+format+"\n", args...)
	os.Exit(1)
}
