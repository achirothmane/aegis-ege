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
	quarantinePath := flag.String("quarantine-decision", "", "signed reconciliation decision that created QUARANTINED")
	clearancePath := flag.String("clearance-observation", "", "signed post-remediation recovery observation")
	remotePath := flag.String("remote-decision", "", "fresh signed remote attestation decision")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	hostPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	remotePubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	admissionPubPath := flag.String("admission-issuer-pub", "", "admission issuer public key")
	operatorKeyPath := flag.String("operator-key", "", "operator Ed25519 private key (0600)")
	operatorID := flag.String("operator-id", "", "operator identity")
	caseRef := flag.String("case", "", "incident/change case reference")
	reason := flag.String("reason", "", "human release rationale")
	ttl := flag.Duration("ttl", kernelfabric.DefaultQuarantineApprovalTTL, "operator approval lifetime")
	out := flag.String("out", "quarantine-operator-approval.json", "signed operator approval output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*priorGrantPath == "" || *activationPath == "" || *quarantinePath == "" ||
		*clearancePath == "" || *remotePath == "" || *lifecyclePubPath == "" ||
		*hostPubPath == "" || *remotePubPath == "" || *admissionPubPath == "" ||
		*operatorKeyPath == "" || *operatorID == "" || *caseRef == "" || *reason == "" {
		fatalf("all lifecycle, evidence, trust and operator flags are required")
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

	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle public key: %v", err) }
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil { fatalf("load host attestor public key: %v", err) }
	remotePub, err := kernelfabric.LoadEd25519PublicKey(*remotePubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	admissionPub, err := kernelfabric.LoadEd25519PublicKey(*admissionPubPath)
	if err != nil { fatalf("load admission issuer public key: %v", err) }
	operatorKey, err := kernelfabric.LoadEd25519PrivateKey(*operatorKeyPath)
	if err != nil { fatalf("load operator key: %v", err) }

	approval, err := kernelfabric.IssueQuarantineOperatorApproval(
		state, priorGrant, activation, quarantine, clearance, remote,
		kernelfabric.QuarantineReleaseTrust{
			LifecycleAuthorityPublicKey: lifecyclePub,
			HostAttestorPublicKey:       hostPub,
			RemoteVerifierPublicKey:     remotePub,
			AdmissionIssuerPublicKey:    admissionPub,
		},
		operatorKey,
		*operatorID,
		*caseRef,
		*reason,
		*ttl,
		time.Now().UTC(),
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, approval, 0o600); err != nil {
		fatalf("write operator approval: %v", err)
	}
	fmt.Printf("operator approval: %s\n", *out)
	fmt.Printf("requested lifecycle epoch: %d\n", approval.Approval.RequestedLifecycleEpoch)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-quarantine-approve: "+format+"\n", args...)
	os.Exit(1)
}
