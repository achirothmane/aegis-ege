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
	activationPath := flag.String("activation", "", "signed activation receipt for current generation")
	observationPath := flag.String("observation", "", "signed recovery observation")
	hostAttestorPubPath := flag.String("host-attestor-pub", "", "enrolled host attestor public key")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleAuthorityID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	out := flag.String("out", "workload-reconciliation-decision.json", "signed reconciliation decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *observationPath == "" ||
		*hostAttestorPubPath == "" || *lifecycleKeyPath == "" ||
		*lifecycleAuthorityID == "" {
		fatalf("all lifecycle, activation, observation and authority flags are required")
	}
	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil {
		fatalf("read lifecycle state: %v", err)
	}
	if !exists {
		fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID)
	}
	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil {
		fatalf("read activation receipt: %v", err)
	}
	observation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadRecoveryObservation](*observationPath)
	if err != nil {
		fatalf("read recovery observation: %v", err)
	}
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostAttestorPubPath)
	if err != nil {
		fatalf("load host attestor public key: %v", err)
	}
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil {
		fatalf("load lifecycle authority key: %v", err)
	}

	decision, err := kernelfabric.EvaluateWorkloadReconciliation(
		state,
		activation,
		observation,
		hostPub,
		lifecycleKey,
		*lifecycleAuthorityID,
		time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write reconciliation decision: %v", err)
	}
	fmt.Printf("reconciliation decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-reconcile-decide: "+format+"\n", args...)
	os.Exit(1)
}
