//go:build linux

package main

import (
	"crypto/ed25519"
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
	activationPath := flag.String("activation", "", "signed activation receipt")
	hostPubPath := flag.String("host-attestor-pub", "", "enrolled host attestor public key")
	hostKeyPath := flag.String("host-attestor-key", "", "host attestor private key (0600)")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	observationOut := flag.String("observation-out", "workload-recovery-observation.json", "signed recovery observation output")
	decisionOut := flag.String("decision-out", "workload-reconciliation-decision.json", "signed reconciliation decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *hostPubPath == "" || *hostKeyPath == "" ||
		*lifecycleKeyPath == "" || *lifecycleID == "" {
		fatalf("all lifecycle, activation, attestor and authority flags are required")
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
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil {
		fatalf("load host attestor public key: %v", err)
	}
	hostKey, err := kernelfabric.LoadEd25519PrivateKey(*hostKeyPath)
	if err != nil {
		fatalf("load host attestor private key: %v", err)
	}
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil {
		fatalf("load lifecycle authority key: %v", err)
	}
	now := time.Now().UTC()
	observation, err := kernelfabric.ObserveOrphanedWorkload(
		state,
		activation,
		hostPub,
		hostKey,
		now,
	)
	if err != nil {
		fatalf("observe orphaned workload: %v", err)
	}
	if err := cliio.WriteJSON(*observationOut, observation, 0o600); err != nil {
		fatalf("write recovery observation: %v", err)
	}

	decision, err := kernelfabric.EvaluateWorkloadReconciliation(
		state,
		activation,
		observation,
		hostPub,
		lifecycleKey,
		*lifecycleID,
		time.Now().UTC(),
	)
	if err != nil {
		fatalf("evaluate reconciliation: %v", err)
	}
	if err := cliio.WriteJSON(*decisionOut, decision, 0o600); err != nil {
		fatalf("write reconciliation decision: %v", err)
	}
	updated, err := kernelfabric.ApplyWorkloadReconciliation(
		store,
		decision,
		lifecycleKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		fatalf("apply reconciliation: %v", err)
	}
	fmt.Printf("recovery observation: %s\n", observation.Observation.State)
	fmt.Printf("reconciliation decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("lifecycle state: %s\n", updated.State)
	fmt.Printf("observation artifact: %s\n", *observationOut)
	fmt.Printf("decision artifact: %s\n", *decisionOut)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-lifecycle-reconcile: "+format+"\n", args...)
	os.Exit(1)
}
