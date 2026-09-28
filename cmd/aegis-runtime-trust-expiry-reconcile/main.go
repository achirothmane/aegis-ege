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
	activationPath := flag.String("activation", "", "signed Activation Receipt v2")
	leasePath := flag.String("lease", "", "signed runtime trust lease that expired")
	expiryPath := flag.String("expiry-evidence", "", "host-signed automatic expiry evidence")
	hostPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	out := flag.String("out", "runtime-trust-expiry-reconciliation.json", "standard signed reconciliation decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *leasePath == "" || *expiryPath == "" ||
		*hostPubPath == "" || *lifecycleKeyPath == "" || *lifecycleID == "" {
		fatalf("all lifecycle, expiry evidence and authority flags are required")
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
	lease, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustLease](*leasePath)
	if err != nil {
		fatalf("read runtime trust lease: %v", err)
	}
	expiry, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustExpiryEvidence](*expiryPath)
	if err != nil {
		fatalf("read runtime trust expiry evidence: %v", err)
	}
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil {
		fatalf("load host attestor public key: %v", err)
	}
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil {
		fatalf("load lifecycle authority key: %v", err)
	}

	decision, err := kernelfabric.EvaluateRuntimeTrustExpiryReconciliation(
		state,
		activation,
		lease,
		expiry,
		hostPub,
		lifecycleKey,
		*lifecycleID,
		time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write expiry reconciliation decision: %v", err)
	}
	fmt.Printf("reconciliation decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("artifact: %s\n", *out)
	fmt.Println("apply with aegis-reconcile-apply")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-expiry-reconcile: "+format+"\n", args...)
	os.Exit(1)
}
