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
	activationPath := flag.String("activation", "", "signed activation receipt for current generation")
	hostAttestorKeyPath := flag.String("host-attestor-key", "", "enrolled host attestor private key (0600)")
	out := flag.String("out", "workload-recovery-observation.json", "signed recovery observation output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *hostAttestorKeyPath == "" {
		fatalf("-lifecycle-dir, -device, -workload, -activation and -host-attestor-key are required")
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
	hostKey, err := kernelfabric.LoadEd25519PrivateKey(*hostAttestorKeyPath)
	if err != nil {
		fatalf("load host attestor key: %v", err)
	}
	hostPub, ok := hostKey.Public().(ed25519.PublicKey)
	if !ok {
		fatalf("host attestor key is not Ed25519")
	}

	observation, err := kernelfabric.ObserveOrphanedWorkload(
		state,
		activation,
		hostPub,
		hostKey,
		time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, observation, 0o600); err != nil {
		fatalf("write recovery observation: %v", err)
	}
	fmt.Printf("recovery observation: %s\n", observation.Observation.State)
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-reconcile-observe: "+format+"\n", args...)
	os.Exit(1)
}
