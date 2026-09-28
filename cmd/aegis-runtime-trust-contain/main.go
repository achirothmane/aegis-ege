//go:build linux

package main

import (
	"context"
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
	decisionPath := flag.String("decision", "", "signed runtime trust REVOKE decision")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	hostKeyPath := flag.String("host-attestor-key", "", "host attestor private key (0600)")
	bpftoolPath := flag.String("bpftool", "", "bpftool path; empty resolves from PATH")
	capsuleMap := flag.String("capsule-map", kernelfabric.DefaultCapsuleMapPath, "pinned capsule map path")
	fenceMap := flag.String("fence-map", kernelfabric.DefaultFenceMapPath, "pinned fence map path")
	out := flag.String("out", "runtime-trust-recovery-observation.json", "signed containment observation output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *decisionPath == "" ||
		*lifecyclePubPath == "" || *hostKeyPath == "" {
		fatalf("lifecycle, activation, decision and trust-key flags are required")
	}
	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil { fatalf("read lifecycle state: %v", err) }
	if !exists { fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID) }

	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	decision, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustDecision](*decisionPath)
	if err != nil { fatalf("read runtime trust decision: %v", err) }
	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle authority public key: %v", err) }
	hostKey, err := kernelfabric.LoadEd25519PrivateKey(*hostKeyPath)
	if err != nil { fatalf("load host attestor key: %v", err) }
	kernelStore, err := kernelfabric.NewBPFToolStore(*bpftoolPath, *capsuleMap, *fenceMap)
	if err != nil { fatalf("open kernel enforcement store: %v", err) }

	observation, fence, err := kernelfabric.ContainRuntimeTrustRevocation(
		context.Background(),
		kernelfabric.Installer{Store: kernelStore},
		state,
		activation,
		decision,
		lifecyclePub,
		hostKey,
		time.Now().UTC(),
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, observation, 0o600); err != nil {
		fatalf("write containment observation: %v", err)
	}
	fmt.Printf("kernel network revocation epoch: %d\n", fence.RevocationEpoch)
	fmt.Printf("recovery observation: %s\n", observation.Observation.State)
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-contain: "+format+"\n", args...)
	os.Exit(1)
}
