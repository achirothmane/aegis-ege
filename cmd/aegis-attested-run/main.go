//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	grantPath := flag.String("grant", "", "signed workload admission grant")
	issuerPublicKeyPath := flag.String("issuer-pub", "", "admission issuer Ed25519 public key")
	specPath := flag.String("spec", "", "workload launch spec JSON")
	consumptionDir := flag.String("consumption-dir", "", "durable one-shot grant consumption directory")
	lifecycleDir := flag.String("lifecycle-dir", "", "durable workload lifecycle ledger directory")
	restartDecisionPath := flag.String("restart-decision", "", "signed restart decision; required after the first generation")
	lifecycleAuthorityPubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key for restart verification")
	deviceID := flag.String("device", "", "enrolled device id")
	hostAttestorKeyPath := flag.String("host-attestor-key", "", "enrolled host attestor private key (0600)")
	activationReceiptPath := flag.String("receipt", "workload-activation-receipt.json", "signed activation receipt output")
	exitReceiptPath := flag.String("exit-receipt", "workload-exit-receipt.json", "signed exit receipt output")
	flag.Parse()

	if *grantPath == "" || *issuerPublicKeyPath == "" || *specPath == "" ||
		*consumptionDir == "" || *lifecycleDir == "" ||
		*deviceID == "" || *hostAttestorKeyPath == "" {
		fatalf("-grant, -issuer-pub, -spec, -consumption-dir, -lifecycle-dir, -device and -host-attestor-key are required")
	}
	grant, err := cliio.ReadJSON[kernelfabric.SignedWorkloadAdmissionGrant](*grantPath)
	if err != nil {
		fatalf("read admission grant: %v", err)
	}
	spec, err := cliio.ReadJSON[kernelfabric.WorkloadLaunchSpec](*specPath)
	if err != nil {
		fatalf("read workload spec: %v", err)
	}
	issuerKey, err := kernelfabric.LoadEd25519PublicKey(*issuerPublicKeyPath)
	if err != nil {
		fatalf("load admission issuer public key: %v", err)
	}
	hostAttestorKey, err := kernelfabric.LoadEd25519PrivateKey(*hostAttestorKeyPath)
	if err != nil {
		fatalf("load host attestor private key: %v", err)
	}

	var restartDecision *kernelfabric.SignedWorkloadRestartDecision
	var lifecycleAuthorityPub []byte
	if *restartDecisionPath != "" {
		decision, err := cliio.ReadJSON[kernelfabric.SignedWorkloadRestartDecision](*restartDecisionPath)
		if err != nil {
			fatalf("read restart decision: %v", err)
		}
		if *lifecycleAuthorityPubPath == "" {
			fatalf("-lifecycle-authority-pub is required with -restart-decision")
		}
		pub, err := kernelfabric.LoadEd25519PublicKey(*lifecycleAuthorityPubPath)
		if err != nil {
			fatalf("load lifecycle authority public key: %v", err)
		}
		restartDecision = &decision
		lifecycleAuthorityPub = pub
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	started, state, err := kernelfabric.StartGovernedWorkload(
		ctx,
		kernelfabric.GovernedWorkloadLaunchRequest{
			LaunchRequest: kernelfabric.AttestedWorkloadLaunchRequest{
				SignedGrant:     grant,
				IssuerPublicKey: issuerKey,
				LaunchSpec:      spec,
				ConsumptionDir:  *consumptionDir,
				DeviceID:        *deviceID,
				HostAttestorKey: hostAttestorKey,
				Now:             time.Now().UTC(),
			},
			LifecycleStore:              store,
			RestartDecision:             restartDecision,
			LifecycleAuthorityPublicKey: lifecycleAuthorityPub,
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*activationReceiptPath, started.SignedReceipt, 0o600); err != nil {
		_ = started.Command.Process.Kill()
		if exitReceipt, _, waitErr := kernelfabric.WaitGovernedWorkload(started, store, hostAttestorKey); waitErr == nil {
			_ = cliio.WriteJSON(*exitReceiptPath, exitReceipt, 0o600)
		}
		fatalf("write activation receipt; workload killed: %v", err)
	}
	fmt.Printf("attested workload started pid=%d generation=%d\n", started.Command.Process.Pid, state.Generation)
	fmt.Printf("activation receipt: %s\n", *activationReceiptPath)

	exitReceipt, exitCode, err := kernelfabric.WaitGovernedWorkload(
		started,
		store,
		hostAttestorKey,
	)
	if err != nil {
		fatalf("wait/govern workload exit: %v", err)
	}
	if err := cliio.WriteJSON(*exitReceiptPath, exitReceipt, 0o600); err != nil {
		fatalf("write signed exit receipt: %v", err)
	}
	fmt.Printf("workload exit: class=%s code=%d\n", exitReceipt.Receipt.ExitClass, exitCode)
	fmt.Printf("exit receipt: %s\n", *exitReceiptPath)

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-attested-run: "+format+"\n", args...)
	os.Exit(1)
}
