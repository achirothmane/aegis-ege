//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	deviceID := flag.String("device", "", "enrolled device id")
	hostAttestorKeyPath := flag.String("host-attestor-key", "", "enrolled host attestor private key (0600)")
	receiptPath := flag.String("receipt", "workload-activation-receipt.json", "signed activation receipt output")
	flag.Parse()

	if *grantPath == "" || *issuerPublicKeyPath == "" || *specPath == "" ||
		*consumptionDir == "" || *deviceID == "" || *hostAttestorKeyPath == "" {
		fatalf("-grant, -issuer-pub, -spec, -consumption-dir, -device and -host-attestor-key are required")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started, err := kernelfabric.StartAttestedWorkload(
		ctx,
		kernelfabric.AttestedWorkloadLaunchRequest{
			SignedGrant:     grant,
			IssuerPublicKey: issuerKey,
			LaunchSpec:      spec,
			ConsumptionDir:  *consumptionDir,
			DeviceID:        *deviceID,
			HostAttestorKey: hostAttestorKey,
			Now:             time.Now().UTC(),
		},
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*receiptPath, started.SignedReceipt, 0o600); err != nil {
		_ = started.Command.Process.Kill()
		_, _ = started.Command.Process.Wait()
		fatalf("write activation receipt; workload killed: %v", err)
	}
	fmt.Printf("attested workload started pid=%d\n", started.Command.Process.Pid)
	fmt.Printf("activation receipt: %s\n", *receiptPath)

	if err := started.Command.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fatalf("wait for workload: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-attested-run: "+format+"\n", args...)
	os.Exit(1)
}
