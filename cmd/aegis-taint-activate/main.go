//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	var (
		planPath      = flag.String("plan", "", "taint activation plan JSON")
		receiptPath   = flag.String("bootstrap-receipt", "", "signed taint bootstrap receipt")
		attestKeyPath = flag.String("attestation-public-key", "", "base64 Ed25519 bootstrap attestation public key")
		bpffsRoot     = flag.String("bpffs-root", kernelfabric.DefaultTaintBPFFSRoot, "taint bpffs root")
	)
	flag.Parse()

	if *planPath == "" || *receiptPath == "" || *attestKeyPath == "" {
		fatalf("-plan, -bootstrap-receipt and -attestation-public-key are required")
	}

	plan, err := kernelfabric.LoadTaintActivationPlan(*planPath)
	if err != nil {
		fatalf("load activation plan: %v", err)
	}
	signedReceipt, err := kernelfabric.LoadSignedTaintBootstrapReceipt(*receiptPath)
	if err != nil {
		fatalf("load bootstrap receipt: %v", err)
	}
	publicKey, err := kernelfabric.LoadEd25519PublicKey(*attestKeyPath)
	if err != nil {
		fatalf("load bootstrap attestation public key: %v", err)
	}

	result, err := kernelfabric.ActivateTaintCgroup(kernelfabric.TaintActivationRequest{
		BPFFSRoot:                     *bpffsRoot,
		Plan:                          plan,
		SignedBootstrapReceipt:        signedReceipt,
		BootstrapAttestationPublicKey: publicKey,
	})
	if err != nil {
		fatalf("activate taint enforcement: %v", err)
	}

	fmt.Printf("taint enforcement activated\n")
	fmt.Printf("cgroup id: %d\n", result.CgroupID)
	fmt.Printf("activation plan digest: %s\n", result.PlanDigest)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-taint-activate: "+format+"\n", args...)
	os.Exit(1)
}
