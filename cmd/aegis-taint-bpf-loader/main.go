//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	var (
		artifact      = flag.String("artifact", "", "compiled taint BPF object")
		manifestPath  = flag.String("manifest", "", "signed taint bootstrap manifest")
		trustKeyPath  = flag.String("trust-key", "", "base64 Ed25519 manifest signer public key")
		attestKeyPath = flag.String("attestation-key", "", "base64 Ed25519 local attestation private key (0600)")
		cgroupPath    = flag.String("cgroup", "", "target cgroup v2 path")
		bpffsRoot     = flag.String("bpffs-root", kernelfabric.DefaultTaintBPFFSRoot, "taint bpffs root")
		receiptPath   = flag.String("receipt", "aegis-taint-bpf-bootstrap.receipt.json", "signed taint bootstrap receipt")
	)
	flag.Parse()

	if *artifact == "" || *manifestPath == "" || *trustKeyPath == "" ||
		*attestKeyPath == "" || *cgroupPath == "" {
		fatalf("-artifact, -manifest, -trust-key, -attestation-key and -cgroup are required")
	}

	signedManifest, err := kernelfabric.LoadSignedBootstrapManifest(*manifestPath)
	if err != nil {
		fatalf("load signed taint manifest: %v", err)
	}
	trustKey, err := kernelfabric.LoadEd25519PublicKey(*trustKeyPath)
	if err != nil {
		fatalf("load taint manifest trust key: %v", err)
	}
	trustKeyID, err := kernelfabric.BootstrapKeyID(trustKey)
	if err != nil {
		fatalf("derive taint trust key id: %v", err)
	}
	trust := kernelfabric.BootstrapTrustStore{trustKeyID: trustKey}

	attestationKey, err := kernelfabric.LoadEd25519PrivateKey(*attestKeyPath)
	if err != nil {
		fatalf("load taint attestation key: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader := kernelfabric.TaintBootstrapLoader{}
	result, err := loader.LoadAndAttach(ctx, kernelfabric.TaintBootstrapLoadRequest{
		ArtifactPath:          *artifact,
		CgroupPath:            *cgroupPath,
		BPFFSRoot:             *bpffsRoot,
		SignedManifest:        signedManifest,
		Trust:                 trust,
		AttestationPrivateKey: attestationKey,
	})
	if err != nil {
		fatalf("taint bootstrap failed: %v", err)
	}
	if err := kernelfabric.WriteSignedTaintBootstrapReceipt(*receiptPath, result.SignedReceipt); err != nil {
		fatalf("write taint bootstrap receipt: %v", err)
	}

	fmt.Printf("verified taint BPF programs loaded, attached and pinned\n")
	fmt.Printf("activation is still disabled until aegis-taint-activate succeeds\n")
	fmt.Printf("receipt: %s\n", *receiptPath)
	fmt.Printf("manifest signer: %s\n", result.SignedReceipt.Receipt.ManifestSignerKeyID)
	fmt.Printf("local attestor: %s\n", result.SignedReceipt.KeyID)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-taint-bpf-loader: "+format+"\n", args...)
	os.Exit(1)
}
