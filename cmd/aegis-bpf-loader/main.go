//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	var (
		artifact       = flag.String("artifact", "", "compiled BPF object")
		manifestPath   = flag.String("manifest", "", "signed bootstrap manifest")
		trustKeyPath   = flag.String("trust-key", "", "base64 Ed25519 manifest signer public key")
		attestKeyPath  = flag.String("attestation-key", "", "base64 Ed25519 local attestation private key (0600)")
		cgroupPath     = flag.String("cgroup", "", "protected cgroup v2 path")
		bpffsRoot      = flag.String("bpffs-root", "/sys/fs/bpf/aegis-ege", "Aegis bpffs root")
		bpftoolPath    = flag.String("bpftool", "", "absolute bpftool executable path (default: resolve bpftool from PATH once)")
		receiptPath    = flag.String("receipt", "aegis-bpf-bootstrap.receipt.json", "signed bootstrap receipt output")
		bootIDPath     = flag.String("boot-id", kernelfabric.DefaultBootIDPath, "boot id path")
		lockdownPath   = flag.String("lockdown", kernelfabric.DefaultKernelLockdownPath, "kernel lockdown status path")
	)
	flag.Parse()

	if *artifact == "" || *manifestPath == "" || *trustKeyPath == "" ||
		*attestKeyPath == "" || *cgroupPath == "" {
		fatalf("-artifact, -manifest, -trust-key, -attestation-key and -cgroup are required")
	}

	signedManifest, err := kernelfabric.LoadSignedBootstrapManifest(*manifestPath)
	if err != nil {
		fatalf("load signed manifest: %v", err)
	}
	trustKey, err := kernelfabric.LoadEd25519PublicKey(*trustKeyPath)
	if err != nil {
		fatalf("load trust key: %v", err)
	}
	trustKeyID, err := kernelfabric.BootstrapKeyID(trustKey)
	if err != nil {
		fatalf("derive trust key id: %v", err)
	}
	trust := kernelfabric.BootstrapTrustStore{trustKeyID: trustKey}

	attestationKey, err := kernelfabric.LoadEd25519PrivateKey(*attestKeyPath)
	if err != nil {
		fatalf("load attestation key: %v", err)
	}
	resolvedBPFTool := *bpftoolPath
	if resolvedBPFTool == "" {
		resolvedBPFTool, err = exec.LookPath("bpftool")
		if err != nil {
			fatalf("resolve bpftool: %v", err)
		}
	}
	resolvedBPFTool, err = filepath.Abs(resolvedBPFTool)
	if err != nil {
		fatalf("resolve absolute bpftool path: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader := kernelfabric.BootstrapLoader{
		BPFToolPath: resolvedBPFTool,
		HostProvider: kernelfabric.LinuxBootstrapHostProvider{
			BootIDPath:   *bootIDPath,
			LockdownPath: *lockdownPath,
		},
	}
	result, err := loader.LoadAndAttach(ctx, kernelfabric.BootstrapLoadRequest{
		ArtifactPath:          *artifact,
		CgroupPath:            *cgroupPath,
		BPFFSRoot:             *bpffsRoot,
		SignedManifest:        signedManifest,
		Trust:                 trust,
		AttestationPrivateKey: attestationKey,
	})
	if err != nil {
		fatalf("bootstrap failed: %v", err)
	}

	if err := kernelfabric.WriteSignedBootstrapReceipt(*receiptPath, result.SignedReceipt); err != nil {
		rollbackErr := loader.DetachManifestPrograms(
			context.Background(),
			*cgroupPath,
			*bpffsRoot,
			signedManifest.Manifest,
		)
		if rollbackErr != nil {
			fatalf("write receipt: %v; rollback also failed: %v", err, rollbackErr)
		}
		fatalf("write receipt: %v; attached programs rolled back", err)
	}

	fmt.Printf("verified BPF bootstrap attached successfully\n")
	fmt.Printf("receipt: %s\n", *receiptPath)
	fmt.Printf("manifest signer: %s\n", result.SignedReceipt.Receipt.ManifestSignerKeyID)
	fmt.Printf("local attestor: %s\n", result.SignedReceipt.KeyID)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-bpf-loader: "+format+"\n", args...)
	os.Exit(1)
}
