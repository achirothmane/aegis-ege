package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	var (
		artifact   = flag.String("artifact", "", "compiled BPF object to authorize")
		privateKey = flag.String("private-key", "", "base64 Ed25519 private key file (0600)")
		output     = flag.String("out", "aegis-bpf-bootstrap.signed.json", "signed manifest output")
		validFor   = flag.Duration("valid-for", 24*time.Hour, "manifest validity duration")
		skew       = flag.Duration("not-before-skew", 5*time.Minute, "allowable clock skew before signing time")
	)
	flag.Parse()

	if *artifact == "" || *privateKey == "" {
		fatalf("-artifact and -private-key are required")
	}
	if *validFor <= 0 || *skew < 0 {
		fatalf("validity duration must be positive and skew non-negative")
	}

	key, err := kernelfabric.LoadEd25519PrivateKey(*privateKey)
	if err != nil {
		fatalf("load signing key: %v", err)
	}
	now := time.Now().UTC()
	manifest, err := kernelfabric.BuildNetworkBootstrapManifest(
		*artifact,
		now.Add(-*skew),
		now.Add(*validFor),
	)
	if err != nil {
		fatalf("build bootstrap manifest: %v", err)
	}
	signed, err := kernelfabric.SignBootstrapManifest(manifest, key)
	if err != nil {
		fatalf("sign bootstrap manifest: %v", err)
	}
	if err := kernelfabric.WriteSignedBootstrapManifest(*output, signed); err != nil {
		fatalf("write signed manifest: %v", err)
	}
	fmt.Printf("signed bootstrap manifest written to %s\n", *output)
	fmt.Printf("signer key id: %s\n", signed.KeyID)
	fmt.Printf("artifact digest: %s\n", signed.Manifest.ArtifactSHA256)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-bpf-sign: "+format+"\n", args...)
	os.Exit(1)
}
