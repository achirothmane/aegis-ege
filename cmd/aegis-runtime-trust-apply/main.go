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
	leasePath := flag.String("lease", "", "signed runtime trust lease")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	out := flag.String("out", "workload-lifecycle-after-runtime-lease.json", "updated lifecycle state output")
	flag.Parse()

	if *lifecycleDir == "" || *leasePath == "" || *lifecyclePubPath == "" {
		fatalf("-lifecycle-dir, -lease and -lifecycle-authority-pub are required")
	}
	lease, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustLease](*leasePath)
	if err != nil { fatalf("read runtime trust lease: %v", err) }
	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle authority public key: %v", err) }

	state, err := kernelfabric.ApplyRuntimeTrustLease(
		kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir},
		lease,
		lifecyclePub,
		time.Now().UTC(),
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, state, 0o600); err != nil {
		fatalf("write updated lifecycle state: %v", err)
	}
	fmt.Printf("runtime trust epoch: %d\n", state.RuntimeTrustEpoch)
	fmt.Printf("runtime trust expires at: %s\n", state.RuntimeTrustExpiresAt.Format(time.RFC3339Nano))
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-apply: "+format+"\n", args...)
	os.Exit(1)
}
