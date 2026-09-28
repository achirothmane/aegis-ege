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
	decisionPath := flag.String("decision", "", "signed quarantine release decision")
	lifecyclePubPath := flag.String("lifecycle-authority-pub", "", "lifecycle authority public key")
	out := flag.String("out", "workload-lifecycle-after-release.json", "released lifecycle state output")
	flag.Parse()

	if *lifecycleDir == "" || *decisionPath == "" || *lifecyclePubPath == "" {
		fatalf("-lifecycle-dir, -decision and -lifecycle-authority-pub are required")
	}
	decision, err := cliio.ReadJSON[kernelfabric.SignedQuarantineReleaseDecision](*decisionPath)
	if err != nil { fatalf("read release decision: %v", err) }
	lifecyclePub, err := kernelfabric.LoadEd25519PublicKey(*lifecyclePubPath)
	if err != nil { fatalf("load lifecycle authority public key: %v", err) }

	state, err := kernelfabric.ApplyQuarantineRelease(
		kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir},
		decision,
		lifecyclePub,
		time.Now().UTC(),
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, state, 0o600); err != nil {
		fatalf("write released lifecycle state: %v", err)
	}
	fmt.Printf("lifecycle state: %s\n", state.State)
	fmt.Printf("lifecycle epoch: %d\n", state.LifecycleEpoch)
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-quarantine-release-apply: "+format+"\n", args...)
	os.Exit(1)
}
