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
	deviceID := flag.String("device", "", "device id")
	workloadID := flag.String("workload", "", "workload id")
	activationPath := flag.String("activation", "", "signed activation receipt")
	leasePath := flag.String("lease", "", "current signed runtime trust lease")
	remotePath := flag.String("remote-decision", "", "optional newer signed remote decision")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	remotePubPath := flag.String("remote-verifier-pub", "", "remote verifier public key; required with -remote-decision")
	hostPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	policyDigest := flag.String("policy-digest", "", "sha256 digest of current runtime trust policy")
	out := flag.String("out", "runtime-trust-decision.json", "signed runtime trust decision output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *leasePath == "" ||
		*lifecycleKeyPath == "" || *lifecycleID == "" ||
		*hostPubPath == "" || *policyDigest == "" {
		fatalf("lifecycle, activation, lease, lifecycle authority, host trust and policy flags are required")
	}
	if *remotePath != "" && *remotePubPath == "" {
		fatalf("-remote-verifier-pub is required with -remote-decision")
	}

	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil { fatalf("read lifecycle state: %v", err) }
	if !exists { fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID) }

	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	lease, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustLease](*leasePath)
	if err != nil { fatalf("read runtime trust lease: %v", err) }
	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil { fatalf("load lifecycle authority key: %v", err) }
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil { fatalf("load host attestor public key: %v", err) }

	var remote *kernelfabric.SignedRemoteAttestationDecision
	var remotePub []byte
	if *remotePath != "" {
		value, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
		if err != nil { fatalf("read remote decision: %v", err) }
		pub, err := kernelfabric.LoadEd25519PublicKey(*remotePubPath)
		if err != nil { fatalf("load remote verifier public key: %v", err) }
		remote = &value
		remotePub = pub
	}

	decision, err := kernelfabric.EvaluateRuntimeTrust(
		state,
		activation,
		lease,
		remote,
		kernelfabric.RuntimeTrustEvaluationPolicy{
			LifecycleAuthorityKey:   lifecycleKey,
			LifecycleAuthorityID:    *lifecycleID,
			RemoteVerifierPublicKey: remotePub,
			HostAttestorPublicKey:   hostPub,
			PolicyDigest:            *policyDigest,
			Now:                     func() time.Time { return time.Now().UTC() },
		},
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, decision, 0o600); err != nil {
		fatalf("write runtime trust decision: %v", err)
	}
	fmt.Printf("runtime trust decision: %s\n", decision.Decision.Outcome)
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-evaluate: "+format+"\n", args...)
	os.Exit(1)
}
