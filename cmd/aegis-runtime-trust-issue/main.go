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
	priorGrantPath := flag.String("prior-grant", "", "signed admission grant for current generation")
	activationPath := flag.String("activation", "", "signed activation receipt for current generation")
	remotePath := flag.String("remote-decision", "", "fresh signed remote attestation decision")
	previousLeasePath := flag.String("previous-lease", "", "current signed runtime trust lease when renewing")
	lifecycleKeyPath := flag.String("lifecycle-key", "", "lifecycle authority private key (0600)")
	lifecycleID := flag.String("lifecycle-authority-id", "", "lifecycle authority id")
	remotePubPath := flag.String("remote-verifier-pub", "", "remote verifier public key")
	admissionPubPath := flag.String("admission-issuer-pub", "", "admission issuer public key")
	hostPubPath := flag.String("host-attestor-pub", "", "host attestor public key")
	policyDigest := flag.String("policy-digest", "", "sha256 digest of current runtime trust policy")
	maxAge := flag.Duration("max-attestation-age", kernelfabric.DefaultRuntimeTrustMaxAge, "maximum accepted remote attestation age")
	ttl := flag.Duration("ttl", kernelfabric.DefaultRuntimeTrustLeaseTTL, "runtime trust lease lifetime")
	out := flag.String("out", "runtime-trust-lease.json", "signed runtime trust lease output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*priorGrantPath == "" || *activationPath == "" || *remotePath == "" ||
		*lifecycleKeyPath == "" || *lifecycleID == "" ||
		*remotePubPath == "" || *admissionPubPath == "" || *hostPubPath == "" ||
		*policyDigest == "" {
		fatalf("all lifecycle, evidence, trust-key and policy flags are required")
	}

	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}
	state, exists, err := store.Read(*deviceID, *workloadID)
	if err != nil { fatalf("read lifecycle state: %v", err) }
	if !exists { fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID) }

	priorGrant, err := cliio.ReadJSON[kernelfabric.SignedWorkloadAdmissionGrant](*priorGrantPath)
	if err != nil { fatalf("read prior grant: %v", err) }
	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil { fatalf("read activation receipt: %v", err) }
	remote, err := cliio.ReadJSON[kernelfabric.SignedRemoteAttestationDecision](*remotePath)
	if err != nil { fatalf("read remote decision: %v", err) }

	var previous *kernelfabric.SignedRuntimeTrustLease
	if *previousLeasePath != "" {
		value, err := cliio.ReadJSON[kernelfabric.SignedRuntimeTrustLease](*previousLeasePath)
		if err != nil { fatalf("read previous runtime trust lease: %v", err) }
		previous = &value
	}

	lifecycleKey, err := kernelfabric.LoadEd25519PrivateKey(*lifecycleKeyPath)
	if err != nil { fatalf("load lifecycle authority key: %v", err) }
	remotePub, err := kernelfabric.LoadEd25519PublicKey(*remotePubPath)
	if err != nil { fatalf("load remote verifier public key: %v", err) }
	admissionPub, err := kernelfabric.LoadEd25519PublicKey(*admissionPubPath)
	if err != nil { fatalf("load admission issuer public key: %v", err) }
	hostPub, err := kernelfabric.LoadEd25519PublicKey(*hostPubPath)
	if err != nil { fatalf("load host attestor public key: %v", err) }

	now := time.Now().UTC()
	lease, err := kernelfabric.IssueRuntimeTrustLease(
		state,
		priorGrant,
		activation,
		remote,
		previous,
		kernelfabric.RuntimeTrustPolicy{
			LifecycleAuthorityKey:    lifecycleKey,
			LifecycleAuthorityID:     *lifecycleID,
			RemoteVerifierPublicKey:  remotePub,
			AdmissionIssuerPublicKey: admissionPub,
			HostAttestorPublicKey:    hostPub,
			PolicyDigest:             *policyDigest,
			MaxAttestationAge:        *maxAge,
			LeaseTTL:                 *ttl,
			Now:                      func() time.Time { return now },
		},
	)
	if err != nil { fatalf("%v", err) }
	if err := cliio.WriteJSON(*out, lease, 0o600); err != nil {
		fatalf("write runtime trust lease: %v", err)
	}
	fmt.Printf("runtime trust lease epoch: %d\n", lease.Lease.LeaseEpoch)
	fmt.Printf("expires at: %s\n", lease.Lease.ExpiresAt.Format(time.RFC3339Nano))
	fmt.Printf("artifact: %s\n", *out)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-issue: "+format+"\n", args...)
	os.Exit(1)
}
