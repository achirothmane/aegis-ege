//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/integrationfixture"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type independentQuorumFixture struct {
	bundle       liveQuorumBundleIntegration
	binding      journal.GenesisQuorumBinding
	policy       journal.QuorumPolicyState
	quorum       *journal.QuorumHeadStore
	history      *journal.GenesisBoundHistoryStore
	remoteStores map[string]*journal.RemoteHeadStore
	members      map[string]liveQuorumMemberIntegration
}

func TestKindLiveQuorumIndependentControlPlanes(t *testing.T) {
	phase := strings.TrimSpace(os.Getenv("LIVE_QUORUM_FAILURE_DOMAIN_PHASE"))
	if phase == "" {
		t.Skip("LIVE_QUORUM_FAILURE_DOMAIN_PHASE is required")
	}
	fixture := loadIndependentQuorumFixture(t)

	switch phase {
	case "baseline":
		proveIndependentQuorumBaseline(t, fixture)
	case "one-control-plane-down":
		proveIndependentQuorumOneControlPlaneDown(t, fixture)
	case "restored-stale-minority":
		proveIndependentQuorumRestoredStaleMinority(t, fixture)
	case "two-control-planes-down":
		proveIndependentQuorumTwoControlPlanesDown(t, fixture)
	default:
		t.Fatalf("unsupported failure-domain phase %q", phase)
	}
}

func loadIndependentQuorumFixture(t *testing.T) independentQuorumFixture {
	t.Helper()
	bundlePath := strings.TrimSpace(os.Getenv("LIVE_QUORUM_CLIENT_BUNDLE"))
	if bundlePath == "" {
		t.Fatal("LIVE_QUORUM_CLIENT_BUNDLE is required")
	}
	payload, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle liveQuorumBundleIntegration
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Version != liveQuorumBundleVersionIntegration {
		t.Fatalf("live quorum bundle version=%q", bundle.Version)
	}
	if len(bundle.Members) != 3 {
		t.Fatalf("live quorum member count=%d want 3", len(bundle.Members))
	}

	envelope, err := base64.StdEncoding.DecodeString(bundle.CapabilityEnvelopeBase64)
	if err != nil {
		t.Fatal(err)
	}
	genesisFixture, err := integrationfixture.NewProductionGenesisFixture(
		t.TempDir(),
		envelope,
		bundle.GenesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, result, pin, err := genesisbootstrap.BootstrapProductionWithSubjectPin(
		t.Context(),
		genesisFixture.ManifestPath,
		genesisFixture.BundlePath,
		bundle.GenesisEpoch,
		3,
		genesis.ConformanceC3,
		genesisFixture.Subject,
		genesisFixture.Now,
	)
	if err != nil {
		t.Fatalf("verify live quorum runtime Genesis: %v result=%+v", err, result)
	}
	if runtime == nil || result.State != genesis.StateReady {
		t.Fatalf("live quorum runtime Genesis did not reach BOOTSTRAP_READY: runtime=%v result=%+v", runtime, result)
	}
	if pin.CapabilityEnvelopeHash() != bundle.CapabilityEnvelopeHash {
		t.Fatalf(
			"live bundle capability hash=%q differs from verified Genesis=%q",
			bundle.CapabilityEnvelopeHash,
			pin.CapabilityEnvelopeHash(),
		)
	}
	binding, err := pin.ParseQuorumBinding(envelope)
	if err != nil {
		t.Fatalf("bind live quorum through verified Genesis pin: %v", err)
	}
	historyBinding, err := pin.ParseHistoryBinding(
		envelope,
		liveQuorumHistoryPurposeIntegration,
	)
	if err != nil {
		t.Fatalf("bind live history through verified Genesis pin: %v", err)
	}
	if bundle.JournalID != historyBinding.JournalID() {
		t.Fatalf(
			"live bundle journal=%q differs from verified Genesis history=%q",
			bundle.JournalID,
			historyBinding.JournalID(),
		)
	}
	tamperedEnvelope := append(append([]byte(nil), envelope...), '\n')
	if _, err := pin.ParseQuorumBinding(tamperedEnvelope); err == nil {
		t.Fatal("tampered live quorum envelope bypassed verified Genesis pin")
	}
	policy, err := binding.ActivePolicy(bundle.GenesisEpoch)
	if err != nil {
		t.Fatal(err)
	}

	workloadPublicRaw, err := base64.StdEncoding.DecodeString(
		bundle.WorkloadSignerPublicKey,
	)
	if err != nil || len(workloadPublicRaw) != ed25519.PublicKeySize {
		t.Fatal("invalid live quorum workload signer public key")
	}
	workloadPublic := ed25519.PublicKey(workloadPublicRaw)

	ctx := context.Background()
	quorumMembers := make([]journal.QuorumHeadMember, 0, 3)
	remoteStores := make(map[string]*journal.RemoteHeadStore, 3)
	members := make(map[string]liveQuorumMemberIntegration, 3)

	for _, member := range bundle.Members {
		members[member.ID] = member
		ownerPublicRaw, err := base64.StdEncoding.DecodeString(
			member.WitnessOwnerPublicKey,
		)
		if err != nil || len(ownerPublicRaw) != ed25519.PublicKeySize {
			t.Fatalf("invalid witness owner key for %s", member.ID)
		}
		root, err := journal.NewTwoPrincipalWitnessTrustRoot(
			bundle.WorkloadSignerKeyID,
			workloadPublic,
			member.WitnessOwnerKeyID,
			ed25519.PublicKey(ownerPublicRaw),
			1,
		)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(member.CAPEM)) {
			t.Fatalf("%s TLS CA is invalid", member.ID)
		}
		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    roots,
					ServerName: member.TLSServerName,
				},
			},
			Timeout: 2 * time.Second,
		}
		store, err := journal.NewTwoPrincipalRemoteHeadStore(
			ctx,
			member.SignedTrust,
			root,
			client,
		)
		if err != nil {
			t.Fatalf("construct %s remote store: %v", member.ID, err)
		}
		remoteStores[member.ID] = store
		quorumMembers = append(quorumMembers, journal.QuorumHeadMember{
			ID:    member.ID,
			Store: store,
		})
	}

	quorum, err := journal.NewGovernedQuorumHeadStore(
		quorumMembers,
		binding,
		bundle.GenesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	history, err := journal.NewGenesisBoundHistoryStore(quorum, historyBinding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := history.Load(
		ctx,
		bundle.JournalID+"-replacement",
	); !errors.Is(err, journal.ErrHistoryLineageMismatch) {
		t.Fatalf("verified Genesis history accepted substituted lineage: %v", err)
	}
	return independentQuorumFixture{
		bundle:       bundle,
		binding:      binding,
		policy:       policy,
		quorum:       quorum,
		history:      history,
		remoteStores: remoteStores,
		members:      members,
	}
}

func proveIndependentQuorumBaseline(
	t *testing.T,
	fixture independentQuorumFixture,
) {
	t.Helper()
	ctx := context.Background()
	assertIndependentChaosCredentials(t, fixture)

	initial, err := fixture.history.Load(ctx, fixture.bundle.JournalID)
	if err != nil {
		t.Fatalf("load independent quorum baseline: %v", err)
	}
	if initial.Sequence != 0 {
		t.Fatalf("baseline sequence=%d want 0", initial.Sequence)
	}

	t1 := journal.ExternalHead{
		JournalID: fixture.bundle.JournalID,
		Sequence:  1,
		HeadHash:  integrationQuorumDigest("failure-domain-t1"),
		KeyID:     initial.KeyID,
	}
	if _, err := fixture.history.CompareAndAdvance(ctx, initial, t1); err != nil {
		t.Fatalf("advance independent quorum to T1: %v", err)
	}

	// Quorum CompareAndAdvance is allowed to return after threshold members
	// commit. Before removing a whole control plane, explicitly synchronize all
	// three witnesses to T1 so the later stale-minority observation is
	// deterministic and not a scheduler artifact.
	for id, store := range fixture.remoteStores {
		current, err := store.LoadForQuorum(
			ctx,
			fixture.bundle.JournalID,
			fixture.policy,
		)
		if err != nil {
			t.Fatalf("load %s at baseline: %v", id, err)
		}
		switch current.Sequence {
		case 0:
			if _, err := store.CompareAndAdvanceForQuorum(
				ctx,
				fixture.policy,
				current,
				t1,
			); err != nil {
				t.Fatalf("synchronize %s to T1: %v", id, err)
			}
		case 1:
			if current.HeadHash != t1.HeadHash {
				t.Fatalf("%s has conflicting T1 head %+v", id, current)
			}
		default:
			t.Fatalf("%s baseline sequence=%d want 0 or 1", id, current.Sequence)
		}
	}
	for id, store := range fixture.remoteStores {
		current, err := store.LoadForQuorum(
			ctx,
			fixture.bundle.JournalID,
			fixture.policy,
		)
		if err != nil || current.Sequence != 1 || current.HeadHash != t1.HeadHash {
			t.Fatalf("%s did not converge to T1: head=%+v err=%v", id, current, err)
		}
	}
}

func proveIndependentQuorumOneControlPlaneDown(
	t *testing.T,
	fixture independentQuorumFixture,
) {
	t.Helper()
	ctx := context.Background()
	t1, err := fixture.history.Load(ctx, fixture.bundle.JournalID)
	if err != nil {
		t.Fatalf("2-of-3 load with control-plane C down: %v", err)
	}
	if t1.Sequence != 1 ||
		t1.HeadHash != integrationQuorumDigest("failure-domain-t1") {
		t.Fatalf("unexpected T1 while C is down: %+v", t1)
	}

	t2 := journal.ExternalHead{
		JournalID: fixture.bundle.JournalID,
		Sequence:  2,
		HeadHash:  integrationQuorumDigest("failure-domain-t2"),
		KeyID:     t1.KeyID,
	}
	if _, err := fixture.history.CompareAndAdvance(ctx, t1, t2); err != nil {
		t.Fatalf("advance via A+B while C control plane is down: %v", err)
	}
	current, err := fixture.history.Load(ctx, fixture.bundle.JournalID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Sequence != 2 || current.HeadHash != t2.HeadHash {
		t.Fatalf("A+B did not establish T2: %+v", current)
	}
}

func proveIndependentQuorumRestoredStaleMinority(
	t *testing.T,
	fixture independentQuorumFixture,
) {
	t.Helper()
	ctx := context.Background()
	c := fixture.remoteStores["witness-c"]
	if c == nil {
		t.Fatal("witness-c remote store is missing")
	}
	stale := waitForRemoteWitnessHead(
		t,
		ctx,
		c,
		fixture.policy,
		fixture.bundle.JournalID,
	)
	if stale.Sequence != 1 ||
		stale.HeadHash != integrationQuorumDigest("failure-domain-t1") {
		t.Fatalf("restored C is not the expected stale T1 witness: %+v", stale)
	}

	t2, err := fixture.history.Load(ctx, fixture.bundle.JournalID)
	if err != nil {
		t.Fatalf("load quorum with restored stale C: %v", err)
	}
	if t2.Sequence != 2 ||
		t2.HeadHash != integrationQuorumDigest("failure-domain-t2") {
		t.Fatalf("stale C changed quorum truth: %+v", t2)
	}

	next := journal.ExternalHead{
		JournalID: fixture.bundle.JournalID,
		Sequence:  2,
		HeadHash:  t2.HeadHash,
		KeyID:     t2.KeyID,
	}
	if _, err := c.CompareAndAdvanceForQuorum(
		ctx,
		fixture.policy,
		stale,
		next,
	); err != nil {
		t.Fatalf("catch up restored C to T2: %v", err)
	}

	for id, store := range fixture.remoteStores {
		head := waitForRemoteWitnessHead(
			t,
			ctx,
			store,
			fixture.policy,
			fixture.bundle.JournalID,
		)
		if head.Sequence != 2 || head.HeadHash != t2.HeadHash {
			t.Fatalf("%s did not converge to T2: %+v", id, head)
		}
	}
}

func proveIndependentQuorumTwoControlPlanesDown(
	t *testing.T,
	fixture independentQuorumFixture,
) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.history.Load(
		ctx,
		fixture.bundle.JournalID,
	); !errors.Is(err, journal.ErrExternalHeadQuorum) {
		t.Fatalf(
			"one surviving control plane returned %v, want %v",
			err,
			journal.ErrExternalHeadQuorum,
		)
	}
}

func assertIndependentChaosCredentials(
	t *testing.T,
	fixture independentQuorumFixture,
) {
	t.Helper()
	paths := map[string]string{
		"witness-a": os.Getenv("LIVE_QUORUM_WITNESS_A_CHAOS_KUBECONFIG"),
		"witness-b": os.Getenv("LIVE_QUORUM_WITNESS_B_CHAOS_KUBECONFIG"),
		"witness-c": os.Getenv("LIVE_QUORUM_WITNESS_C_CHAOS_KUBECONFIG"),
	}
	configs := make(map[string]*rest.Config, len(paths))
	hosts := make(map[string]string, len(paths))
	for id, path := range paths {
		if strings.TrimSpace(path) == "" {
			t.Fatalf("%s availability kubeconfig path is required", id)
		}
		config, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			t.Fatalf("read %s availability kubeconfig: %v", id, err)
		}
		if config.BearerToken == "" {
			t.Fatalf("%s availability kubeconfig has no bearer token", id)
		}
		if previous, exists := hosts[config.Host]; exists {
			t.Fatalf(
				"%s and %s resolve to the same control plane %s",
				previous,
				id,
				config.Host,
			)
		}
		hosts[config.Host] = id
		configs[id] = config

		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		member := fixture.members[id]
		if _, err := client.CoreV1().ConfigMaps("aegis-capability-witness").Get(
			context.Background(),
			member.StateName,
			metav1.GetOptions{},
		); err == nil || !apierrors.IsForbidden(err) {
			t.Fatalf("%s availability credential can read governed state: %v", id, err)
		}
		deployment, err := client.AppsV1().Deployments(
			"aegis-capability-witness",
		).Get(
			context.Background(),
			member.SignerDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatalf("%s cannot inspect its signer deployment: %v", id, err)
		}
		automount := deployment.Spec.Template.Spec.AutomountServiceAccountToken
		if automount == nil || *automount {
			t.Fatalf("%s signer custody pod has Kubernetes token access", id)
		}
	}
	if len(hosts) != 3 {
		t.Fatalf("distinct control plane count=%d want 3", len(hosts))
	}

	for sourceID, source := range configs {
		for targetID, target := range configs {
			if sourceID == targetID {
				continue
			}
			foreignConfig := runtimeConfigForForeignAPI(
				target,
				source.BearerToken,
			)
			client, err := kubernetes.NewForConfig(foreignConfig)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.CoreV1().Namespaces().Get(
				context.Background(),
				"aegis-capability-witness",
				metav1.GetOptions{},
			)
			if err == nil ||
				(!apierrors.IsUnauthorized(err) && !apierrors.IsForbidden(err)) {
				t.Fatalf(
					"%s credential authenticated against %s control plane: %v",
					sourceID,
					targetID,
					err,
				)
			}
		}
	}
}

func waitForRemoteWitnessHead(
	t *testing.T,
	ctx context.Context,
	store *journal.RemoteHeadStore,
	policy journal.QuorumPolicyState,
	journalID string,
) journal.ExternalHead {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for {
		head, err := store.LoadForQuorum(ctx, journalID, policy)
		if err == nil {
			return head
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("remote witness did not recover: %v", lastErr)
		}
		time.Sleep(time.Second)
	}
}

func independentQuorumPhaseName(phase string) string {
	return fmt.Sprintf("live-quorum-independent-control-planes/%s", phase)
}
