//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const liveQuorumBundleVersionIntegration = "aegis-ege/live-external-head-quorum-client/v1"

type liveQuorumBundleIntegration struct {
	Version                  string                        `json:"version"`
	GenesisEpoch             uint64                        `json:"genesis_epoch"`
	CapabilityEnvelopeBase64 string                        `json:"capability_envelope_base64"`
	CapabilityEnvelopeHash   string                        `json:"capability_envelope_hash"`
	JournalID                string                        `json:"journal_id"`
	WorkloadSignerKeyID      string                        `json:"workload_signer_key_id"`
	WorkloadSignerPublicKey  string                        `json:"workload_signer_public_key"`
	Members                  []liveQuorumMemberIntegration `json:"members"`
}

type liveQuorumMemberIntegration struct {
	ID                    string                              `json:"id"`
	StateName             string                              `json:"state_name"`
	DeploymentName        string                              `json:"deployment_name"`
	SignerDeploymentName  string                              `json:"signer_deployment_name"`
	Endpoint              string                              `json:"endpoint"`
	TLSServerName         string                              `json:"tls_server_name"`
	CAPEM                 string                              `json:"ca_pem"`
	WitnessOwnerKeyID     string                              `json:"witness_owner_key_id"`
	WitnessOwnerPublicKey string                              `json:"witness_owner_public_key"`
	SignedTrust           journal.SignedWitnessTrustManifest `json:"signed_trust"`
}

func TestKindLiveTwoOfThreeExternalHeadQuorum(t *testing.T) {
	bundlePath := os.Getenv("LIVE_QUORUM_CLIENT_BUNDLE")
	chaosPath := os.Getenv("LIVE_QUORUM_CHAOS_KUBECONFIG")
	witnessRuntimePath := os.Getenv("WITNESS_KUBECONFIG")
	if bundlePath == "" || chaosPath == "" || witnessRuntimePath == "" {
		t.Skip("live quorum bundle, chaos kubeconfig, and witness runtime kubeconfig are required")
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
	if bundle.GenesisEpoch == 0 || len(bundle.Members) != 3 {
		t.Fatalf(
			"live quorum bundle epoch=%d members=%d, want positive epoch and 3 members",
			bundle.GenesisEpoch,
			len(bundle.Members),
		)
	}

	envelope, err := base64.StdEncoding.DecodeString(bundle.CapabilityEnvelopeBase64)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := journal.ParseGenesisQuorumBinding(
		envelope,
		bundle.CapabilityEnvelopeHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := binding.ActivePolicy(bundle.GenesisEpoch)
	if err != nil {
		t.Fatal(err)
	}

	workloadPublicRaw, err := base64.StdEncoding.DecodeString(bundle.WorkloadSignerPublicKey)
	if err != nil || len(workloadPublicRaw) != ed25519.PublicKeySize {
		t.Fatal("invalid live quorum workload signer public key")
	}
	workloadPublic := ed25519.PublicKey(workloadPublicRaw)

	ctx := context.Background()
	quorumMembers := make([]journal.QuorumHeadMember, 0, len(bundle.Members))
	remoteStores := make(map[string]*journal.RemoteHeadStore, len(bundle.Members))
	memberByID := make(map[string]liveQuorumMemberIntegration, len(bundle.Members))

	for _, member := range bundle.Members {
		if _, exists := memberByID[member.ID]; exists {
			t.Fatalf("duplicate live quorum member %q", member.ID)
		}
		memberByID[member.ID] = member

		ownerPublicRaw, err := base64.StdEncoding.DecodeString(member.WitnessOwnerPublicKey)
		if err != nil || len(ownerPublicRaw) != ed25519.PublicKeySize {
			t.Fatalf("invalid owner public key for %s", member.ID)
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
			t.Fatalf("%s CA PEM is invalid", member.ID)
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
			Timeout: 3 * time.Second,
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

	initial, err := quorum.Load(ctx, bundle.JournalID)
	if err != nil {
		t.Fatalf("load initial live quorum head: %v", err)
	}
	if initial.Sequence != 0 {
		t.Fatalf("initial live quorum sequence=%d want 0", initial.Sequence)
	}

	t1 := journal.ExternalHead{
		JournalID: bundle.JournalID,
		Sequence:  1,
		HeadHash:  integrationQuorumDigest("t1"),
		KeyID:     initial.KeyID,
	}
	if _, err := quorum.CompareAndAdvance(ctx, initial, t1); err != nil {
		t.Fatalf("advance live quorum to T1: %v", err)
	}
	t1Current, err := quorum.Load(ctx, bundle.JournalID)
	if err != nil {
		t.Fatal(err)
	}

	chaosConfig, err := clientcmd.BuildConfigFromFlags("", chaosPath)
	if err != nil {
		t.Fatal(err)
	}
	chaosClient, err := kubernetes.NewForConfig(chaosConfig)
	if err != nil {
		t.Fatal(err)
	}

	memberC := memberByID["witness-c"]
	if memberC.ID == "" {
		t.Fatal("live quorum bundle is missing witness-c")
	}
	scaleWitness(t, ctx, chaosClient, memberC.DeploymentName, 0)

	t2 := journal.ExternalHead{
		JournalID: bundle.JournalID,
		Sequence:  2,
		HeadHash:  integrationQuorumDigest("t2"),
		KeyID:     initial.KeyID,
	}
	if _, err := quorum.CompareAndAdvance(ctx, t1Current, t2); err != nil {
		t.Fatalf("2-of-3 advance with witness-c unavailable: %v", err)
	}

	scaleWitness(t, ctx, chaosClient, memberC.DeploymentName, 1)

	// Kubernetes ReadyReplicas can become visible a few moments before the
	// NodePort/TLS data path is stable after a restart. Recovery is considered
	// complete only after the witness itself returns a policy-bound signed head.
	staleC := waitForRemoteWitnessHead(
		t,
		ctx,
		remoteStores["witness-c"],
		policy,
		bundle.JournalID,
	)
	if staleC.Sequence != 1 {
		t.Fatalf("restored witness-c sequence=%d want stale T1=1", staleC.Sequence)
	}

	quorumT2, err := quorum.Load(ctx, bundle.JournalID)
	if err != nil {
		t.Fatalf("load quorum with one stale witness: %v", err)
	}
	if quorumT2.Sequence != 2 || quorumT2.HeadHash != t2.HeadHash {
		t.Fatalf("stale minority changed live quorum truth: %+v", quorumT2)
	}

	if _, err := remoteStores["witness-c"].CompareAndAdvanceForQuorum(
		ctx,
		policy,
		staleC,
		t2,
	); err != nil {
		t.Fatalf("catch up witness-c to T2: %v", err)
	}
	synced, err := quorum.Load(ctx, bundle.JournalID)
	if err != nil || synced.Sequence != 2 {
		t.Fatalf("quorum did not converge at T2: head=%+v err=%v", synced, err)
	}

	memberA := memberByID["witness-a"]
	memberB := memberByID["witness-b"]
	if memberA.ID == "" || memberB.ID == "" {
		t.Fatal("live quorum bundle is missing witness-a or witness-b")
	}

	scaleWitness(t, ctx, chaosClient, memberA.DeploymentName, 0)
	oneDown, err := quorum.Load(ctx, bundle.JournalID)
	if err != nil {
		t.Fatalf("one witness outage broke 2-of-3 quorum: %v", err)
	}
	if oneDown.Sequence != 2 || oneDown.HeadHash != t2.HeadHash {
		t.Fatalf("one witness outage changed quorum truth: %+v", oneDown)
	}

	scaleWitness(t, ctx, chaosClient, memberB.DeploymentName, 0)
	if _, err := quorum.Load(ctx, bundle.JournalID); !errors.Is(
		err,
		journal.ErrExternalHeadQuorum,
	) {
		t.Fatalf("two witness outage load=%v, want %v", err, journal.ErrExternalHeadQuorum)
	}

	scaleWitness(t, ctx, chaosClient, memberA.DeploymentName, 1)
	scaleWitness(t, ctx, chaosClient, memberB.DeploymentName, 1)

	witnessRuntimeConfig, err := clientcmd.BuildConfigFromFlags(
		"",
		witnessRuntimePath,
	)
	if err != nil {
		t.Fatal(err)
	}
	witnessRuntimeClient, err := kubernetes.NewForConfig(witnessRuntimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range bundle.Members {
		if _, err := witnessRuntimeClient.CoreV1().ConfigMaps(
			"aegis-capability-witness",
		).Get(
			ctx,
			member.StateName,
			metav1.GetOptions{},
		); err == nil || !apierrors.IsForbidden(err) {
			t.Fatalf(
				"legacy witness runtime credential can read %s state: %v",
				member.ID,
				err,
			)
		}
		if _, err := chaosClient.CoreV1().ConfigMaps(
			"aegis-capability-witness",
		).Get(
			ctx,
			member.StateName,
			metav1.GetOptions{},
		); err == nil || !apierrors.IsForbidden(err) {
			t.Fatalf(
				"availability-only chaos credential can read %s state: %v",
				member.ID,
				err,
			)
		}

		signerDeployment, err := chaosClient.AppsV1().Deployments(
			"aegis-capability-witness",
		).Get(
			ctx,
			member.SignerDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatalf("read %s signer deployment: %v", member.ID, err)
		}
		automount := signerDeployment.Spec.Template.Spec.AutomountServiceAccountToken
		if automount == nil || *automount {
			t.Fatalf("%s signer custody pod has Kubernetes token access", member.ID)
		}
	}
}

func scaleWitness(
	t *testing.T,
	ctx context.Context,
	client kubernetes.Interface,
	name string,
	replicas int32,
) {
	t.Helper()
	scale, err := client.AppsV1().Deployments(
		"aegis-capability-witness",
	).GetScale(
		ctx,
		name,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get scale %s: %v", name, err)
	}
	scale.Spec.Replicas = replicas
	if _, err := client.AppsV1().Deployments(
		"aegis-capability-witness",
	).UpdateScale(
		ctx,
		name,
		scale,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("scale %s to %d: %v", name, replicas, err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		deployment, err := client.AppsV1().Deployments(
			"aegis-capability-witness",
		).Get(
			ctx,
			name,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatalf("read deployment %s: %v", name, err)
		}
		if replicas == 0 && deployment.Status.ReadyReplicas == 0 {
			return
		}
		if replicas > 0 && deployment.Status.ReadyReplicas >= replicas {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"deployment %s ready replicas=%d want %d",
				name,
				deployment.Status.ReadyReplicas,
				replicas,
			)
		}
		time.Sleep(time.Second)
	}
}

func integrationQuorumDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
