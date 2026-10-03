package genesisbootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/journal"
)

func makeGenesisBoundRemoteWitness(
	t *testing.T,
	id string,
	endpoint string,
) (*journal.RemoteHeadStore, WitnessQuorumMemberPolicy) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := journal.Ed25519KeyID(pub)
	store, err := journal.NewRemoteHeadStore(
		endpoint,
		keyID,
		pub,
		&http.Client{},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.TrustIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return store, WitnessQuorumMemberPolicy{
		ID:                   id,
		Endpoint:             identity.Endpoint,
		WitnessKeyID:         identity.WitnessKeyID,
		WitnessPublicKeyHash: identity.WitnessPublicKeyHash,
	}
}

func buildGenesisBoundQuorumFixture(
	t *testing.T,
	membershipEpoch uint64,
) (
	productionFixture,
	[]WitnessQuorumMemberPolicy,
	map[string]*journal.RemoteHeadStore,
	SignedWitnessQuorumMembershipPolicy,
) {
	t.Helper()
	fixture := buildProductionFixture(t)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	members := make([]WitnessQuorumMemberPolicy, 0, 3)
	stores := make(map[string]*journal.RemoteHeadStore, 3)
	for _, spec := range []struct {
		id       string
		endpoint string
	}{
		{"witness-a", "https://witness-a.example.invalid"},
		{"witness-b", "https://witness-b.example.invalid"},
		{"witness-c", "https://witness-c.example.invalid"},
	} {
		store, policyMember := makeGenesisBoundRemoteWitness(t, spec.id, spec.endpoint)
		stores[spec.id] = store
		members = append(members, policyMember)
	}

	policy := WitnessQuorumMembershipPolicy{
		Version:                    WitnessQuorumMembershipPolicyVersion,
		GenesisManifestPayloadHash: manifestHash,
		GenesisEpoch:               manifest.GenesisEpoch,
		MembershipEpoch:            membershipEpoch,
		Threshold:                  2,
		Members:                    members,
	}
	signed, err := SignWitnessQuorumMembershipPolicy(policy, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, members, stores, signed
}

func TestGenesisBoundQuorumAcceptsExactSignedMembership(t *testing.T) {
	fixture, _, stores, signed := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestPub := fixture.manifestSigner.Public().(ed25519.PublicKey)

	quorum, err := BuildGenesisBoundQuorumHeadStore(
		t.Context(),
		manifest,
		signed,
		manifestPub,
		11,
		stores,
	)
	if err != nil {
		t.Fatal(err)
	}
	if quorum == nil {
		t.Fatal("expected Genesis-bound quorum store")
	}
}

func TestGenesisBoundQuorumRejectsRuntimeWitnessSubstitution(t *testing.T) {
	fixture, _, stores, signed := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	replacement, _ := makeGenesisBoundRemoteWitness(
		t,
		"witness-a",
		"https://replacement.example.invalid",
	)
	stores["witness-a"] = replacement

	_, err = BuildGenesisBoundQuorumHeadStore(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		11,
		stores,
	)
	if err == nil || !strings.Contains(err.Error(), "trust identity substitution detected") {
		t.Fatalf("runtime witness substitution = %v, want identity-substitution denial", err)
	}
}

func TestGenesisBoundQuorumRejectsUnsignedMembershipMutation(t *testing.T) {
	fixture, _, _, signed := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	signed.Policy.Members[0].Endpoint = "https://substituted.example.invalid"
	_, err = VerifyGenesisBoundWitnessQuorumMembershipPolicy(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		11,
	)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("unsigned membership mutation = %v, want signature rejection", err)
	}
}

func TestGenesisBoundQuorumRejectsPolicyReplayAcrossGenesis(t *testing.T) {
	fixture, _, _, signed := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest.Sequence++
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyGenesisBoundWitnessQuorumMembershipPolicy(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		11,
	)
	if err == nil || !strings.Contains(err.Error(), "Genesis binding mismatch") {
		t.Fatalf("policy replay across Genesis = %v, want exact-manifest binding denial", err)
	}
}

func TestGenesisBoundQuorumRejectsMembershipEpochRollback(t *testing.T) {
	fixture, _, _, signed := buildGenesisBoundQuorumFixture(t, 8)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyGenesisBoundWitnessQuorumMembershipPolicy(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		9,
	)
	if err == nil || !strings.Contains(err.Error(), "membership epoch rollback") {
		t.Fatalf("membership epoch rollback = %v, want rollback denial", err)
	}
}

func TestGenesisBoundQuorumRejectsDifferentPolicySigner(t *testing.T) {
	fixture, members, _, _ := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignWitnessQuorumMembershipPolicy(
		WitnessQuorumMembershipPolicy{
			Version:                    WitnessQuorumMembershipPolicyVersion,
			GenesisManifestPayloadHash: manifestHash,
			GenesisEpoch:               manifest.GenesisEpoch,
			MembershipEpoch:            11,
			Threshold:                  2,
			Members:                    members,
		},
		otherPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyGenesisBoundWitnessQuorumMembershipPolicy(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		11,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match trusted Genesis manifest authority") {
		t.Fatalf("different quorum policy signer = %v, want Genesis-authority denial", err)
	}
}

func TestGenesisBoundQuorumRejectsSignedNonMajorityPolicy(t *testing.T) {
	fixture, members, _, _ := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignWitnessQuorumMembershipPolicy(
		WitnessQuorumMembershipPolicy{
			Version:                    WitnessQuorumMembershipPolicyVersion,
			GenesisManifestPayloadHash: manifestHash,
			GenesisEpoch:               manifest.GenesisEpoch,
			MembershipEpoch:            11,
			Threshold:                  1,
			Members:                    members,
		},
		fixture.manifestSigner,
	)
	if err == nil || !strings.Contains(err.Error(), "strict majority") {
		t.Fatalf("signed 1-of-3 policy = %v, want structural quorum rejection", err)
	}
}

func TestGenesisBoundQuorumRejectsUnexpectedExtraRuntimeWitness(t *testing.T) {
	fixture, _, stores, signed := buildGenesisBoundQuorumFixture(t, 11)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := makeGenesisBoundRemoteWitness(
		t,
		"witness-d",
		"https://witness-d.example.invalid",
	)
	stores["witness-d"] = extra

	_, err = BuildGenesisBoundQuorumHeadStore(
		t.Context(),
		manifest,
		signed,
		fixture.manifestSigner.Public().(ed25519.PublicKey),
		11,
		stores,
	)
	if err == nil || !strings.Contains(err.Error(), "membership cardinality mismatch") {
		t.Fatalf("extra runtime witness = %v, want exact-set denial", err)
	}
}
