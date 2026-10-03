package journal

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func quorumTrustHashForTest(id string) string {
	return sha256Digest([]byte("quorum-test-trust:" + id))
}

func quorumBindingForTest(
	t *testing.T,
	threshold int,
	ids ...string,
) GenesisQuorumBinding {
	t.Helper()
	raw := quorumCapabilityEnvelopeForTest(t, threshold, ids...)
	binding, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func quorumCapabilityEnvelopeForTest(
	t *testing.T,
	threshold int,
	ids ...string,
) []byte {
	t.Helper()
	members := make([]QuorumTrustPolicyMember, 0, len(ids))
	for _, id := range ids {
		members = append(members, QuorumTrustPolicyMember{
			ID:                id,
			TrustManifestHash: quorumTrustHashForTest(id),
		})
	}
	envelope := struct {
		Version               string            `json:"version"`
		ExternalWitnessQuorum QuorumTrustPolicy `json:"external_witness_quorum"`
	}{
		Version: "aegis-ege/capability-envelope/v1",
		ExternalWitnessQuorum: QuorumTrustPolicy{
			Protocol:  QuorumTrustPolicyVersion,
			Threshold: threshold,
			Members:   members,
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func quorumMemberForTest(id string, store ExternalHeadStore) QuorumHeadMember {
	return QuorumHeadMember{
		ID:                id,
		TrustManifestHash: quorumTrustHashForTest(id),
		Store:             store,
	}
}

func TestGenesisQuorumBindingAcceptsExactGovernedConfiguration(t *testing.T) {
	raw := quorumCapabilityEnvelopeForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	binding, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	if binding.threshold != 2 {
		t.Fatalf("threshold = %d, want 2", binding.threshold)
	}
	if len(binding.members) != 3 {
		t.Fatalf("members = %d, want 3", len(binding.members))
	}
	if !validSHA256Digest(binding.policyHash) {
		t.Fatalf("policy hash is not bound: %q", binding.policyHash)
	}

	base := newQuorumTestStore(nil)
	store, err := NewQuorumHeadStore([]QuorumHeadMember{
		quorumMemberForTest("witness-c", base),
		quorumMemberForTest("witness-a", base),
		quorumMemberForTest("witness-b", base),
	}, binding)
	if err != nil {
		t.Fatal(err)
	}
	if store.threshold != 2 {
		t.Fatalf("constructed threshold = %d, want 2", store.threshold)
	}
	if store.policyHash != binding.policyHash {
		t.Fatalf("store policy hash = %s, want %s", store.policyHash, binding.policyHash)
	}
}

func TestGenesisQuorumBindingRejectsCapabilityEnvelopeTamper(t *testing.T) {
	raw := quorumCapabilityEnvelopeForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	genesisHash := sha256Digest(raw)
	tampered := append([]byte(nil), raw...)
	tampered = append(tampered, byte(' '))

	if _, err := ParseGenesisQuorumBinding(tampered, genesisHash); err == nil {
		t.Fatal("capability envelope byte tamper unexpectedly accepted")
	}
}

func TestGenesisQuorumBindingRejectsValidThresholdDowngradeWithoutNewGenesis(t *testing.T) {
	strong := quorumCapabilityEnvelopeForTest(
		t,
		4,
		"witness-a",
		"witness-b",
		"witness-c",
		"witness-d",
		"witness-e",
	)
	genesisHash := sha256Digest(strong)

	// 3-of-5 remains a mathematically valid strict majority. It is nevertheless
	// a different governance choice and must require a new Genesis-bound
	// capability envelope rather than being accepted as runtime configuration.
	weaker := quorumCapabilityEnvelopeForTest(
		t,
		3,
		"witness-a",
		"witness-b",
		"witness-c",
		"witness-d",
		"witness-e",
	)
	if _, err := ParseGenesisQuorumBinding(weaker, genesisHash); err == nil {
		t.Fatal("valid-but-weaker quorum threshold unexpectedly replaced Genesis policy")
	}
}

func TestQuorumHeadStoreRejectsWitnessSetReplacement(t *testing.T) {
	binding := quorumBindingForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	base := newQuorumTestStore(nil)

	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		quorumMemberForTest("witness-a", base),
		quorumMemberForTest("witness-b", base),
		quorumMemberForTest("witness-x", base),
	}, binding); err == nil {
		t.Fatal("runtime witness replacement unexpectedly accepted")
	}
}

func TestQuorumHeadStoreRejectsWitnessTrustIdentityReplacement(t *testing.T) {
	binding := quorumBindingForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	base := newQuorumTestStore(nil)
	replaced := quorumMemberForTest("witness-b", base)
	replaced.TrustManifestHash = sha256Digest([]byte("different-runtime-key-and-endpoint"))

	if _, err := NewQuorumHeadStore([]QuorumHeadMember{
		quorumMemberForTest("witness-a", base),
		replaced,
		quorumMemberForTest("witness-c", base),
	}, binding); err == nil {
		t.Fatal("same witness id with different trust identity unexpectedly accepted")
	}
}

func TestGenesisQuorumBindingRejectsNonMajorityPolicy(t *testing.T) {
	raw := quorumCapabilityEnvelopeForTest(
		t,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
		"witness-d",
	)
	if _, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw)); err == nil {
		t.Fatal("2-of-4 non-intersecting policy unexpectedly accepted")
	}
}

func TestGenesisQuorumBindingRejectsDuplicateWitnessIDs(t *testing.T) {
	raw := quorumCapabilityEnvelopeForTest(
		t,
		2,
		"witness-a",
		"witness-a",
		"witness-c",
	)
	if _, err := ParseGenesisQuorumBinding(raw, sha256Digest(raw)); err == nil {
		t.Fatal("duplicate governed witness id unexpectedly accepted")
	}
}

func TestWitnessTrustManifestDigestBindsRuntimeIdentity(t *testing.T) {
	baseKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	manifest := WitnessTrustManifest{
		Version:             WitnessTrustManifestVersion,
		TrustEpoch:          9,
		WorkloadPrincipal:   "spiffe://workload/aegis",
		WitnessPrincipal:    "spiffe://witness/a",
		Endpoint:            "https://witness-a.example.test/",
		WitnessRuntimeKeyID: "key-a",
		WitnessRuntimeKey:   baseKey,
	}
	first, err := WitnessTrustManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Endpoint = strings.TrimSuffix(manifest.Endpoint, "/")
	same, err := WitnessTrustManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first != same {
		t.Fatalf("normalized equivalent endpoint changed digest: %s != %s", first, same)
	}

	manifest.WitnessRuntimeKeyID = "key-b"
	changed, err := WitnessTrustManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("runtime witness key identity replacement did not change trust manifest digest")
	}
}
