package genesisbootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

type verifiedPinTestStore struct {
	trustManifestHash string
	policy            journal.QuorumPolicyState
}

func (s *verifiedPinTestStore) QuorumTrustManifestHash() string {
	return s.trustManifestHash
}

func (s *verifiedPinTestStore) Load(
	context.Context,
	string,
) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, journal.ErrExternalHeadNotFound
}

func (s *verifiedPinTestStore) CompareAndAdvance(
	context.Context,
	journal.ExternalHead,
	journal.ExternalHead,
) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, journal.ErrExternalHeadConflict
}

func (s *verifiedPinTestStore) LoadForQuorum(
	context.Context,
	string,
	journal.QuorumPolicyState,
) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, journal.ErrExternalHeadNotFound
}

func (s *verifiedPinTestStore) CompareAndAdvanceForQuorum(
	context.Context,
	journal.QuorumPolicyState,
	journal.ExternalHead,
	journal.ExternalHead,
) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, journal.ErrExternalHeadConflict
}

func (s *verifiedPinTestStore) CurrentQuorumPolicy(
	context.Context,
) (journal.QuorumPolicyState, error) {
	return s.policy, nil
}

func (s *verifiedPinTestStore) ObserveQuorumRotationHead(
	context.Context,
	string,
) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, journal.ErrExternalHeadNotFound
}

func (s *verifiedPinTestStore) CompareAndTransitionQuorumPolicy(
	context.Context,
	journal.QuorumPolicyState,
	journal.QuorumPolicyState,
	string,
	journal.ExternalHead,
) error {
	return errors.New("not used")
}

func TestProductionGenesisPinBindsExactQuorumEnvelope(t *testing.T) {
	fixture := buildProductionFixture(t)
	memberTrustHash := "sha256:" + strings.Repeat("a", 64)
	envelope := installQuorumCapabilityEnvelope(
		t,
		fixture,
		memberTrustHash,
	)

	runtime, result, pin, err := BootstrapProductionWithSubjectPin(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err != nil {
		t.Fatalf("production Genesis with quorum envelope: %v result=%+v", err, result)
	}
	if runtime == nil || result.State != genesis.StateReady {
		t.Fatalf("expected BOOTSTRAP_READY, got runtime=%v result=%+v", runtime, result)
	}
	if pin.GenesisEpoch() != 7 ||
		pin.CapabilityEnvelopeHash() == "" ||
		pin.ManifestPayloadHash() == "" {
		t.Fatalf("invalid verified Genesis pin: epoch=%d envelope=%q manifest=%q",
			pin.GenesisEpoch(),
			pin.CapabilityEnvelopeHash(),
			pin.ManifestPayloadHash(),
		)
	}

	binding, err := pin.ParseQuorumBinding(envelope)
	if err != nil {
		t.Fatalf("bind exact Genesis capability envelope: %v", err)
	}
	historyBinding, err := pin.ParseHistoryBinding(envelope, "production-history")
	if err != nil {
		t.Fatalf("bind exact Genesis history identity: %v", err)
	}
	if historyBinding.JournalID() != "production-history/main" ||
		historyBinding.CapabilityEnvelopeHash() != pin.CapabilityEnvelopeHash() {
		t.Fatalf(
			"unexpected Genesis history binding: journal=%q envelope=%q",
			historyBinding.JournalID(),
			historyBinding.CapabilityEnvelopeHash(),
		)
	}

	quorumEpoch, historyEpoch, err := pin.ParseHistorySuccessionEpochs(
		envelope,
		"production-history",
	)
	if err != nil {
		t.Fatalf("derive co-bound succession epochs: %v", err)
	}
	if quorumEpoch.GenesisEpoch() != pin.GenesisEpoch() ||
		historyEpoch.GenesisEpoch() != pin.GenesisEpoch() ||
		quorumEpoch.GenesisManifestHash() != pin.ManifestPayloadHash() ||
		historyEpoch.GenesisManifestHash() != pin.ManifestPayloadHash() ||
		quorumEpoch.CapabilityEnvelopeHash() != pin.CapabilityEnvelopeHash() ||
		historyEpoch.JournalID() != historyBinding.JournalID() {
		t.Fatalf(
			"succession epochs escaped verified Genesis provenance: quorum=(epoch=%d manifest=%q envelope=%q) history=(epoch=%d manifest=%q journal=%q)",
			quorumEpoch.GenesisEpoch(),
			quorumEpoch.GenesisManifestHash(),
			quorumEpoch.CapabilityEnvelopeHash(),
			historyEpoch.GenesisEpoch(),
			historyEpoch.GenesisManifestHash(),
			historyEpoch.JournalID(),
		)
	}
	expectedPolicy, err := binding.ActivePolicy(pin.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	if quorumEpoch.PolicyHash() != expectedPolicy.PolicyHash {
		t.Fatal("co-bound quorum epoch policy differs from verified Genesis binding")
	}
	store := &verifiedPinTestStore{
		trustManifestHash: memberTrustHash,
		policy: journal.QuorumPolicyState{
			Phase:        journal.QuorumPolicyPhaseActive,
			GenesisEpoch: pin.GenesisEpoch(),
		},
	}
	quorum, err := journal.NewGovernedQuorumHeadStore(
		[]journal.QuorumHeadMember{{
			ID:    "witness-live-a",
			Store: store,
		}},
		binding,
		pin.GenesisEpoch(),
	)
	if err != nil {
		t.Fatalf("construct Genesis-bound 1-of-1 quorum: %v", err)
	}
	if quorum.QuorumPolicyHash() == "" {
		t.Fatal("Genesis-bound quorum omitted policy hash")
	}
	store.policy.PolicyHash = quorum.QuorumPolicyHash()

	tampered := append([]byte(nil), envelope...)
	tampered = append(tampered, byte(10))
	if _, err := pin.ParseQuorumBinding(tampered); err == nil ||
		!strings.Contains(err.Error(), "capability envelope hash mismatch") {
		t.Fatalf("tampered envelope = %v, want exact Genesis hash rejection", err)
	}
	if _, err := pin.ParseHistoryBinding(
		tampered,
		"production-history",
	); err == nil || !strings.Contains(err.Error(), "capability envelope hash mismatch") {
		t.Fatalf("tampered history envelope = %v, want exact Genesis hash rejection", err)
	}
	if _, _, err := pin.ParseHistorySuccessionEpochs(
		tampered,
		"production-history",
	); err == nil || !strings.Contains(err.Error(), "capability envelope hash mismatch") {
		t.Fatalf("tampered succession envelope = %v, want exact Genesis hash rejection", err)
	}
}

func TestProductionGenesisPinBindsSuccessorGovernanceAuthority(t *testing.T) {
	fixture := buildProductionFixture(t)
	governancePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := installSuccessorGovernanceCapabilityEnvelope(t, fixture, governancePub)

	runtime, result, pin, err := BootstrapProductionWithSubjectPin(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err != nil {
		t.Fatalf("production Genesis with successor-governance envelope: %v result=%+v", err, result)
	}
	if runtime == nil || result.State != genesis.StateReady {
		t.Fatalf("expected BOOTSTRAP_READY, got runtime=%v result=%+v", runtime, result)
	}

	binding, err := pin.ParseEnrollmentSuccessorGovernanceBinding(envelope)
	if err != nil {
		t.Fatal(err)
	}
	boundKey, err := binding.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(boundKey) != string(governancePub) ||
		binding.GenesisEpoch() != pin.GenesisEpoch() ||
		binding.CapabilityEnvelopeHash() != pin.CapabilityEnvelopeHash() ||
		binding.PolicyHash() == "" {
		t.Fatalf("unexpected Genesis successor-governance binding: epoch=%d envelope=%s policy=%s",
			binding.GenesisEpoch(),
			binding.CapabilityEnvelopeHash(),
			binding.PolicyHash(),
		)
	}

	tampered := append([]byte(nil), envelope...)
	tampered = append(tampered, byte(10))
	if _, err := pin.ParseEnrollmentSuccessorGovernanceBinding(tampered); err == nil ||
		!strings.Contains(err.Error(), "capability envelope hash mismatch") {
		t.Fatalf("tampered successor-governance envelope = %v, want exact Genesis hash rejection", err)
	}
}

func TestProductionGenesisLockedDoesNotEmitVerifiedPin(t *testing.T) {
	fixture := buildProductionFixture(t)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Implementation.ImplementationDigest = digestBytes(
		[]byte("different-running-binary"),
	)
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)

	runtime, result, pin, err := BootstrapProductionWithSubjectPin(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil {
		t.Fatal("locked Genesis unexpectedly emitted success")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED, got runtime=%v result=%+v", runtime, result)
	}
	if pin.GenesisEpoch() != 0 ||
		pin.CapabilityEnvelopeHash() != "" ||
		pin.ManifestPayloadHash() != "" {
		t.Fatalf("locked Genesis leaked usable pin: %+v", pin)
	}
	if _, err := pin.ParseQuorumBinding([]byte("{}")); err == nil ||
		!strings.Contains(err.Error(), "verified Genesis pin is unavailable") {
		t.Fatalf("zero pin parse = %v, want unavailable", err)
	}
	if _, err := pin.ParseHistoryBinding(
		[]byte("{}"),
		"production-history",
	); err == nil || !strings.Contains(err.Error(), "verified Genesis pin is unavailable") {
		t.Fatalf("zero pin history parse = %v, want unavailable", err)
	}
	if _, _, err := pin.ParseHistorySuccessionEpochs(
		[]byte("{}"),
		"production-history",
	); err == nil || !strings.Contains(err.Error(), "verified Genesis pin is unavailable") {
		t.Fatalf("zero pin succession epochs = %v, want unavailable", err)
	}
}

func installQuorumCapabilityEnvelope(
	t *testing.T,
	fixture productionFixture,
	memberTrustHash string,
) []byte {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"external_witness_quorum": journal.QuorumTrustPolicy{
			Protocol:  journal.QuorumTrustPolicyVersion,
			Threshold: 1,
			Members: []journal.QuorumTrustPolicyMember{{
				ID:                "witness-live-a",
				TrustManifestHash: memberTrustHash,
			}},
		},
		"governed_histories": journal.GovernedHistoryTrustPolicy{
			Protocol: journal.GovernedHistoryTrustPolicyVersion,
			Histories: []journal.GovernedHistoryIdentity{{
				Purpose:   "production-history",
				JournalID: "production-history/main",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(fixture.manifestPath), "quorum-capability-envelope.json")
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ThreatModel.CapabilityEnvelopeHash = digest
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)
	payloadHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := LoadVerificationBundle(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts.CapabilityEnvelope = path
	bundle.RelyingContext.ExpectedManifestPayloadHash = payloadHash
	writeJSONFile(t, fixture.bundlePath, bundle)
	return envelope
}


func installSuccessorGovernanceCapabilityEnvelope(
	t *testing.T,
	fixture productionFixture,
	publicKey ed25519.PublicKey,
) []byte {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"enrollment_successor_governance": journal.EnrollmentSuccessorGovernancePolicy{
			Protocol:        journal.EnrollmentSuccessorGovernancePolicyVersion,
			AuthorityID:     "vcs13-production-authority",
			PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(fixture.manifestPath), "successor-governance-capability-envelope.json")
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ThreatModel.CapabilityEnvelopeHash = digest
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)
	payloadHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := LoadVerificationBundle(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts.CapabilityEnvelope = path
	bundle.RelyingContext.ExpectedManifestPayloadHash = payloadHash
	writeJSONFile(t, fixture.bundlePath, bundle)
	return envelope
}
