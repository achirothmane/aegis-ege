package genesisbootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func TestBootstrapProductionAllowsFullyBoundGenesis(t *testing.T) {
	fixture := buildProductionFixture(t)

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err != nil {
		t.Fatalf("BootstrapProduction() error = %v; result=%+v", err, result)
	}
	if result.State != genesis.StateReady || runtime == nil {
		t.Fatalf("expected BOOTSTRAP_READY runtime, got state=%s failures=%v", result.State, result.Failures)
	}
}

func TestBootstrapProductionRejectsImplementationDigestTamper(t *testing.T) {
	fixture := buildProductionFixture(t)

	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Implementation.ImplementationDigest = digestBytes([]byte("different-binary"))
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err == nil {
		t.Fatal("expected tampered implementation digest to fail")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED with nil runtime, got runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureImplementationMismatch)
}

func TestBootstrapProductionRejectsRevokedManifest(t *testing.T) {
	fixture := buildProductionFixture(t)

	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	payloadHash, err := ManifestRevocationHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	revocations := RevocationList{
		Version:                     RevocationListVersion,
		Epoch:                       2,
		MinimumAcceptedGenesisEpoch:  7,
		MinimumAcceptedDoctrineEpoch: 3,
		MinimumTrustRootEpoch:        7,
		IssuedAt:                    fixture.now.Add(-time.Hour),
		ExpiresAt:                   fixture.now.Add(time.Hour),
		RevokedManifestHashes:       []string{payloadHash},
	}
	signed, err := SignRevocationList(revocations, fixture.revocationSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.revocationPath, signed)
	ref, err := SignedRevocationListDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Trust.RevocationRef = ref
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err == nil {
		t.Fatal("expected revoked manifest to fail")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED, got runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureRevoked)
}



func TestBootstrapProductionRejectsDoctrineEpochRollback(t *testing.T) {
	fixture := buildProductionFixture(t)

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		4,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err == nil {
		t.Fatal("expected doctrine rollback to fail")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED, got runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureDoctrineRollback)
}

func TestBootstrapProductionRejectsDoctrineManifestTamper(t *testing.T) {
	fixture := buildProductionFixture(t)
	if err := os.WriteFile(fixture.doctrineManifestPath, []byte("tampered-doctrine"), 0o600); err != nil {
		t.Fatal(err)
	}

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err == nil {
		t.Fatal("expected doctrine manifest tamper to fail")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED, got runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureDoctrineMismatch)
}

func TestBootstrapProductionRejectsDoctrineAuthoritySignatureTamper(t *testing.T) {
	fixture := buildProductionFixture(t)
	var signed SignedDoctrineAuthorityStatement
	if err := readStrictJSON(fixture.doctrineStatementPath, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	writeJSONFile(t, fixture.doctrineStatementPath, signed)

	runtime, result, err := BootstrapProduction(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.now,
	)
	if err == nil {
		t.Fatal("expected doctrine authority signature tamper to fail")
	}
	if runtime != nil || result.State != genesis.StateLocked {
		t.Fatalf("expected GENESIS_LOCKED, got runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureDoctrineUnverified)
}

func TestManifestRevocationHashIgnoresRevocationRef(t *testing.T) {
	fixture := buildProductionFixture(t)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ManifestRevocationHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Trust.RevocationRef = digestBytes([]byte("another-revocation-list"))
	second, err := ManifestRevocationHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("revocation identity changed with revocation_ref: %s != %s", first, second)
	}
}

type productionFixture struct {
	now                    time.Time
	manifestPath           string
	bundlePath             string
	doctrineManifestPath   string
	doctrineStatementPath  string
	revocationPath         string
	buildProvenancePath    string
	proofRecordPath        string
	bootstrapReceiptPath   string
	remoteDecisionPath     string
	manifestSigner         ed25519.PrivateKey
	bootstrapSigner        ed25519.PrivateKey
	remoteSigner           ed25519.PrivateKey
	revocationSigner       ed25519.PrivateKey
	currentSubject         CurrentSubject
}

func buildProductionFixture(t *testing.T) productionFixture {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 9, 28, 5, 0, 0, 0, time.UTC)

	doctrinePub, doctrinePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPub, manifestPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePub, remotePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPub, bootstrapPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revocationPub, revocationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	doctrinePubPath := filepath.Join(dir, "doctrine-authority.pub")
	manifestPubPath := filepath.Join(dir, "manifest.pub")
	remotePubPath := filepath.Join(dir, "remote.pub")
	bootstrapPubPath := filepath.Join(dir, "bootstrap.pub")
	revocationPubPath := filepath.Join(dir, "revocation.pub")
	writePublicKey(t, doctrinePubPath, doctrinePub)
	writePublicKey(t, manifestPubPath, manifestPub)
	writePublicKey(t, remotePubPath, remotePub)
	writePublicKey(t, bootstrapPubPath, bootstrapPub)
	writePublicKey(t, revocationPubPath, revocationPub)

	artifactPath := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(artifactPath, []byte("genesis-production-artifact-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactDigest, err := fileDigest(artifactPath)
	if err != nil {
		t.Fatal(err)
	}

	doctrineManifestPath := filepath.Join(dir, "doctrine.md")
	if err := os.WriteFile(doctrineManifestPath, []byte("# Assumption Decay Doctrine\n\nEvidence before authority.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doctrineDigest, err := fileDigest(doctrineManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	doctrineStatement := DoctrineAuthorityStatement{
		Version:              DoctrineAuthorityStatementVersion,
		DoctrineID:           "aegis-ege-doctrine",
		DoctrineEpoch:        3,
		DoctrineManifestHash: doctrineDigest,
		IssuedAt:             now.Add(-time.Hour),
		ExpiresAt:            now.Add(time.Hour),
	}
	signedDoctrineStatement, err := SignDoctrineAuthorityStatement(doctrineStatement, doctrinePriv)
	if err != nil {
		t.Fatal(err)
	}
	doctrineStatementPath := filepath.Join(dir, "doctrine-authority-statement.json")
	writeJSONFile(t, doctrineStatementPath, signedDoctrineStatement)

	executableDigest, err := currentExecutableDigest()
	if err != nil {
		t.Fatal(err)
	}
	currentSubject, err := CurrentProductionSubject("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}

	buildProvenance := BuildProvenanceStatement{
		Version:                     BuildProvenanceStatementVersion,
		BuilderIdentity:             "builder://test",
		SourceRevision:              "git:test",
		SubjectImplementationDigest: executableDigest,
		MaterialsHash:               artifactDigest,
		SBOMHash:                    artifactDigest,
		BuiltAt:                     now.Add(-2 * time.Hour),
		IssuedAt:                    now.Add(-90 * time.Minute),
		ExpiresAt:                   now.Add(time.Hour),
	}
	signedBuildProvenance, err := SignBuildProvenanceStatement(buildProvenance, manifestPriv)
	if err != nil {
		t.Fatal(err)
	}
	buildProvenancePath := filepath.Join(dir, "build-provenance.json")
	writeJSONFile(t, buildProvenancePath, signedBuildProvenance)
	buildProvenanceDigest, err := fileDigest(buildProvenancePath)
	if err != nil {
		t.Fatal(err)
	}

	proofRecord := ProofVerificationRecord{
		Version:          ProofVerificationRecordVersion,
		Result:           "PASS",
		VerificationMode: "mixed",
		SpecHash:         artifactDigest,
		ProofScopeHash:   artifactDigest,
		Toolchain:        []string{"TLC", "TLAPS"},
		ModelBounds:      []string{"production-profile-test"},
		CheckedAt:        now.Add(-80 * time.Minute),
	}
	proofRecordPath := filepath.Join(dir, "proof-verification-record.json")
	writeJSONFile(t, proofRecordPath, proofRecord)
	proofRecordDigest, err := fileDigest(proofRecordPath)
	if err != nil {
		t.Fatal(err)
	}

	bootstrapReceipt := kernelfabric.BootstrapReceipt{
		Version:             kernelfabric.BootstrapReceiptVersion,
		ManifestDigest:      digestBytes([]byte("bpf-manifest")),
		ManifestSignerKeyID: "ed25519:test-release",
		ArtifactSHA256:      digestBytes([]byte("bpf-object")),
		ArtifactSize:        123,
		Host: kernelfabric.BootstrapHostSnapshot{
			BootIDHash:    currentSubject.BootIDHash,
			KernelRelease: "test-kernel",
			LockdownMode:  "integrity",
			BPFFSRoot:     "/sys/fs/bpf",
		},
		CgroupPath: "/sys/fs/cgroup/aegis",
		Programs: []kernelfabric.PinnedProgramAttestation{
			{PinName: "aegis_connect4", ID: 1, Name: "aegis_connect4", Type: "cgroup_sock_addr", Tag: "tag4", AttachType: "connect4"},
			{PinName: "aegis_connect6", ID: 2, Name: "aegis_connect6", Type: "cgroup_sock_addr", Tag: "tag6", AttachType: "connect6"},
		},
		Maps: []kernelfabric.PinnedMapAttestation{
			{Name: "aegis_capsules", ID: 3, Type: "hash", KeySize: 8, ValueSize: 64, MaxEntries: 1024},
			{Name: "aegis_fences", ID: 4, Type: "hash", KeySize: 8, ValueSize: 64, MaxEntries: 1024},
		},
		CompletedAt: now.Add(-time.Minute),
	}
	signedReceipt, err := kernelfabric.SignBootstrapReceipt(bootstrapReceipt, bootstrapPriv)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapReceiptPath := filepath.Join(dir, "bootstrap-receipt.json")
	writeJSONFile(t, bootstrapReceiptPath, signedReceipt)
	bootstrapDigest, err := kernelfabric.SignedBootstrapReceiptDigest(signedReceipt)
	if err != nil {
		t.Fatal(err)
	}

	remoteDecision := kernelfabric.RemoteAttestationDecision{
		Version:         kernelfabric.RemoteAttestationDecisionVersion,
		DecisionID:      "decision-1",
		ChallengeID:     "challenge-1",
		DeviceID:        "device-1",
		Decision:        "ALLOW",
		ReasonCodes:     []string{"TPM_QUOTE_VERIFIED", "PLATFORM_EVENT_LOG_VERIFIED", "BPF_ARTIFACT_IMA_MEASURED", "IMA_PCR10_REPLAY_VERIFIED"},
		BootstrapDigest: bootstrapDigest,
		AKPublicSHA256:  digestBytes([]byte("ak")),
		PCR10SHA256:     digestBytes([]byte("pcr10")),
		IMAReplaySHA256: digestBytes([]byte("ima")),
		VerifiedAt:      now.Add(-30 * time.Second),
		VerifierID:      "prod-attestation-authority",
	}
	signedDecision := signRemoteDecisionForTest(t, remoteDecision, remotePriv)
	remoteDecisionPath := filepath.Join(dir, "remote-decision.json")
	writeJSONFile(t, remoteDecisionPath, signedDecision)

	revocations := RevocationList{
		Version:                      RevocationListVersion,
		Epoch:                        1,
		MinimumAcceptedGenesisEpoch:  7,
		MinimumAcceptedDoctrineEpoch: 3,
		MinimumTrustRootEpoch:        7,
		IssuedAt:                    now.Add(-time.Hour),
		ExpiresAt:                   now.Add(time.Hour),
	}
	signedRevocations, err := SignRevocationList(revocations, revocationPriv)
	if err != nil {
		t.Fatal(err)
	}
	revocationPath := filepath.Join(dir, "revocations.json")
	writeJSONFile(t, revocationPath, signedRevocations)
	revocationDigest, err := SignedRevocationListDigest(signedRevocations)
	if err != nil {
		t.Fatal(err)
	}

	trustRootRef, err := kernelfabric.BootstrapKeyID(remotePub)
	if err != nil {
		t.Fatal(err)
	}

	manifest := genesis.Manifest{
		ManifestVersion:     "1.1",
		GenesisEpoch:        7,
		Sequence:            0,
		ArchitectureVersion: "level-minus-1/v1.1",
		Doctrine: genesis.DoctrineBinding{
			DoctrineID:           "aegis-ege-doctrine",
			DoctrineEpoch:        3,
			DoctrineManifestHash: doctrineDigest,
		},
		Specification: genesis.Specification{
			SpecHash:              artifactDigest,
			InvariantSetHash:      artifactDigest,
			AssumptionSetHash:     artifactDigest,
			ForbiddenStateSetHash: artifactDigest,
			TauBoundsHash:         artifactDigest,
		},
		Verification: genesis.Verification{
			Mode:           "mixed",
			ProofStatus:    "PASS",
			ProofArtifacts: []string{proofRecordDigest},
			Toolchain:      []string{"TLC", "TLAPS"},
			ModelBounds:    []string{"production-profile-test"},
			ProofScopeHash: artifactDigest,
		},
		ThreatModel: genesis.ThreatModel{
			ThreatModelHash:        artifactDigest,
			CapabilityEnvelopeHash: artifactDigest,
		},
		Trust: genesis.Trust{
			TrustRootRef:          trustRootRef,
			TrustRootEpoch:        7,
			AttestationPolicyHash: artifactDigest,
			NoncePolicyHash:       artifactDigest,
			RevocationRef:         revocationDigest,
		},
		Enforcement: genesis.Enforcement{
			EnforcementPolicyHash: artifactDigest,
			DefaultDenyRequired:   true,
		},
		Implementation: genesis.Implementation{
			ImplementationDigest:   executableDigest,
			RefinementMappingHash:  artifactDigest,
			ConformanceLevel:       genesis.ConformanceC3,
			ExecutableContractHash: artifactDigest,
		},
		SupplyChain: genesis.SupplyChain{
			SourceRevision:     "git:test",
			BuilderIdentity:    "builder://test",
			BuildProvenanceRef: buildProvenanceDigest,
			MaterialsHash:      artifactDigest,
			SBOMHash:           artifactDigest,
		},
		Validity: genesis.Validity{
			BuiltAt:              now.Add(-2 * time.Hour),
			ValidFrom:            now.Add(-time.Hour),
			ValidUntil:           now.Add(time.Hour),
			MinimumAcceptedEpoch: 7,
		},
		Approval: genesis.Approval{
			ApprovedBy:         []string{"security://test"},
			ApprovalPolicyHash: artifactDigest,
		},
	}
	manifest, err = SignManifest(manifest, manifestPriv)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "genesis.json")
	writeJSONFile(t, manifestPath, manifest)
	manifestPayloadHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		t.Fatal(err)
	}

	bundle := VerificationBundle{
		Version:                            BundleVersion,
		AssuranceProfile:                   AssuranceProfileVersion,
		RelyingContext: RelyingContext{
			ExpectedManifestPayloadHash: manifestPayloadHash,
			ExpectedDeviceID:            remoteDecision.DeviceID,
			ExpectedChallengeID:         remoteDecision.ChallengeID,
		},
		DoctrineManifest:                   doctrineManifestPath,
		SignedDoctrineAuthorityStatement:   doctrineStatementPath,
		DoctrineAuthorityPublicKey:         doctrinePubPath,
		ManifestSignerPublicKey:            manifestPubPath,
		RemoteAttestationDecision:          remoteDecisionPath,
		RemoteAttestationVerifierPublicKey: remotePubPath,
		BootstrapReceipt:                   bootstrapReceiptPath,
		BootstrapAttestorPublicKey:         bootstrapPubPath,
		SignedRevocationList:               revocationPath,
		RevocationAuthorityPublicKey:       revocationPubPath,
		MaxAttestationAgeSeconds:           120,
		Artifacts: ArtifactPaths{
			Specification:      artifactPath,
			InvariantSet:       artifactPath,
			AssumptionSet:      artifactPath,
			ForbiddenStateSet:  artifactPath,
			TauBounds:          artifactPath,
			ProofScope:         artifactPath,
			ThreatModel:        artifactPath,
			CapabilityEnvelope: artifactPath,
			AttestationPolicy:  artifactPath,
			NoncePolicy:        artifactPath,
			EnforcementPolicy:  artifactPath,
			RefinementMapping:  artifactPath,
			ExecutableContract: artifactPath,
			BuildProvenance:    buildProvenancePath,
			Materials:          artifactPath,
			SBOM:               artifactPath,
			ApprovalPolicy:     artifactPath,
		},
		ProofArtifactPaths: []string{proofRecordPath},
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	writeJSONFile(t, bundlePath, bundle)

	return productionFixture{
		now:                    now,
		manifestPath:           manifestPath,
		bundlePath:             bundlePath,
		doctrineManifestPath:   doctrineManifestPath,
		doctrineStatementPath:  doctrineStatementPath,
		revocationPath:         revocationPath,
		buildProvenancePath:    buildProvenancePath,
		proofRecordPath:        proofRecordPath,
		bootstrapReceiptPath:   bootstrapReceiptPath,
		remoteDecisionPath:     remoteDecisionPath,
		manifestSigner:         manifestPriv,
		bootstrapSigner:        bootstrapPriv,
		remoteSigner:           remotePriv,
		revocationSigner:       revocationPriv,
		currentSubject:         currentSubject,
	}
}

func signRemoteDecisionForTest(t *testing.T, decision kernelfabric.RemoteAttestationDecision, key ed25519.PrivateKey) kernelfabric.SignedRemoteAttestationDecision {
	t.Helper()
	normalized := decision
	normalized.VerifiedAt = normalized.VerifiedAt.UTC()
	normalized.ReasonCodes = append([]string(nil), normalized.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	body, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte("aegis-ege/remote-attestation-decision/v1\x00"), body...)
	keyID, err := kernelfabric.BootstrapKeyID(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return kernelfabric.SignedRemoteAttestationDecision{
		Decision:  decision,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)),
	}
}

func writePublicKey(t *testing.T, path string, key ed25519.PublicKey) {
	t.Helper()
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func assertFailureCode(t *testing.T, result genesis.Result, code genesis.FailureCode) {
	t.Helper()
	for _, failure := range result.Failures {
		if failure.Code == code {
			return
		}
	}
	t.Fatalf("missing failure code %s in %+v", code, result.Failures)
}
