package testsupport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

// ProductionGenesisFixture is a real production-verifier fixture for integration
// tests. Unlike NewSyntheticEASLRuntime it exercises the full Genesis assurance
// path and may be used only from tests/offline proofs.
type ProductionGenesisFixture struct {
	ManifestPath string
	BundlePath   string
	Subject      genesisbootstrap.CurrentSubject
	Now          time.Time
}

func NewProductionGenesisFixture(
	dir string,
	capabilityEnvelope []byte,
	genesisEpoch uint64,
) (ProductionGenesisFixture, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	return NewProductionGenesisFixtureForExecutable(
		dir,
		capabilityEnvelope,
		genesisEpoch,
		executablePath,
	)
}

func NewProductionGenesisFixtureForExecutable(
	dir string,
	capabilityEnvelope []byte,
	genesisEpoch uint64,
	executablePath string,
) (ProductionGenesisFixture, error) {
	if genesisEpoch == 0 {
		return ProductionGenesisFixture{}, fmt.Errorf("genesis epoch must be non-zero")
	}
	if len(capabilityEnvelope) == 0 {
		return ProductionGenesisFixture{}, fmt.Errorf("capability envelope is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ProductionGenesisFixture{}, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	doctrinePub, doctrinePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	manifestPub, manifestPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	remotePub, remotePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	bootstrapPub, bootstrapPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	revocationPub, revocationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	doctrinePubPath := filepath.Join(dir, "doctrine-authority.pub")
	manifestPubPath := filepath.Join(dir, "manifest.pub")
	remotePubPath := filepath.Join(dir, "remote.pub")
	bootstrapPubPath := filepath.Join(dir, "bootstrap.pub")
	revocationPubPath := filepath.Join(dir, "revocation.pub")
	for path, key := range map[string]ed25519.PublicKey{
		doctrinePubPath: doctrinePub,
		manifestPubPath: manifestPub,
		remotePubPath: remotePub,
		bootstrapPubPath: bootstrapPub,
		revocationPubPath: revocationPub,
	} {
		if err := writeFixturePublicKey(path, key); err != nil {
			return ProductionGenesisFixture{}, err
		}
	}

	artifactPath := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(artifactPath, []byte("genesis-production-integration-artifact-v1"), 0o600); err != nil {
		return ProductionGenesisFixture{}, err
	}
	artifactDigest, err := fixtureFileDigest(artifactPath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	envelopePath := filepath.Join(dir, "capability-envelope.json")
	if err := os.WriteFile(envelopePath, capabilityEnvelope, 0o600); err != nil {
		return ProductionGenesisFixture{}, err
	}
	envelopeDigest, err := fixtureFileDigest(envelopePath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	doctrineManifestPath := filepath.Join(dir, "doctrine.md")
	if err := os.WriteFile(
		doctrineManifestPath,
		[]byte("# Assumption Decay Doctrine\n\nEvidence before authority.\n"),
		0o600,
	); err != nil {
		return ProductionGenesisFixture{}, err
	}
	doctrineDigest, err := fixtureFileDigest(doctrineManifestPath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	doctrineStatement := genesisbootstrap.DoctrineAuthorityStatement{
		Version:              genesisbootstrap.DoctrineAuthorityStatementVersion,
		DoctrineID:           "aegis-ege-doctrine",
		DoctrineEpoch:        3,
		DoctrineManifestHash: doctrineDigest,
		IssuedAt:             now.Add(-time.Hour),
		ExpiresAt:            now.Add(time.Hour),
	}
	signedDoctrine, err := genesisbootstrap.SignDoctrineAuthorityStatement(
		doctrineStatement,
		doctrinePriv,
	)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	doctrineStatementPath := filepath.Join(dir, "doctrine-authority-statement.json")
	if err := writeFixtureJSON(doctrineStatementPath, signedDoctrine); err != nil {
		return ProductionGenesisFixture{}, err
	}

	if executablePath == "" {
		return ProductionGenesisFixture{}, fmt.Errorf("target executable path is required")
	}
	executableDigest, err := fixtureFileDigest(executablePath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	subject, err := genesisbootstrap.CurrentProductionSubject("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	buildProvenance := genesisbootstrap.BuildProvenanceStatement{
		Version:                     genesisbootstrap.BuildProvenanceStatementVersion,
		BuilderIdentity:             "builder://live-quorum-integration",
		SourceRevision:              "git:integration",
		SubjectImplementationDigest: executableDigest,
		MaterialsHash:               artifactDigest,
		SBOMHash:                    artifactDigest,
		BuiltAt:                     now.Add(-2 * time.Hour),
		IssuedAt:                    now.Add(-90 * time.Minute),
		ExpiresAt:                   now.Add(time.Hour),
	}
	signedBuild, err := genesisbootstrap.SignBuildProvenanceStatement(
		buildProvenance,
		manifestPriv,
	)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	buildProvenancePath := filepath.Join(dir, "build-provenance.json")
	if err := writeFixtureJSON(buildProvenancePath, signedBuild); err != nil {
		return ProductionGenesisFixture{}, err
	}
	buildProvenanceDigest, err := fixtureFileDigest(buildProvenancePath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	proofRecord := genesisbootstrap.ProofVerificationRecord{
		Version:          genesisbootstrap.ProofVerificationRecordVersion,
		Result:           "PASS",
		VerificationMode: "mixed",
		SpecHash:         artifactDigest,
		ProofScopeHash:   artifactDigest,
		Toolchain:        []string{"TLC", "TLAPS"},
		ModelBounds:      []string{"live-quorum-integration"},
		CheckedAt:        now.Add(-80 * time.Minute),
	}
	proofRecordPath := filepath.Join(dir, "proof-verification-record.json")
	if err := writeFixtureJSON(proofRecordPath, proofRecord); err != nil {
		return ProductionGenesisFixture{}, err
	}
	proofRecordDigest, err := fixtureFileDigest(proofRecordPath)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	bootstrapReceipt := kernelfabric.BootstrapReceipt{
		Version:             kernelfabric.BootstrapReceiptVersion,
		ManifestDigest:      fixtureDigestBytes([]byte("bpf-manifest")),
		ManifestSignerKeyID: "ed25519:live-quorum-integration",
		ArtifactSHA256:      fixtureDigestBytes([]byte("bpf-object")),
		ArtifactSize:        123,
		Host: kernelfabric.BootstrapHostSnapshot{
			BootIDHash:    subject.BootIDHash,
			KernelRelease: "integration-kernel",
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
	signedBootstrap, err := kernelfabric.SignBootstrapReceipt(bootstrapReceipt, bootstrapPriv)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	bootstrapPath := filepath.Join(dir, "bootstrap-receipt.json")
	if err := writeFixtureJSON(bootstrapPath, signedBootstrap); err != nil {
		return ProductionGenesisFixture{}, err
	}
	bootstrapDigest, err := kernelfabric.SignedBootstrapReceiptDigest(signedBootstrap)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	remoteDecision := kernelfabric.RemoteAttestationDecision{
		Version:         kernelfabric.RemoteAttestationDecisionVersion,
		DecisionID:      "live-quorum-decision",
		ChallengeID:     "live-quorum-challenge",
		DeviceID:        "live-quorum-device",
		Decision:        "ALLOW",
		ReasonCodes:     []string{"TPM_QUOTE_VERIFIED", "PLATFORM_EVENT_LOG_VERIFIED", "BPF_ARTIFACT_IMA_MEASURED", "IMA_PCR10_REPLAY_VERIFIED"},
		BootstrapDigest: bootstrapDigest,
		AKPublicSHA256:  fixtureDigestBytes([]byte("ak")),
		PCR10SHA256:     fixtureDigestBytes([]byte("pcr10")),
		IMAReplaySHA256: fixtureDigestBytes([]byte("ima")),
		VerifiedAt:      now.Add(-30 * time.Second),
		VerifierID:      "live-quorum-attestation-authority",
	}
	signedDecision, err := signFixtureRemoteDecision(remoteDecision, remotePriv)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	remoteDecisionPath := filepath.Join(dir, "remote-decision.json")
	if err := writeFixtureJSON(remoteDecisionPath, signedDecision); err != nil {
		return ProductionGenesisFixture{}, err
	}

	revocations := genesisbootstrap.RevocationList{
		Version:                      genesisbootstrap.RevocationListVersion,
		Epoch:                        1,
		MinimumAcceptedGenesisEpoch:  genesisEpoch,
		MinimumAcceptedDoctrineEpoch: 3,
		MinimumTrustRootEpoch:        7,
		IssuedAt:                    now.Add(-time.Hour),
		ExpiresAt:                   now.Add(time.Hour),
	}
	signedRevocations, err := genesisbootstrap.SignRevocationList(revocations, revocationPriv)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	revocationPath := filepath.Join(dir, "revocations.json")
	if err := writeFixtureJSON(revocationPath, signedRevocations); err != nil {
		return ProductionGenesisFixture{}, err
	}
	revocationDigest, err := genesisbootstrap.SignedRevocationListDigest(signedRevocations)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	trustRootRef, err := kernelfabric.BootstrapKeyID(remotePub)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	manifest := genesis.Manifest{
		ManifestVersion:     "1.1",
		GenesisEpoch:        genesisEpoch,
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
			ModelBounds:    []string{"live-quorum-integration"},
			ProofScopeHash: artifactDigest,
		},
		ThreatModel: genesis.ThreatModel{
			ThreatModelHash:        artifactDigest,
			CapabilityEnvelopeHash: envelopeDigest,
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
			SourceRevision:     "git:integration",
			BuilderIdentity:    "builder://live-quorum-integration",
			BuildProvenanceRef: buildProvenanceDigest,
			MaterialsHash:      artifactDigest,
			SBOMHash:           artifactDigest,
		},
		Validity: genesis.Validity{
			BuiltAt:              now.Add(-2 * time.Hour),
			ValidFrom:            now.Add(-time.Hour),
			ValidUntil:           now.Add(time.Hour),
			MinimumAcceptedEpoch: genesisEpoch,
		},
		Approval: genesis.Approval{
			ApprovedBy:         []string{"security://live-quorum-integration"},
			ApprovalPolicyHash: artifactDigest,
		},
	}
	manifest, err = genesisbootstrap.SignManifest(manifest, manifestPriv)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}
	manifestPath := filepath.Join(dir, "genesis.json")
	if err := writeFixtureJSON(manifestPath, manifest); err != nil {
		return ProductionGenesisFixture{}, err
	}
	manifestPayloadHash, err := genesisbootstrap.ManifestPayloadHash(manifest)
	if err != nil {
		return ProductionGenesisFixture{}, err
	}

	bundle := genesisbootstrap.VerificationBundle{
		Version:          genesisbootstrap.BundleVersion,
		AssuranceProfile: genesisbootstrap.AssuranceProfileVersion,
		RelyingContext: genesisbootstrap.RelyingContext{
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
		BootstrapReceipt:                   bootstrapPath,
		BootstrapAttestorPublicKey:         bootstrapPubPath,
		SignedRevocationList:               revocationPath,
		RevocationAuthorityPublicKey:       revocationPubPath,
		MaxAttestationAgeSeconds:           120,
		Artifacts: genesisbootstrap.ArtifactPaths{
			Specification:      artifactPath,
			InvariantSet:       artifactPath,
			AssumptionSet:      artifactPath,
			ForbiddenStateSet:  artifactPath,
			TauBounds:          artifactPath,
			ProofScope:         artifactPath,
			ThreatModel:        artifactPath,
			CapabilityEnvelope: envelopePath,
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
	bundlePath := filepath.Join(dir, "verification-bundle.json")
	if err := writeFixtureJSON(bundlePath, bundle); err != nil {
		return ProductionGenesisFixture{}, err
	}
	return ProductionGenesisFixture{
		ManifestPath: manifestPath,
		BundlePath:   bundlePath,
		Subject:      subject,
		Now:          now,
	}, nil
}

func signFixtureRemoteDecision(
	decision kernelfabric.RemoteAttestationDecision,
	privateKey ed25519.PrivateKey,
) (kernelfabric.SignedRemoteAttestationDecision, error) {
	normalized := decision
	normalized.VerifiedAt = normalized.VerifiedAt.UTC()
	normalized.ReasonCodes = append([]string(nil), normalized.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	body, err := json.Marshal(normalized)
	if err != nil {
		return kernelfabric.SignedRemoteAttestationDecision{}, err
	}
	payload := append([]byte("aegis-ege/remote-attestation-decision/v1\x00"), body...)
	keyID, err := kernelfabric.BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return kernelfabric.SignedRemoteAttestationDecision{}, err
	}
	return kernelfabric.SignedRemoteAttestationDecision{
		Decision:  decision,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func writeFixturePublicKey(path string, key ed25519.PublicKey) error {
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600)
}

func writeFixtureJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func fixtureFileDigest(path string) (string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fixtureDigestBytes(payload), nil
}

func fixtureDigestBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
