package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/easl"
	"github.com/achirothmane/easl/genesis"
)

type testGenesisVerifier struct{}

func (testGenesisVerifier) VerifyAuthenticity(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyTrustRoot(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyAttestation(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyRevocation(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyBuildProvenance(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifySpecBuildBinding(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyDefaultDeny(context.Context, genesis.Manifest) error {
	return nil
}
func (testGenesisVerifier) VerifyProofRequirements(context.Context, genesis.Manifest) error {
	return nil
}

func readyEASLRuntime(t *testing.T) *easl.Runtime {
	t.Helper()

	now := time.Date(2026, 9, 28, 4, 45, 0, 0, time.UTC)
	manifest := genesis.Manifest{
		ManifestVersion:     "1.0",
		GenesisEpoch:        1,
		ArchitectureVersion: "level-minus-1/v1.0",
		Specification: genesis.Specification{
			SpecHash:              testGenesisDigest("a"),
			InvariantSetHash:      testGenesisDigest("b"),
			AssumptionSetHash:     testGenesisDigest("c"),
			ForbiddenStateSetHash: testGenesisDigest("d"),
			TauBoundsHash:         testGenesisDigest("e"),
		},
		Verification: genesis.Verification{
			Mode:           "mixed",
			ProofStatus:    "PASS",
			ProofArtifacts: []string{"proof://test"},
			Toolchain:      []string{"TLC"},
			ModelBounds:    []string{"test"},
			ProofScopeHash: testGenesisDigest("f"),
		},
		ThreatModel: genesis.ThreatModel{
			ThreatModelHash:        testGenesisDigest("1"),
			CapabilityEnvelopeHash: testGenesisDigest("2"),
		},
		Trust: genesis.Trust{
			TrustRootRef:          "trust://test/root",
			TrustRootEpoch:        1,
			AttestationPolicyHash: testGenesisDigest("3"),
			NoncePolicyHash:       testGenesisDigest("4"),
			RevocationRef:         "revocation://test/root",
		},
		Enforcement: genesis.Enforcement{
			EnforcementPolicyHash: testGenesisDigest("5"),
			DefaultDenyRequired:   true,
		},
		Implementation: genesis.Implementation{
			ImplementationDigest:   testGenesisDigest("6"),
			RefinementMappingHash:  testGenesisDigest("7"),
			ConformanceLevel:       genesis.ConformanceC3,
			ExecutableContractHash: testGenesisDigest("8"),
		},
		SupplyChain: genesis.SupplyChain{
			SourceRevision:     "git:test",
			BuilderIdentity:    "builder://test",
			BuildProvenanceRef: "provenance://test",
			MaterialsHash:      testGenesisDigest("9"),
			SBOMHash:           testGenesisDigest("0"),
		},
		Validity: genesis.Validity{
			BuiltAt:              now.Add(-2 * time.Hour),
			ValidFrom:            now.Add(-time.Hour),
			ValidUntil:           now.Add(time.Hour),
			MinimumAcceptedEpoch: 1,
		},
		Approval: genesis.Approval{
			ApprovedBy:         []string{"test://approver"},
			ApprovalPolicyHash: testGenesisDigest("a"),
		},
		Authenticity: genesis.Authenticity{
			Canonicalization:   "RFC8785",
			SignatureScope:     "MANIFEST_EXCLUDING_AUTHENTICITY",
			SignedPayloadHash:  testGenesisDigest("b"),
			SignatureAlgorithm: "ed25519",
			SignerKeyID:        "key://test/genesis",
			Signature:          "base64:test",
		},
	}

	runtime, result := easl.Bootstrap(context.Background(), easl.BootstrapInput{
		Manifest: manifest,
		Verification: genesis.Context{
			Now:                          now,
			MinimumAcceptedEpoch:         1,
			ExpectedImplementationDigest: manifest.Implementation.ImplementationDigest,
			RequiredConformance:          genesis.ConformanceC3,
		},
		Verifier: testGenesisVerifier{},
	})
	if result.State != genesis.StateReady || runtime == nil {
		t.Fatalf("test Genesis bootstrap failed: state=%s failures=%v", result.State, result.Failures)
	}
	return runtime
}

func testGenesisDigest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}
