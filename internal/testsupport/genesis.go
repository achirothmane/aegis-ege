// Package testsupport contains deterministic fixtures for tests and offline
// non-mutating simulations. It must never be used to authorize production
// mutations or replace a real Genesis verifier.
package testsupport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/easl"
	"github.com/achirothmane/easl/genesis"
)

type syntheticGenesisVerifier struct{}

func (syntheticGenesisVerifier) VerifyAuthenticity(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyTrustRoot(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyAttestation(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyRevocation(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyBuildProvenance(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifySpecBuildBinding(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyDefaultDeny(context.Context, genesis.Manifest) error { return nil }
func (syntheticGenesisVerifier) VerifyProofRequirements(context.Context, genesis.Manifest) error { return nil }

// NewSyntheticEASLRuntime returns a deterministic Genesis-bound runtime for
// tests and offline benchmarks only.
func NewSyntheticEASLRuntime() (*easl.Runtime, error) {
	now := time.Date(2026, 9, 28, 4, 45, 0, 0, time.UTC)
	manifest := genesis.Manifest{
		ManifestVersion:     "1.0",
		GenesisEpoch:        1,
		ArchitectureVersion: "level-minus-1/v1.0",
		Specification: genesis.Specification{
			SpecHash:              digest("a"),
			InvariantSetHash:      digest("b"),
			AssumptionSetHash:     digest("c"),
			ForbiddenStateSetHash: digest("d"),
			TauBoundsHash:         digest("e"),
		},
		Verification: genesis.Verification{
			Mode:           "mixed",
			ProofStatus:    "PASS",
			ProofArtifacts: []string{"proof://synthetic"},
			Toolchain:      []string{"TLC"},
			ModelBounds:    []string{"synthetic"},
			ProofScopeHash: digest("f"),
		},
		ThreatModel: genesis.ThreatModel{
			ThreatModelHash:        digest("1"),
			CapabilityEnvelopeHash: digest("2"),
		},
		Trust: genesis.Trust{
			TrustRootRef:          "trust://synthetic/root",
			TrustRootEpoch:        1,
			AttestationPolicyHash: digest("3"),
			NoncePolicyHash:       digest("4"),
			RevocationRef:         "revocation://synthetic/root",
		},
		Enforcement: genesis.Enforcement{
			EnforcementPolicyHash: digest("5"),
			DefaultDenyRequired:   true,
		},
		Implementation: genesis.Implementation{
			ImplementationDigest:   digest("6"),
			RefinementMappingHash:  digest("7"),
			ConformanceLevel:       genesis.ConformanceC3,
			ExecutableContractHash: digest("8"),
		},
		SupplyChain: genesis.SupplyChain{
			SourceRevision:     "git:synthetic",
			BuilderIdentity:    "builder://synthetic",
			BuildProvenanceRef: "provenance://synthetic",
			MaterialsHash:      digest("9"),
			SBOMHash:           digest("0"),
		},
		Validity: genesis.Validity{
			BuiltAt:              now.Add(-2 * time.Hour),
			ValidFrom:            now.Add(-time.Hour),
			ValidUntil:           now.Add(24 * time.Hour),
			MinimumAcceptedEpoch: 1,
		},
		Approval: genesis.Approval{
			ApprovedBy:         []string{"synthetic://approver"},
			ApprovalPolicyHash: digest("a"),
		},
		Authenticity: genesis.Authenticity{
			Canonicalization:   "RFC8785",
			SignatureScope:     "MANIFEST_EXCLUDING_AUTHENTICITY",
			SignedPayloadHash:  digest("b"),
			SignatureAlgorithm: "ed25519",
			SignerKeyID:        "key://synthetic/genesis",
			Signature:          "base64:synthetic",
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
		Verifier: syntheticGenesisVerifier{},
	})
	if result.State != genesis.StateReady || runtime == nil {
		return nil, fmt.Errorf("synthetic Genesis bootstrap failed: state=%s failures=%v", result.State, result.Failures)
	}
	return runtime, nil
}

func digest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}
