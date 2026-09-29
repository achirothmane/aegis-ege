package genesisbootstrap

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func TestBootstrapProductionV2RejectsSemanticallyWrongSignedProvenance(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BuildProvenanceStatement)
	}{
		{
			name: "wrong builder",
			mutate: func(statement *BuildProvenanceStatement) {
				statement.BuilderIdentity = "builder://other"
			},
		},
		{
			name: "wrong source",
			mutate: func(statement *BuildProvenanceStatement) {
				statement.SourceRevision = "git:other"
			},
		},
		{
			name: "wrong subject binary",
			mutate: func(statement *BuildProvenanceStatement) {
				statement.SubjectImplementationDigest = digestBytes([]byte("other-binary"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := buildProductionFixture(t)
			var signed SignedBuildProvenanceStatement
			if err := readStrictJSON(fixture.buildProvenancePath, &signed); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&signed.Statement)
			resigned, err := SignBuildProvenanceStatement(signed.Statement, fixture.manifestSigner)
			if err != nil {
				t.Fatal(err)
			}
			writeJSONFile(t, fixture.buildProvenancePath, resigned)
			provenanceDigest, err := fileDigest(fixture.buildProvenancePath)
			if err != nil {
				t.Fatal(err)
			}

			manifest, err := LoadManifest(fixture.manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest.SupplyChain.BuildProvenanceRef = provenanceDigest
			resignManifestAndRepin(t, fixture, manifest)

			runtime, result, err := BootstrapProductionWithSubject(
				t.Context(),
				fixture.manifestPath,
				fixture.bundlePath,
				7,
				3,
				genesis.ConformanceC3,
				fixture.currentSubject,
				fixture.now,
			)
			if err == nil || runtime != nil {
				t.Fatalf("semantic provenance substitution unexpectedly accepted: runtime=%v result=%+v", runtime, result)
			}
			assertFailureCode(t, result, genesis.FailureBuildProvenance)
		})
	}
}

func TestBootstrapProductionV2RejectsHashCorrectSemanticallyInvalidProofRecord(t *testing.T) {
	fixture := buildProductionFixture(t)
	var record ProofVerificationRecord
	if err := readStrictJSON(fixture.proofRecordPath, &record); err != nil {
		t.Fatal(err)
	}
	record.Result = "FAIL"
	writeJSONFile(t, fixture.proofRecordPath, record)
	proofDigest, err := fileDigest(fixture.proofRecordPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Verification.ProofArtifacts = []string{proofDigest}
	resignManifestAndRepin(t, fixture, manifest)

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("semantic proof failure unexpectedly accepted: runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureProofRequirements)
}

func TestBootstrapProductionV2RejectsPriorBootReportInDifferentCurrentBoot(t *testing.T) {
	fixture := buildProductionFixture(t)
	otherSubject := fixture.currentSubject
	otherSubject.BootIDHash = digestBytes([]byte("other-current-boot"))

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		otherSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("prior-boot report unexpectedly accepted: runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureAttestation)
}

func TestBootstrapProductionV2RejectsWrongRelyingDeviceOrChallenge(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerificationBundle)
	}{
		{
			name: "wrong device",
			mutate: func(bundle *VerificationBundle) {
				bundle.RelyingContext.ExpectedDeviceID = "device-other"
			},
		},
		{
			name: "wrong challenge",
			mutate: func(bundle *VerificationBundle) {
				bundle.RelyingContext.ExpectedChallengeID = "challenge-other"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := buildProductionFixture(t)
			var bundle VerificationBundle
			if err := readStrictJSON(fixture.bundlePath, &bundle); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&bundle)
			writeJSONFile(t, fixture.bundlePath, bundle)

			runtime, result, err := BootstrapProductionWithSubject(
				t.Context(),
				fixture.manifestPath,
				fixture.bundlePath,
				7,
				3,
				genesis.ConformanceC3,
				fixture.currentSubject,
				fixture.now,
			)
			if err == nil || runtime != nil {
				t.Fatalf("wrong relying context unexpectedly accepted: runtime=%v result=%+v", runtime, result)
			}
			assertFailureCode(t, result, genesis.FailureAttestation)
		})
	}
}

func TestBootstrapProductionV2RejectsSubstitutedSignedManifestWithoutRelyingPin(t *testing.T) {
	fixture := buildProductionFixture(t)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Approval.ApprovedBy = []string{"security://substituted"}
	manifest, err = SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, manifest)

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("substituted manifest unexpectedly accepted: runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureAuthenticity)
}

func TestBootstrapProductionV2RejectsStaleAttestationAndRevocation(t *testing.T) {
	t.Run("remote decision stale", func(t *testing.T) {
		fixture := buildProductionFixture(t)
		var signed kernelfabric.SignedRemoteAttestationDecision
		if err := readStrictJSON(fixture.remoteDecisionPath, &signed); err != nil {
			t.Fatal(err)
		}
		signed.Decision.VerifiedAt = fixture.now.Add(-3 * time.Minute)
		signed = signRemoteDecisionForTest(t, signed.Decision, fixture.remoteSigner)
		writeJSONFile(t, fixture.remoteDecisionPath, signed)

		runtime, result, err := BootstrapProductionWithSubject(
			t.Context(),
			fixture.manifestPath,
			fixture.bundlePath,
			7,
			3,
			genesis.ConformanceC3,
			fixture.currentSubject,
			fixture.now,
		)
		if err == nil || runtime != nil {
			t.Fatalf("stale attestation unexpectedly accepted: runtime=%v result=%+v", runtime, result)
		}
		assertFailureCode(t, result, genesis.FailureAttestation)
	})

	t.Run("revocation list stale", func(t *testing.T) {
		fixture := buildProductionFixture(t)
		var signed SignedRevocationList
		if err := readStrictJSON(fixture.revocationPath, &signed); err != nil {
			t.Fatal(err)
		}
		signed.List.IssuedAt = fixture.now.Add(-2 * time.Hour)
		signed.List.ExpiresAt = fixture.now.Add(-time.Minute)
		resigned, err := SignRevocationList(signed.List, fixture.revocationSigner)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, fixture.revocationPath, resigned)
		ref, err := SignedRevocationListDigest(resigned)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := LoadManifest(fixture.manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Trust.RevocationRef = ref
		resignManifestAndRepin(t, fixture, manifest)

		runtime, result, err := BootstrapProductionWithSubject(
			t.Context(),
			fixture.manifestPath,
			fixture.bundlePath,
			7,
			3,
			genesis.ConformanceC3,
			fixture.currentSubject,
			fixture.now,
		)
		if err == nil || runtime != nil {
			t.Fatalf("stale revocation unexpectedly accepted: runtime=%v result=%+v", runtime, result)
		}
		assertFailureCode(t, result, genesis.FailureRevoked)
	})
}

func TestBootstrapProductionV2DeniesUnsupportedC4Assurance(t *testing.T) {
	fixture := buildProductionFixture(t)
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Implementation.ConformanceLevel = genesis.ConformanceC4
	resignManifestAndRepin(t, fixture, manifest)

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("unsupported C4 assurance unexpectedly accepted: runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureSpecBuildBinding)
}

func resignManifestAndRepin(t *testing.T, fixture productionFixture, manifest genesis.Manifest) {
	t.Helper()
	signed, err := SignManifest(manifest, fixture.manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.manifestPath, signed)
	payloadHash, err := ManifestPayloadHash(signed)
	if err != nil {
		t.Fatal(err)
	}
	var bundle VerificationBundle
	if err := readStrictJSON(fixture.bundlePath, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.RelyingContext.ExpectedManifestPayloadHash = payloadHash
	writeJSONFile(t, fixture.bundlePath, bundle)
}

func TestProductionBundleV1IsNotSilentlyUpgraded(t *testing.T) {
	fixture := buildProductionFixture(t)
	var bundle VerificationBundle
	if err := readStrictJSON(fixture.bundlePath, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Version = "aegis.ege/genesis-verification-bundle/v1"
	writeJSONFile(t, fixture.bundlePath, bundle)

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("legacy bundle unexpectedly authorized startup: runtime=%v result=%+v", runtime, result)
	}
	if result.State != genesis.StateLocked {
		t.Fatalf("legacy bundle result = %+v", result)
	}
}

func TestSignedProvenanceRequiresTrustedIssuer(t *testing.T) {
	fixture := buildProductionFixture(t)
	var signed SignedBuildProvenanceStatement
	if err := readStrictJSON(fixture.buildProvenancePath, &signed); err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resigned, err := SignBuildProvenanceStatement(signed.Statement, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, fixture.buildProvenancePath, resigned)
	provenanceDigest, err := fileDigest(fixture.buildProvenancePath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.SupplyChain.BuildProvenanceRef = provenanceDigest
	resignManifestAndRepin(t, fixture, manifest)

	runtime, result, err := BootstrapProductionWithSubject(
		t.Context(),
		fixture.manifestPath,
		fixture.bundlePath,
		7,
		3,
		genesis.ConformanceC3,
		fixture.currentSubject,
		fixture.now,
	)
	if err == nil || runtime != nil {
		t.Fatalf("untrusted provenance issuer unexpectedly accepted: runtime=%v result=%+v", runtime, result)
	}
	assertFailureCode(t, result, genesis.FailureBuildProvenance)
}

var (
	_ = errors.Is
	_ = os.ErrNotExist
	_ = strings.Contains
)
