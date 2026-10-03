package genesisbootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Reuse the existing assurance fixture, including its explicit simulated
// attestation/proof records. The native driver must independently call the
// production verifier before receiving a VerifiedGenesisPin. This is not
// physical TPM or formal-model evidence and is never graded as such.
func TestCompositeGenesisFixtureExport(t *testing.T) {
	dir := os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR")
	if dir == "" {
		return
	}
	var input struct {
		NativeBinary string `json:"native_binary"`
		BuildSHA     string `json:"build_sha"`
		OldEnvelope  []byte `json:"old_envelope"`
		NewEnvelope  []byte `json:"new_envelope"`
	}
	data, err := os.ReadFile(os.Getenv("COMPOSITE_GENESIS_INPUT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.BuildSHA) != 40 || input.NativeBinary == "" {
		t.Fatal("exact native binary and build required")
	}
	implementation, err := fileDigest(input.NativeBinary)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for index, envelope := range [][]byte{input.OldEnvelope, input.NewEnvelope} {
		name := "old"
		if index == 1 {
			name = "new"
		}
		folder := filepath.Join(dir, name)
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		fixture := buildProductionFixtureAt(t, folder, now)
		manifest, err := LoadManifest(fixture.manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var provenance SignedBuildProvenanceStatement
		if err := readStrictJSON(fixture.buildProvenancePath, &provenance); err != nil {
			t.Fatal(err)
		}
		provenance.Statement.SubjectImplementationDigest = implementation
		provenance.Statement.SourceRevision = input.BuildSHA
		provenance, err = SignBuildProvenanceStatement(provenance.Statement, fixture.manifestSigner)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, fixture.buildProvenancePath, provenance)
		manifest.Implementation.ImplementationDigest = implementation
		manifest.SupplyChain.SourceRevision = input.BuildSHA
		manifest.SupplyChain.BuildProvenanceRef, err = fileDigest(fixture.buildProvenancePath)
		if err != nil {
			t.Fatal(err)
		}
		manifest.GenesisEpoch = uint64(7 + index)
		manifest.Trust.TrustRootEpoch = manifest.GenesisEpoch
		capPath := filepath.Join(folder, "capability-envelope.json")
		if err := os.WriteFile(capPath, envelope, 0600); err != nil {
			t.Fatal(err)
		}
		manifest.ThreatModel.CapabilityEnvelopeHash = digestBytes(envelope)
		manifest, err = SignManifest(manifest, fixture.manifestSigner)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, fixture.manifestPath, manifest)
		bundle, err := LoadVerificationBundle(fixture.bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Artifacts.CapabilityEnvelope = capPath
		bundle.RelyingContext.ExpectedManifestPayloadHash, err = ManifestPayloadHash(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, fixture.bundlePath, bundle)
		payload, err := CanonicalManifestPayload(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, filepath.Join(folder, "portable-genesis.json"), map[string]any{"payload": payload, "key_id": manifest.Authenticity.SignerKeyID, "signature": manifest.Authenticity.Signature, "capability_envelope": envelope})
		writeJSONFile(t, filepath.Join(folder, "fixture-metadata.json"), map[string]any{"now": now, "genesis_grade": "simulation", "manifest_signer_key_id": manifest.Authenticity.SignerKeyID, "manifest_signer_public_key": base64.StdEncoding.EncodeToString(fixture.manifestSigner.Public().(ed25519.PublicKey))})
	}
}
