package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

type twoPrincipalKeys struct {
	workloadPublic  ed25519.PublicKey
	workloadPrivate ed25519.PrivateKey
	witnessPublic   ed25519.PublicKey
	witnessPrivate  ed25519.PrivateKey
	runtimePublic   ed25519.PublicKey
	runtimePrivate  ed25519.PrivateKey
}

func generateTwoPrincipalKeys(t *testing.T) twoPrincipalKeys {
	t.Helper()
	wp, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	op, opriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rp, rpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return twoPrincipalKeys{
		workloadPublic:  wp,
		workloadPrivate: wpriv,
		witnessPublic:   op,
		witnessPrivate:  opriv,
		runtimePublic:   rp,
		runtimePrivate:  rpriv,
	}
}

func baseWitnessTrustManifest(keys twoPrincipalKeys, epoch uint64) WitnessTrustManifest {
	return WitnessTrustManifest{
		Version:             WitnessTrustManifestVersion,
		TrustEpoch:          epoch,
		WorkloadPrincipal:   "principal-a/workload-owner",
		WitnessPrincipal:    "principal-b/witness-owner",
		Endpoint:            "https://witness.example.invalid",
		WitnessRuntimeKeyID: Ed25519KeyID(keys.runtimePublic),
		WitnessRuntimeKey:   base64.StdEncoding.EncodeToString(keys.runtimePublic),
	}
}

func newTwoPrincipalRoot(t *testing.T, keys twoPrincipalKeys, minimumEpoch uint64) *TwoPrincipalWitnessTrustRoot {
	t.Helper()
	root, err := NewTwoPrincipalWitnessTrustRoot(
		"workload-root",
		keys.workloadPublic,
		"witness-owner-root",
		keys.witnessPublic,
		minimumEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func signTwoPrincipalManifest(t *testing.T, manifest WitnessTrustManifest, keys twoPrincipalKeys) SignedWitnessTrustManifest {
	t.Helper()
	signed, err := SignWitnessTrustManifest(
		manifest,
		"workload-root",
		keys.workloadPrivate,
		"witness-owner-root",
		keys.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestTwoPrincipalWitnessTrustManifestAcceptsJointAuthorization(t *testing.T) {
	keys := generateTwoPrincipalKeys(t)
	root := newTwoPrincipalRoot(t, keys, 7)
	signed := signTwoPrincipalManifest(t, baseWitnessTrustManifest(keys, 7), keys)

	manifest, runtimeKey, err := root.Verify(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TrustEpoch != 7 ||
		manifest.Endpoint != "https://witness.example.invalid" ||
		manifest.WitnessPrincipal != "principal-b/witness-owner" {
		t.Fatalf("unexpected verified manifest: %+v", manifest)
	}
	if string(runtimeKey) != string(keys.runtimePublic) {
		t.Fatal("verified runtime key mismatch")
	}

	store, err := NewTwoPrincipalRemoteHeadStore(
		context.Background(),
		signed,
		root,
		&http.Client{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store.endpoint != manifest.Endpoint ||
		store.witnessKeyID != manifest.WitnessRuntimeKeyID ||
		string(store.witnessKey) != string(keys.runtimePublic) {
		t.Fatal("remote head store was not bound to verified manifest")
	}
	wantTrustManifestHash, err := WitnessTrustManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if store.QuorumTrustManifestHash() != wantTrustManifestHash {
		t.Fatalf(
			"remote store trust manifest hash = %s, want verified %s",
			store.QuorumTrustManifestHash(),
			wantTrustManifestHash,
		)
	}
}

func TestTwoPrincipalWitnessTrustManifestRejectsWorkloadOnlyRotation(t *testing.T) {
	keys := generateTwoPrincipalKeys(t)
	root := newTwoPrincipalRoot(t, keys, 4)
	signed := signTwoPrincipalManifest(t, baseWitnessTrustManifest(keys, 4), keys)

	signed.Manifest.Endpoint = "https://replacement.example.invalid"
	payload, err := CanonicalWitnessTrustManifestPayload(signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed.WorkloadSignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(keys.workloadPrivate, payload),
	)
	// Principal A can re-sign its own side, but cannot create Principal B's
	// authorization over the replacement witness.
	if _, _, err := root.Verify(context.Background(), signed); err == nil ||
		!strings.Contains(err.Error(), "witness owner signature verification failed") {
		t.Fatalf("workload-only rotation = %v, want witness-owner rejection", err)
	}
}

func TestTwoPrincipalWitnessTrustManifestRejectsWitnessOnlyRotation(t *testing.T) {
	keys := generateTwoPrincipalKeys(t)
	root := newTwoPrincipalRoot(t, keys, 4)
	signed := signTwoPrincipalManifest(t, baseWitnessTrustManifest(keys, 4), keys)

	replacementPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed.Manifest.WitnessRuntimeKeyID = Ed25519KeyID(replacementPublic)
	signed.Manifest.WitnessRuntimeKey = base64.StdEncoding.EncodeToString(replacementPublic)
	payload, err := CanonicalWitnessTrustManifestPayload(signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed.WitnessOwnerSignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(keys.witnessPrivate, payload),
	)
	// Principal B controls the witness, but cannot silently replace the trust
	// target without Principal A's authorization.
	if _, _, err := root.Verify(context.Background(), signed); err == nil ||
		!strings.Contains(err.Error(), "workload principal signature verification failed") {
		t.Fatalf("witness-only rotation = %v, want workload-principal rejection", err)
	}
}

func TestTwoPrincipalWitnessTrustManifestRejectsTrustEpochRollback(t *testing.T) {
	keys := generateTwoPrincipalKeys(t)
	root := newTwoPrincipalRoot(t, keys, 9)
	signed := signTwoPrincipalManifest(t, baseWitnessTrustManifest(keys, 8), keys)

	if _, _, err := root.Verify(context.Background(), signed); err == nil ||
		!strings.Contains(err.Error(), "trust epoch rollback") {
		t.Fatalf("stale trust epoch = %v, want rollback rejection", err)
	}
}

func TestTwoPrincipalWitnessTrustManifestRejectsUnsignedRuntimeKeySubstitution(t *testing.T) {
	keys := generateTwoPrincipalKeys(t)
	root := newTwoPrincipalRoot(t, keys, 2)
	signed := signTwoPrincipalManifest(t, baseWitnessTrustManifest(keys, 2), keys)

	replacementPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed.Manifest.WitnessRuntimeKey = base64.StdEncoding.EncodeToString(replacementPublic)

	if _, _, err := root.Verify(context.Background(), signed); err == nil {
		t.Fatal("unsigned runtime-key substitution unexpectedly accepted")
	}
}
