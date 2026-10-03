package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func genesisEnvelopeDigestForTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func externalWitnessGenesisEnvelopeForTest(
	t *testing.T,
	authorityPublic ed25519.PublicKey,
	requiredWitnessID string,
	minimumProfileEpoch uint64,
	minimumPolicyEpoch uint64,
) []byte {
	t.Helper()
	keyID, err := BootstrapKeyID(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{
		"unrelated_capability": map[string]any{
			"enabled": true,
		},
		"external_recovery_witness": ExternalRecoveryWitnessGenesisPolicy{
			Protocol:                  ExternalRecoveryWitnessGenesisPolicyVersion,
			ProfileAuthorityKeyID:     keyID,
			ProfileAuthorityPublicKey: base64.StdEncoding.EncodeToString(authorityPublic),
			RequiredWitnessID:         requiredWitnessID,
			MinimumProfileEpoch:       minimumProfileEpoch,
			MinimumPolicyEpoch:        minimumPolicyEpoch,
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGenesisExternalRecoveryWitnessBindingAdmitsOnlyPinnedAuthorityAndIdentity(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 8)
	profileAuthorityPublic, profileAuthorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const witnessID = "external/recovery-witness-b"
	envelope := externalWitnessGenesisEnvelopeForTest(
		t,
		profileAuthorityPublic,
		witnessID,
		12,
		21,
	)
	binding, err := ParseGenesisExternalRecoveryWitnessBinding(
		envelope,
		genesisEnvelopeDigestForTest(envelope),
	)
	if err != nil {
		t.Fatal(err)
	}

	tlsHash := "sha256:" + strings.Repeat("a", 64)
	policyHash := "sha256:" + strings.Repeat("b", 64)
	signed, err := SignExternalRecoveryWitnessProfile(
		ExternalRecoveryWitnessProfile{
			Version:              ExternalRecoveryWitnessProfileVersion,
			ProfileEpoch:         12,
			WitnessID:            witnessID,
			WitnessKeyID:         trust.signedManifest.Manifest.WitnessKeyID,
			Endpoint:             "https://witness.example",
			TLSTrustAnchorSHA256: tlsHash,
			PolicyEpoch:          21,
			PolicyHash:           policyHash,
		},
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := binding.VerifyProfile(signed, trust.root)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Profile().WitnessID != witnessID {
		t.Fatalf("verified witness id=%q want=%q", verified.Profile().WitnessID, witnessID)
	}

	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPublic
	wrongAuthorityProfile, err := SignExternalRecoveryWitnessProfile(
		signed.Profile,
		otherPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.VerifyProfile(wrongAuthorityProfile, trust.root); err == nil {
		t.Fatal("profile signed by non-Genesis authority was accepted")
	}

	wrongIdentity := signed.Profile
	wrongIdentity.WitnessID = "external/recovery-witness-c"
	wrongIdentitySigned, err := SignExternalRecoveryWitnessProfile(
		wrongIdentity,
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.VerifyProfile(wrongIdentitySigned, trust.root); err == nil {
		t.Fatal("profile naming witness outside Genesis identity was accepted")
	}
}

func TestGenesisExternalRecoveryWitnessBindingRejectsProfileAndPolicyRollback(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 9)
	profileAuthorityPublic, profileAuthorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := externalWitnessGenesisEnvelopeForTest(
		t,
		profileAuthorityPublic,
		"external/recovery-witness-b",
		50,
		70,
	)
	binding, err := ParseGenesisExternalRecoveryWitnessBinding(
		envelope,
		genesisEnvelopeDigestForTest(envelope),
	)
	if err != nil {
		t.Fatal(err)
	}
	base := ExternalRecoveryWitnessProfile{
		Version:              ExternalRecoveryWitnessProfileVersion,
		ProfileEpoch:         50,
		WitnessID:            "external/recovery-witness-b",
		WitnessKeyID:         trust.signedManifest.Manifest.WitnessKeyID,
		Endpoint:             "https://witness.example",
		TLSTrustAnchorSHA256: "sha256:" + strings.Repeat("c", 64),
		PolicyEpoch:          70,
		PolicyHash:           "sha256:" + strings.Repeat("d", 64),
	}

	profileRollback := base
	profileRollback.ProfileEpoch = 49
	signedProfileRollback, err := SignExternalRecoveryWitnessProfile(
		profileRollback,
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.VerifyProfile(signedProfileRollback, trust.root); err == nil {
		t.Fatal("profile epoch below Genesis floor was accepted")
	}

	policyRollback := base
	policyRollback.PolicyEpoch = 69
	signedPolicyRollback, err := SignExternalRecoveryWitnessProfile(
		policyRollback,
		profileAuthorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.VerifyProfile(signedPolicyRollback, trust.root); err == nil {
		t.Fatal("policy epoch below Genesis floor was accepted")
	}
}

func TestGenesisExternalRecoveryWitnessBindingRejectsEnvelopeMutationWithoutGenesisUpdate(t *testing.T) {
	profileAuthorityPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := externalWitnessGenesisEnvelopeForTest(
		t,
		profileAuthorityPublic,
		"external/recovery-witness-b",
		30,
		40,
	)
	genesisHash := genesisEnvelopeDigestForTest(envelope)

	var decoded map[string]any
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	policy := decoded["external_recovery_witness"].(map[string]any)
	policy["minimum_profile_epoch"] = float64(1)
	policy["minimum_policy_epoch"] = float64(1)
	mutated, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenesisExternalRecoveryWitnessBinding(
		mutated,
		genesisHash,
	); err == nil {
		t.Fatal("lowered epoch floors were accepted without a new Genesis envelope hash")
	}
}

func TestGenesisExternalRecoveryWitnessBindingRejectsSignerKeyIDMismatchAndUnknownPolicyFields(t *testing.T) {
	profileAuthorityPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := externalWitnessGenesisEnvelopeForTest(
		t,
		profileAuthorityPublic,
		"external/recovery-witness-b",
		1,
		1,
	)
	var decoded map[string]any
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	policy := decoded["external_recovery_witness"].(map[string]any)
	policy["profile_authority_key_id"] = "sha256:" + strings.Repeat("0", 64)
	mismatched, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenesisExternalRecoveryWitnessBinding(
		mismatched,
		genesisEnvelopeDigestForTest(mismatched),
	); err == nil {
		t.Fatal("profile authority key-id mismatch was accepted")
	}

	delete(policy, "profile_authority_key_id")
	keyID, err := BootstrapKeyID(profileAuthorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	policy["profile_authority_key_id"] = keyID
	policy["silent_override"] = true
	unknown, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenesisExternalRecoveryWitnessBinding(
		unknown,
		genesisEnvelopeDigestForTest(unknown),
	); err == nil {
		t.Fatal("unknown Genesis external witness policy field was accepted")
	}
}


func TestGenesisExternalRecoveryWitnessBindingRejectsCollapsedRecoveryRoles(t *testing.T) {
	trust := newTaintRecoveryTrustFixture(t, 10)
	cases := []struct {
		name       string
		publicKey  ed25519.PublicKey
		privateKey ed25519.PrivateKey
	}{
		{
			name:       "authority-a",
			publicKey:  trust.authorityPublic,
			privateKey: trust.authorityPrivate,
		},
		{
			name:       "witness-b",
			publicKey:  trust.witnessPublic,
			privateKey: trust.witnessPrivate,
		},
		{
			name:       "recovery-trust-signer",
			publicKey:  trust.signerPublic,
			privateKey: trust.signerPrivate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := externalWitnessGenesisEnvelopeForTest(
				t,
				tc.publicKey,
				"external/recovery-witness-b",
				1,
				1,
			)
			binding, err := ParseGenesisExternalRecoveryWitnessBinding(
				envelope,
				genesisEnvelopeDigestForTest(envelope),
			)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := SignExternalRecoveryWitnessProfile(
				ExternalRecoveryWitnessProfile{
					Version:              ExternalRecoveryWitnessProfileVersion,
					ProfileEpoch:         1,
					WitnessID:            "external/recovery-witness-b",
					WitnessKeyID:         trust.signedManifest.Manifest.WitnessKeyID,
					Endpoint:             "https://witness.example",
					TLSTrustAnchorSHA256: "sha256:" + strings.Repeat("e", 64),
					PolicyEpoch:          1,
					PolicyHash:           "sha256:" + strings.Repeat("f", 64),
				},
				tc.privateKey,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := binding.VerifyProfile(signed, trust.root); err == nil {
				t.Fatalf("Genesis-bound profile authority reused %s key", tc.name)
			}
		})
	}
}
