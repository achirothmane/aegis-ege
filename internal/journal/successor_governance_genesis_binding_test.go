package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestGenesisSuccessorGovernanceBindingPinsExactAuthority(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{
		"enrollment_successor_governance": EnrollmentSuccessorGovernancePolicy{
			Protocol:        EnrollmentSuccessorGovernancePolicyVersion,
			AuthorityID:     "successor-governance-a",
			PublicKeyBase64: base64.StdEncoding.EncodeToString(pub),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopeHash := sha256Digest(envelope)
	binding, err := ParseGenesisEnrollmentSuccessorGovernanceBinding(
		envelope,
		envelopeHash,
		13,
		sha256Digest([]byte("binding-test-manifest")),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := binding.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) ||
		binding.GenesisEpoch() != 13 ||
		binding.CapabilityEnvelopeHash() != envelopeHash ||
		binding.PolicyHash() == "" ||
		binding.AuthorityID() != "successor-governance-a" {
		t.Fatalf("unexpected binding: epoch=%d envelope=%s policy=%s authority=%s",
			binding.GenesisEpoch(),
			binding.CapabilityEnvelopeHash(),
			binding.PolicyHash(),
			binding.AuthorityID(),
		)
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	substituted, err := json.Marshal(map[string]any{
		"enrollment_successor_governance": EnrollmentSuccessorGovernancePolicy{
			Protocol:        EnrollmentSuccessorGovernancePolicyVersion,
			AuthorityID:     "successor-governance-a",
			PublicKeyBase64: base64.StdEncoding.EncodeToString(otherPub),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenesisEnrollmentSuccessorGovernanceBinding(
		substituted,
		envelopeHash,
		13,
		sha256Digest([]byte("binding-test-manifest")),
	); err == nil || !strings.Contains(err.Error(), "capability envelope hash mismatch") {
		t.Fatalf("substituted governance authority = %v, want exact Genesis envelope rejection", err)
	}
}

func TestGenesisSuccessorGovernanceBindingRejectsMalformedPolicy(t *testing.T) {
	envelope := []byte(`{"enrollment_successor_governance":{"protocol":"aegis-ege/enrollment-successor-governance-policy/v1","authority_id":"a","public_key_base64":"not-base64"}}`)
	if _, err := ParseGenesisEnrollmentSuccessorGovernanceBinding(
		envelope,
		sha256Digest(envelope),
		1,
		sha256Digest([]byte("binding-test-manifest")),
	); err == nil {
		t.Fatal("malformed successor governance public key was accepted")
	}
}
