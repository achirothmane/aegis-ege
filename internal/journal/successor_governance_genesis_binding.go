package journal

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ucarion/jcs"
)

const EnrollmentSuccessorGovernancePolicyVersion = "aegis-ege/enrollment-successor-governance-policy/v1"

type EnrollmentSuccessorGovernancePolicy struct {
	Protocol        string `json:"protocol"`
	AuthorityID     string `json:"authority_id"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type GenesisEnrollmentSuccessorGovernanceBinding struct {
	genesisEpoch           uint64
	genesisManifestHash    string
	capabilityEnvelopeHash string
	policyHash             string
	authorityID            string
	publicKey              ed25519.PublicKey
}

type enrollmentSuccessorGovernanceCapabilityEnvelope struct {
	EnrollmentSuccessorGovernance json.RawMessage `json:"enrollment_successor_governance"`
}

// ParseGenesisEnrollmentSuccessorGovernanceBinding derives successor-governance
// trust only from the exact capability-envelope bytes pinned by a verified
// Genesis state. A runtime public key is never accepted as configuration.
func ParseGenesisEnrollmentSuccessorGovernanceBinding(
	capabilityEnvelope []byte,
	genesisCapabilityEnvelopeHash string,
	genesisEpoch uint64,
	genesisManifestHash string,
) (GenesisEnrollmentSuccessorGovernanceBinding, error) {
	if genesisEpoch == 0 {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New("Genesis epoch must be non-zero")
	}
	if !validSHA256Digest(genesisManifestHash) {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New("Genesis manifest hash must be sha256")
	}
	if !validSHA256Digest(genesisCapabilityEnvelopeHash) {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New("Genesis capability envelope hash must be a sha256 digest")
	}
	actualEnvelopeHash := sha256Digest(capabilityEnvelope)
	if actualEnvelopeHash != genesisCapabilityEnvelopeHash {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, fmt.Errorf(
			"capability envelope hash mismatch: got %s want Genesis %s",
			actualEnvelopeHash,
			genesisCapabilityEnvelopeHash,
		)
	}

	var envelope enrollmentSuccessorGovernanceCapabilityEnvelope
	if err := decodeSingleJSON(capabilityEnvelope, &envelope, false); err != nil {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, fmt.Errorf("decode capability envelope: %w", err)
	}
	if len(envelope.EnrollmentSuccessorGovernance) == 0 ||
		string(envelope.EnrollmentSuccessorGovernance) == "null" {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New(
			"capability envelope is missing enrollment_successor_governance",
		)
	}

	var policy EnrollmentSuccessorGovernancePolicy
	if err := decodeSingleJSON(envelope.EnrollmentSuccessorGovernance, &policy, true); err != nil {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, fmt.Errorf(
			"decode enrollment successor governance policy: %w",
			err,
		)
	}
	policy.Protocol = strings.TrimSpace(policy.Protocol)
	policy.AuthorityID = strings.TrimSpace(policy.AuthorityID)
	policy.PublicKeyBase64 = strings.TrimSpace(policy.PublicKeyBase64)
	if policy.Protocol != EnrollmentSuccessorGovernancePolicyVersion {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, fmt.Errorf(
			"enrollment successor governance protocol mismatch: got %q want %q",
			policy.Protocol,
			EnrollmentSuccessorGovernancePolicyVersion,
		)
	}
	if policy.AuthorityID == "" {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New(
			"enrollment successor governance authority_id is required",
		)
	}
	rawKey, err := base64.StdEncoding.DecodeString(policy.PublicKeyBase64)
	if err != nil || len(rawKey) != ed25519.PublicKeySize {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, errors.New(
			"enrollment successor governance public key must be base64 Ed25519",
		)
	}
	policy.PublicKeyBase64 = base64.StdEncoding.EncodeToString(rawKey)

	rawPolicy, err := json.Marshal(policy)
	if err != nil {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, err
	}
	var value any
	if err := json.Unmarshal(rawPolicy, &value); err != nil {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return GenesisEnrollmentSuccessorGovernanceBinding{}, err
	}
	policyHash := sha256Digest([]byte(canonical))

	return GenesisEnrollmentSuccessorGovernanceBinding{
		genesisEpoch:           genesisEpoch,
		genesisManifestHash:    genesisManifestHash,
		capabilityEnvelopeHash: actualEnvelopeHash,
		policyHash:             policyHash,
		authorityID:            policy.AuthorityID,
		publicKey:              append(ed25519.PublicKey(nil), rawKey...),
	}, nil
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) GenesisEpoch() uint64 {
	return b.genesisEpoch
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) GenesisManifestHash() string {
	return b.genesisManifestHash
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) CapabilityEnvelopeHash() string {
	return b.capabilityEnvelopeHash
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) PolicyHash() string {
	return b.policyHash
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) AuthorityID() string {
	return b.authorityID
}

func (b GenesisEnrollmentSuccessorGovernanceBinding) PublicKey() (ed25519.PublicKey, error) {
	if b.genesisEpoch == 0 ||
		!validSHA256Digest(b.genesisManifestHash) ||
		!validSHA256Digest(b.capabilityEnvelopeHash) ||
		!validSHA256Digest(b.policyHash) ||
		strings.TrimSpace(b.authorityID) == "" ||
		len(b.publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("valid Genesis enrollment successor governance binding is required")
	}
	return append(ed25519.PublicKey(nil), b.publicKey...), nil
}
