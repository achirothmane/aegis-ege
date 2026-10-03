package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ucarion/jcs"
)

const QuorumTrustPolicyVersion = "aegis-ege/quorum-trust-policy/v1"

type QuorumTrustPolicyMember struct {
	ID                string `json:"id"`
	TrustManifestHash string `json:"trust_manifest_hash"`
}

type QuorumTrustPolicy struct {
	Protocol  string                    `json:"protocol"`
	Threshold int                       `json:"threshold"`
	Members   []QuorumTrustPolicyMember `json:"members"`
}

type GenesisQuorumBinding struct {
	capabilityEnvelopeHash string
	policyHash             string
	threshold              int
	members                map[string]string
}

type quorumCapabilityEnvelope struct {
	ExternalWitnessQuorum json.RawMessage `json:"external_witness_quorum"`
}

// ParseGenesisQuorumBinding derives the only quorum configuration accepted by
// NewQuorumHeadStore. genesisCapabilityEnvelopeHash must come from an already
// verified Genesis manifest. The raw capability-envelope bytes are hashed
// exactly as Genesis hashes the artifact; changing the witness set, threshold,
// or any other envelope byte therefore requires a new governed Genesis state.
func ParseGenesisQuorumBinding(
	capabilityEnvelope []byte,
	genesisCapabilityEnvelopeHash string,
) (GenesisQuorumBinding, error) {
	if !validSHA256Digest(genesisCapabilityEnvelopeHash) {
		return GenesisQuorumBinding{}, errors.New("Genesis capability envelope hash must be a sha256 digest")
	}
	actualEnvelopeHash := sha256Digest(capabilityEnvelope)
	if actualEnvelopeHash != genesisCapabilityEnvelopeHash {
		return GenesisQuorumBinding{}, fmt.Errorf(
			"capability envelope hash mismatch: got %s want Genesis %s",
			actualEnvelopeHash,
			genesisCapabilityEnvelopeHash,
		)
	}

	var envelope quorumCapabilityEnvelope
	if err := decodeSingleJSON(capabilityEnvelope, &envelope, false); err != nil {
		return GenesisQuorumBinding{}, fmt.Errorf("decode capability envelope: %w", err)
	}
	if len(envelope.ExternalWitnessQuorum) == 0 ||
		string(envelope.ExternalWitnessQuorum) == "null" {
		return GenesisQuorumBinding{}, errors.New("capability envelope is missing external_witness_quorum")
	}

	var policy QuorumTrustPolicy
	if err := decodeSingleJSON(envelope.ExternalWitnessQuorum, &policy, true); err != nil {
		return GenesisQuorumBinding{}, fmt.Errorf("decode external witness quorum policy: %w", err)
	}
	normalized, err := normalizeQuorumTrustPolicy(policy)
	if err != nil {
		return GenesisQuorumBinding{}, err
	}
	policyHash, err := quorumTrustPolicyDigest(normalized)
	if err != nil {
		return GenesisQuorumBinding{}, err
	}
	members := make(map[string]string, len(normalized.Members))
	for _, member := range normalized.Members {
		members[member.ID] = member.TrustManifestHash
	}
	return GenesisQuorumBinding{
		capabilityEnvelopeHash: actualEnvelopeHash,
		policyHash:             policyHash,
		threshold:              normalized.Threshold,
		members:                members,
	}, nil
}

func WitnessTrustManifestDigest(manifest WitnessTrustManifest) (string, error) {
	payload, err := CanonicalWitnessTrustManifestPayload(manifest)
	if err != nil {
		return "", err
	}
	return sha256Digest(payload), nil
}

func normalizeQuorumTrustPolicy(policy QuorumTrustPolicy) (QuorumTrustPolicy, error) {
	if policy.Protocol != QuorumTrustPolicyVersion {
		return QuorumTrustPolicy{}, fmt.Errorf(
			"external witness quorum protocol mismatch: got %q want %q",
			policy.Protocol,
			QuorumTrustPolicyVersion,
		)
	}
	if len(policy.Members) == 0 {
		return QuorumTrustPolicy{}, errors.New("external witness quorum requires members")
	}
	if policy.Threshold <= len(policy.Members)/2 || policy.Threshold > len(policy.Members) {
		return QuorumTrustPolicy{}, fmt.Errorf(
			"external witness quorum threshold must be a strict majority: members=%d threshold=%d",
			len(policy.Members),
			policy.Threshold,
		)
	}
	seen := make(map[string]struct{}, len(policy.Members))
	members := make([]QuorumTrustPolicyMember, 0, len(policy.Members))
	for _, member := range policy.Members {
		member.ID = strings.TrimSpace(member.ID)
		member.TrustManifestHash = strings.TrimSpace(member.TrustManifestHash)
		if member.ID == "" {
			return QuorumTrustPolicy{}, errors.New("external witness quorum member id is required")
		}
		if !validSHA256Digest(member.TrustManifestHash) {
			return QuorumTrustPolicy{}, fmt.Errorf(
				"external witness quorum member %q trust manifest hash must be sha256",
				member.ID,
			)
		}
		if _, ok := seen[member.ID]; ok {
			return QuorumTrustPolicy{}, fmt.Errorf(
				"duplicate external witness quorum member id %q",
				member.ID,
			)
		}
		seen[member.ID] = struct{}{}
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	policy.Members = members
	return policy, nil
}

func quorumTrustPolicyDigest(policy QuorumTrustPolicy) (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("encode quorum trust policy: %w", err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("decode quorum trust policy for canonicalization: %w", err)
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize quorum trust policy: %w", err)
	}
	return sha256Digest([]byte(canonical)), nil
}

func decodeSingleJSON(data []byte, dst any, disallowUnknown bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func sha256Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
