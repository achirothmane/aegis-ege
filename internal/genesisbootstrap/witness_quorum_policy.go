package genesisbootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/ucarion/jcs"

	"github.com/achirothmane/easl/genesis"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const WitnessQuorumMembershipPolicyVersion = "aegis.ege/witness-quorum-membership/v1"

type WitnessQuorumMemberPolicy struct {
	ID                   string `json:"id"`
	Endpoint             string `json:"endpoint"`
	WitnessKeyID         string `json:"witness_key_id"`
	WitnessPublicKeyHash string `json:"witness_public_key_hash"`
}

type WitnessQuorumMembershipPolicy struct {
	Version                    string                      `json:"version"`
	GenesisManifestPayloadHash string                      `json:"genesis_manifest_payload_hash"`
	GenesisEpoch               uint64                      `json:"genesis_epoch"`
	MembershipEpoch            uint64                      `json:"membership_epoch"`
	Threshold                  int                         `json:"threshold"`
	Members                    []WitnessQuorumMemberPolicy `json:"members"`
}

type SignedWitnessQuorumMembershipPolicy struct {
	Policy      WitnessQuorumMembershipPolicy `json:"policy"`
	SignerKeyID string                        `json:"signer_key_id"`
	Signature   string                        `json:"signature"`
}

func SignWitnessQuorumMembershipPolicy(
	policy WitnessQuorumMembershipPolicy,
	privateKey ed25519.PrivateKey,
) (SignedWitnessQuorumMembershipPolicy, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWitnessQuorumMembershipPolicy{}, errors.New("invalid Genesis quorum-policy signing key")
	}
	normalized, err := normalizeWitnessQuorumMembershipPolicy(policy)
	if err != nil {
		return SignedWitnessQuorumMembershipPolicy{}, err
	}
	payload, err := canonicalWitnessQuorumMembershipPolicyPayload(normalized)
	if err != nil {
		return SignedWitnessQuorumMembershipPolicy{}, err
	}
	keyID, err := kernelfabric.BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWitnessQuorumMembershipPolicy{}, err
	}
	return SignedWitnessQuorumMembershipPolicy{
		Policy:      normalized,
		SignerKeyID: keyID,
		Signature:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifyGenesisBoundWitnessQuorumMembershipPolicy(
	ctx context.Context,
	manifest genesis.Manifest,
	signed SignedWitnessQuorumMembershipPolicy,
	manifestSignerPublicKey ed25519.PublicKey,
	minimumMembershipEpoch uint64,
) (WitnessQuorumMembershipPolicy, error) {
	if err := ctx.Err(); err != nil {
		return WitnessQuorumMembershipPolicy{}, err
	}
	if len(manifestSignerPublicKey) != ed25519.PublicKeySize {
		return WitnessQuorumMembershipPolicy{}, errors.New("invalid Genesis manifest signer public key")
	}
	policy, err := normalizeWitnessQuorumMembershipPolicy(signed.Policy)
	if err != nil {
		return WitnessQuorumMembershipPolicy{}, err
	}
	if policy.MembershipEpoch < minimumMembershipEpoch {
		return WitnessQuorumMembershipPolicy{}, fmt.Errorf(
			"witness quorum membership epoch rollback: got %d minimum %d",
			policy.MembershipEpoch,
			minimumMembershipEpoch,
		)
	}
	manifestPayloadHash, err := ManifestPayloadHash(manifest)
	if err != nil {
		return WitnessQuorumMembershipPolicy{}, err
	}
	if policy.GenesisManifestPayloadHash != manifestPayloadHash {
		return WitnessQuorumMembershipPolicy{}, fmt.Errorf(
			"witness quorum policy Genesis binding mismatch: got %s want %s",
			policy.GenesisManifestPayloadHash,
			manifestPayloadHash,
		)
	}
	if policy.GenesisEpoch != manifest.GenesisEpoch {
		return WitnessQuorumMembershipPolicy{}, fmt.Errorf(
			"witness quorum policy Genesis epoch mismatch: got %d want %d",
			policy.GenesisEpoch,
			manifest.GenesisEpoch,
		)
	}
	expectedSignerKeyID, err := kernelfabric.BootstrapKeyID(manifestSignerPublicKey)
	if err != nil {
		return WitnessQuorumMembershipPolicy{}, err
	}
	if signed.SignerKeyID != expectedSignerKeyID {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy signer does not match trusted Genesis manifest authority")
	}
	if manifest.Authenticity.SignerKeyID != expectedSignerKeyID {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy authority does not match Genesis manifest signer")
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return WitnessQuorumMembershipPolicy{}, errors.New("invalid witness quorum policy signature")
	}
	payload, err := canonicalWitnessQuorumMembershipPolicyPayload(policy)
	if err != nil {
		return WitnessQuorumMembershipPolicy{}, err
	}
	if !ed25519.Verify(manifestSignerPublicKey, payload, signature) {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy signature verification failed")
	}
	return policy, nil
}

func BuildGenesisBoundQuorumHeadStore(
	ctx context.Context,
	manifest genesis.Manifest,
	signed SignedWitnessQuorumMembershipPolicy,
	manifestSignerPublicKey ed25519.PublicKey,
	minimumMembershipEpoch uint64,
	members map[string]*journal.RemoteHeadStore,
) (*journal.QuorumHeadStore, error) {
	policy, err := VerifyGenesisBoundWitnessQuorumMembershipPolicy(
		ctx,
		manifest,
		signed,
		manifestSignerPublicKey,
		minimumMembershipEpoch,
	)
	if err != nil {
		return nil, err
	}
	if len(members) != len(policy.Members) {
		return nil, fmt.Errorf(
			"runtime witness membership cardinality mismatch: got %d want %d",
			len(members),
			len(policy.Members),
		)
	}

	quorumMembers := make([]journal.QuorumHeadMember, 0, len(policy.Members))
	for _, expected := range policy.Members {
		store, ok := members[expected.ID]
		if !ok || store == nil {
			return nil, fmt.Errorf("required witness %q is missing", expected.ID)
		}
		actual, err := store.TrustIdentity()
		if err != nil {
			return nil, fmt.Errorf("read witness %q trust identity: %w", expected.ID, err)
		}
		if actual.Endpoint != expected.Endpoint ||
			actual.WitnessKeyID != expected.WitnessKeyID ||
			actual.WitnessPublicKeyHash != expected.WitnessPublicKeyHash {
			return nil, fmt.Errorf(
				"witness %q trust identity substitution detected",
				expected.ID,
			)
		}
		quorumMembers = append(quorumMembers, journal.QuorumHeadMember{
			ID:    expected.ID,
			Store: store,
		})
	}
	return journal.NewQuorumHeadStore(quorumMembers, policy.Threshold)
}

func normalizeWitnessQuorumMembershipPolicy(
	policy WitnessQuorumMembershipPolicy,
) (WitnessQuorumMembershipPolicy, error) {
	if policy.Version != WitnessQuorumMembershipPolicyVersion {
		return WitnessQuorumMembershipPolicy{}, fmt.Errorf(
			"unsupported witness quorum membership policy version %q",
			policy.Version,
		)
	}
	if !strings.HasPrefix(policy.GenesisManifestPayloadHash, "sha256:") ||
		len(policy.GenesisManifestPayloadHash) != len("sha256:")+64 {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy requires a sha256 Genesis manifest payload hash")
	}
	if policy.GenesisEpoch > maxExactJSONInteger || policy.MembershipEpoch > maxExactJSONInteger {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy epoch exceeds exact JSON integer profile")
	}
	if len(policy.Members) < 3 {
		return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum policy requires at least three members")
	}
	if policy.Threshold <= len(policy.Members)/2 || policy.Threshold > len(policy.Members) {
		return WitnessQuorumMembershipPolicy{}, fmt.Errorf(
			"witness quorum threshold must be a strict majority: members=%d threshold=%d",
			len(policy.Members),
			policy.Threshold,
		)
	}

	seen := make(map[string]struct{}, len(policy.Members))
	members := append([]WitnessQuorumMemberPolicy(nil), policy.Members...)
	for i := range members {
		member := &members[i]
		member.ID = strings.TrimSpace(member.ID)
		member.Endpoint = strings.TrimRight(strings.TrimSpace(member.Endpoint), "/")
		member.WitnessKeyID = strings.TrimSpace(member.WitnessKeyID)
		member.WitnessPublicKeyHash = strings.TrimSpace(member.WitnessPublicKeyHash)
		if member.ID == "" {
			return WitnessQuorumMembershipPolicy{}, errors.New("witness quorum member id is required")
		}
		if _, exists := seen[member.ID]; exists {
			return WitnessQuorumMembershipPolicy{}, fmt.Errorf("duplicate witness quorum member %q", member.ID)
		}
		seen[member.ID] = struct{}{}
		parsed, err := url.Parse(member.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return WitnessQuorumMembershipPolicy{}, fmt.Errorf("witness %q endpoint must use HTTPS", member.ID)
		}
		if member.WitnessKeyID == "" {
			return WitnessQuorumMembershipPolicy{}, fmt.Errorf("witness %q key id is required", member.ID)
		}
		if !strings.HasPrefix(member.WitnessPublicKeyHash, "sha256:") ||
			len(member.WitnessPublicKeyHash) != len("sha256:")+64 {
			return WitnessQuorumMembershipPolicy{}, fmt.Errorf("witness %q public key hash must be sha256", member.ID)
		}
	}
	sort.Slice(members, func(i, j int) bool {
		return members[i].ID < members[j].ID
	})
	policy.Members = members
	return policy, nil
}

func canonicalWitnessQuorumMembershipPolicyPayload(
	policy WitnessQuorumMembershipPolicy,
) ([]byte, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}
