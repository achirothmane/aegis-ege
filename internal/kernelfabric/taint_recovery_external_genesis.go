package kernelfabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const ExternalRecoveryWitnessGenesisPolicyVersion = "aegis.ege/external-recovery-witness-genesis/v1"

type ExternalRecoveryWitnessGenesisPolicy struct {
	Protocol                  string `json:"protocol"`
	ProfileAuthorityKeyID     string `json:"profile_authority_key_id"`
	ProfileAuthorityPublicKey string `json:"profile_authority_public_key"`
	RequiredWitnessID         string `json:"required_witness_id"`
	TLSServerName             string `json:"tls_server_name"`
	MinimumProfileEpoch       uint64 `json:"minimum_profile_epoch"`
	MinimumPolicyEpoch        uint64 `json:"minimum_policy_epoch"`
}

type GenesisExternalRecoveryWitnessBinding struct {
	capabilityEnvelopeHash string
	policy                 ExternalRecoveryWitnessGenesisPolicy
	profileAuthorityKey    ed25519.PublicKey
}

type externalRecoveryCapabilityEnvelope struct {
	ExternalRecoveryWitness json.RawMessage `json:"external_recovery_witness"`
}

// ParseGenesisExternalRecoveryWitnessBinding derives the profile-authority root
// and anti-rollback floors exclusively from a capability envelope whose exact
// byte hash has already been authenticated by Genesis.
//
// The outer envelope intentionally permits unrelated capability fields. The
// external_recovery_witness object itself is strict and rejects unknown fields.
func ParseGenesisExternalRecoveryWitnessBinding(
	capabilityEnvelope []byte,
	genesisCapabilityEnvelopeHash string,
) (GenesisExternalRecoveryWitnessBinding, error) {
	if _, err := ParseSHA256Digest(genesisCapabilityEnvelopeHash); err != nil {
		return GenesisExternalRecoveryWitnessBinding{}, errors.New(
			"Genesis capability envelope hash must be a sha256 digest",
		)
	}
	sum := sha256.Sum256(capabilityEnvelope)
	actualHash := "sha256:" + hex.EncodeToString(sum[:])
	if actualHash != genesisCapabilityEnvelopeHash {
		return GenesisExternalRecoveryWitnessBinding{}, fmt.Errorf(
			"capability envelope hash mismatch: got %s want Genesis %s",
			actualHash,
			genesisCapabilityEnvelopeHash,
		)
	}

	var envelope externalRecoveryCapabilityEnvelope
	if err := decodeSingleExternalWitnessJSON(capabilityEnvelope, &envelope, false); err != nil {
		return GenesisExternalRecoveryWitnessBinding{}, fmt.Errorf(
			"decode capability envelope: %w",
			err,
		)
	}
	if len(envelope.ExternalRecoveryWitness) == 0 ||
		string(envelope.ExternalRecoveryWitness) == "null" {
		return GenesisExternalRecoveryWitnessBinding{}, errors.New(
			"capability envelope is missing external_recovery_witness",
		)
	}

	var policy ExternalRecoveryWitnessGenesisPolicy
	if err := decodeSingleExternalWitnessJSON(
		envelope.ExternalRecoveryWitness,
		&policy,
		true,
	); err != nil {
		return GenesisExternalRecoveryWitnessBinding{}, fmt.Errorf(
			"decode external recovery witness Genesis policy: %w",
			err,
		)
	}
	normalized, authorityKey, err := normalizeExternalRecoveryWitnessGenesisPolicy(policy)
	if err != nil {
		return GenesisExternalRecoveryWitnessBinding{}, err
	}
	return GenesisExternalRecoveryWitnessBinding{
		capabilityEnvelopeHash: actualHash,
		policy:                 normalized,
		profileAuthorityKey:    authorityKey,
	}, nil
}

func (b GenesisExternalRecoveryWitnessBinding) VerifyProfile(
	signed SignedExternalRecoveryWitnessProfile,
	trustRoot *TaintRecoveryTrustRoot,
) (*VerifiedExternalRecoveryWitnessProfile, error) {
	if len(b.profileAuthorityKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"%w: Genesis external witness binding is unavailable",
			ErrTaintRecoveryAuthorization,
		)
	}
	profileAuthorityKeyID := b.policy.ProfileAuthorityKeyID
	if profileAuthorityKeyID == trustRoot.manifest.AuthorityKeyID ||
		profileAuthorityKeyID == trustRoot.manifest.WitnessKeyID ||
		profileAuthorityKeyID == trustRoot.signerKeyID {
		return nil, fmt.Errorf(
			"%w: external witness profile authority collapses a pinned recovery role",
			ErrTaintRecoveryAuthorization,
		)
	}
	profile, err := VerifyExternalRecoveryWitnessProfile(
		signed,
		b.profileAuthorityKey,
		trustRoot,
		b.policy.MinimumProfileEpoch,
		b.policy.MinimumPolicyEpoch,
	)
	if err != nil {
		return nil, err
	}
	if profile.Profile().WitnessID != b.policy.RequiredWitnessID {
		return nil, fmt.Errorf(
			"%w: external witness identity is not admitted by Genesis",
			ErrTaintRecoveryAuthorization,
		)
	}
	return profile, nil
}

func (b GenesisExternalRecoveryWitnessBinding) Policy() ExternalRecoveryWitnessGenesisPolicy {
	return b.policy
}

func (b GenesisExternalRecoveryWitnessBinding) CapabilityEnvelopeHash() string {
	return b.capabilityEnvelopeHash
}

func (b GenesisExternalRecoveryWitnessBinding) NewRemoteWitness(
	signed SignedExternalRecoveryWitnessProfile,
	trustRoot *TaintRecoveryTrustRoot,
	tlsTrustAnchorPEM []byte,
	timeout time.Duration,
) (*RemoteTaintRecoveryWitness, *VerifiedExternalRecoveryWitnessProfile, error) {
	profile, err := b.VerifyProfile(signed, trustRoot)
	if err != nil {
		return nil, nil, err
	}
	if timeout <= 0 {
		return nil, nil, fmt.Errorf(
			"%w: external witness HTTP timeout must be positive",
			ErrTaintRecoveryAuthorization,
		)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(tlsTrustAnchorPEM); !ok {
		return nil, nil, fmt.Errorf(
			"%w: external witness TLS trust anchor is invalid",
			ErrTaintRecoveryAuthorization,
		)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
				ServerName: b.policy.TLSServerName,
			},
		},
		Timeout: timeout,
	}
	remote, err := NewProfiledRemoteTaintRecoveryWitness(
		profile.Profile().Endpoint,
		trustRoot,
		profile,
		tlsTrustAnchorPEM,
		client,
	)
	if err != nil {
		return nil, nil, err
	}
	return remote, profile, nil
}

func (b GenesisExternalRecoveryWitnessBinding) VerifyMountedTLSCertificate(
	certificatePEM []byte,
	profile *VerifiedExternalRecoveryWitnessProfile,
) error {
	if profile == nil {
		return fmt.Errorf(
			"%w: external witness profile is unavailable",
			ErrTaintRecoveryAuthorization,
		)
	}
	digest, err := TLSCertificatePEMSHA256(certificatePEM)
	if err != nil {
		return err
	}
	if digest != profile.Profile().TLSTrustAnchorSHA256 {
		return fmt.Errorf(
			"%w: mounted TLS certificate differs from external witness profile",
			ErrTaintRecoveryAuthorization,
		)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf(
			"%w: mounted TLS certificate PEM is invalid",
			ErrTaintRecoveryAuthorization,
		)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf(
			"%w: parse mounted TLS certificate: %v",
			ErrTaintRecoveryAuthorization,
			err,
		)
	}
	if err := certificate.VerifyHostname(b.policy.TLSServerName); err != nil {
		return fmt.Errorf(
			"%w: mounted TLS certificate does not satisfy Genesis server name: %v",
			ErrTaintRecoveryAuthorization,
			err,
		)
	}
	return nil
}

func normalizeExternalRecoveryWitnessGenesisPolicy(
	policy ExternalRecoveryWitnessGenesisPolicy,
) (ExternalRecoveryWitnessGenesisPolicy, ed25519.PublicKey, error) {
	if policy.Protocol != ExternalRecoveryWitnessGenesisPolicyVersion {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: external recovery witness Genesis policy version mismatch %q",
			ErrTaintRecoveryAuthorization,
			policy.Protocol,
		)
	}
	policy.ProfileAuthorityKeyID = strings.TrimSpace(policy.ProfileAuthorityKeyID)
	policy.ProfileAuthorityPublicKey = strings.TrimSpace(policy.ProfileAuthorityPublicKey)
	policy.RequiredWitnessID = strings.TrimSpace(policy.RequiredWitnessID)
	policy.TLSServerName = strings.TrimSpace(policy.TLSServerName)
	if policy.ProfileAuthorityKeyID == "" ||
		policy.ProfileAuthorityPublicKey == "" ||
		policy.RequiredWitnessID == "" ||
		policy.TLSServerName == "" {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: incomplete external recovery witness Genesis policy",
			ErrTaintRecoveryAuthorization,
		)
	}
	if policy.MinimumProfileEpoch == 0 || policy.MinimumPolicyEpoch == 0 {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: Genesis external witness epoch floors must be non-zero",
			ErrTaintRecoveryAuthorization,
		)
	}
	if policy.MinimumProfileEpoch > maxTaintRecoveryTrustJSONInteger ||
		policy.MinimumPolicyEpoch > maxTaintRecoveryTrustJSONInteger {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: Genesis external witness epoch exceeds RFC8785/JCS exact integer profile",
			ErrTaintRecoveryAuthorization,
		)
	}
	rawKey, err := base64.StdEncoding.DecodeString(policy.ProfileAuthorityPublicKey)
	if err != nil || len(rawKey) != ed25519.PublicKeySize {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: invalid external witness profile authority public key",
			ErrTaintRecoveryAuthorization,
		)
	}
	authorityKey := ed25519.PublicKey(rawKey)
	keyID, err := BootstrapKeyID(authorityKey)
	if err != nil {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, err
	}
	if keyID != policy.ProfileAuthorityKeyID {
		return ExternalRecoveryWitnessGenesisPolicy{}, nil, fmt.Errorf(
			"%w: external witness profile authority key id mismatch",
			ErrTaintRecoveryAuthorization,
		)
	}
	return policy, append(ed25519.PublicKey(nil), authorityKey...), nil
}

func decodeSingleExternalWitnessJSON(
	data []byte,
	dst any,
	disallowUnknown bool,
) error {
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
