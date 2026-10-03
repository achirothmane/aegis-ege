package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const TPMRootMigrationAttestationTrustVersion = "aegis.ege/tpm-root-migration-attestation-trust/v1"

var ErrTPMRootMigrationAttestationTrust = errors.New("TPM root migration attestation trust is invalid")

type TPMRootMigrationAttestationTrust struct {
	version               string
	genesisEpoch          uint64
	trustRootRef          string
	trustRootEpoch        uint64
	attestationPolicyHash string
	publicKey             ed25519.PublicKey
}

func NewGenesisBoundTPMRootMigrationAttestationTrust(
	verifiedManifest genesis.Manifest,
	remoteVerifierPublicKey ed25519.PublicKey,
) (TPMRootMigrationAttestationTrust, error) {
	if verifiedManifest.GenesisEpoch == 0 {
		return TPMRootMigrationAttestationTrust{}, fmt.Errorf("%w: genesis epoch must be non-zero", ErrTPMRootMigrationAttestationTrust)
	}
	if len(remoteVerifierPublicKey) != ed25519.PublicKeySize {
		return TPMRootMigrationAttestationTrust{}, fmt.Errorf("%w: invalid remote verifier public key", ErrTPMRootMigrationAttestationTrust)
	}
	keyID, err := kernelfabric.BootstrapKeyID(remoteVerifierPublicKey)
	if err != nil {
		return TPMRootMigrationAttestationTrust{}, err
	}
	if strings.TrimSpace(verifiedManifest.Trust.TrustRootRef) != keyID {
		return TPMRootMigrationAttestationTrust{}, fmt.Errorf(
			"%w: genesis trust root %q does not match remote verifier key %q",
			ErrTPMRootMigrationAttestationTrust,
			verifiedManifest.Trust.TrustRootRef,
			keyID,
		)
	}
	if verifiedManifest.Trust.TrustRootEpoch == 0 {
		return TPMRootMigrationAttestationTrust{}, fmt.Errorf("%w: trust root epoch must be non-zero", ErrTPMRootMigrationAttestationTrust)
	}
	if !validSHA256Ref(verifiedManifest.Trust.AttestationPolicyHash) {
		return TPMRootMigrationAttestationTrust{}, fmt.Errorf("%w: attestation policy hash is invalid", ErrTPMRootMigrationAttestationTrust)
	}
	return TPMRootMigrationAttestationTrust{
		version:               TPMRootMigrationAttestationTrustVersion,
		genesisEpoch:          verifiedManifest.GenesisEpoch,
		trustRootRef:          keyID,
		trustRootEpoch:        verifiedManifest.Trust.TrustRootEpoch,
		attestationPolicyHash: strings.TrimSpace(verifiedManifest.Trust.AttestationPolicyHash),
		publicKey:             append(ed25519.PublicKey(nil), remoteVerifierPublicKey...),
	}, nil
}

func (t TPMRootMigrationAttestationTrust) validate() error {
	if t.version != TPMRootMigrationAttestationTrustVersion ||
		t.genesisEpoch == 0 ||
		t.trustRootEpoch == 0 ||
		len(t.publicKey) != ed25519.PublicKeySize ||
		strings.TrimSpace(t.trustRootRef) == "" ||
		!validSHA256Ref(t.attestationPolicyHash) {
		return ErrTPMRootMigrationAttestationTrust
	}
	keyID, err := kernelfabric.BootstrapKeyID(t.publicKey)
	if err != nil {
		return err
	}
	if keyID != t.trustRootRef {
		return fmt.Errorf("%w: verifier key no longer matches trust root", ErrTPMRootMigrationAttestationTrust)
	}
	return nil
}

func (t TPMRootMigrationAttestationTrust) verifySignedAttestation(
	signed SignedTPMRootMigrationDestinationAttestation,
	now time.Time,
) error {
	if err := t.validate(); err != nil {
		return err
	}
	return VerifySignedTPMRootMigrationDestinationAttestation(signed, t.publicKey, now)
}

func (t TPMRootMigrationAttestationTrust) matchesAuthorization(
	genesisEpoch uint64,
	trustRootRef string,
	trustRootEpoch uint64,
	attestationPolicyHash string,
) bool {
	return t.genesisEpoch == genesisEpoch &&
		t.trustRootRef == strings.TrimSpace(trustRootRef) &&
		t.trustRootEpoch == trustRootEpoch &&
		t.attestationPolicyHash == strings.TrimSpace(attestationPolicyHash)
}

func (t TPMRootMigrationAttestationTrust) publicKeyEquals(key ed25519.PublicKey) bool {
	return len(key) == ed25519.PublicKeySize && string(t.publicKey) == string(key)
}
