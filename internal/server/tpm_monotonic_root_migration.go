package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const TPMRootMigrationAuthorizationVersion = "aegis.ege/tpm-root-migration-authorization/v1"

var (
	ErrTPMRootMigrationAuthorization = errors.New("TPM root migration authorization is invalid")
	ErrTPMRootMigrationReplay        = errors.New("TPM root migration authorization replay detected")
	ErrTPMRootMigrationDestination   = errors.New("TPM root migration destination is not empty")
)

type TPMRootMigrationAuthorization struct {
	Version                   string    `json:"version"`
	MigrationID               string    `json:"migration_id"`
	SourceDeviceIdentity      string    `json:"source_device_identity"`
	SourceStateDigest         string    `json:"source_state_digest"`
	SourceGeneration          uint64    `json:"source_generation"`
	DestinationDeviceIdentity string    `json:"destination_device_identity"`
	DestinationGeneration     uint64    `json:"destination_generation"`
	DestinationNVIndex        uint32    `json:"destination_nv_index"`
	DestinationAttestationDigest string  `json:"destination_attestation_digest"`
	NotBefore                 time.Time `json:"not_before"`
	ExpiresAt                 time.Time `json:"expires_at"`
}

type SignedTPMRootMigrationAuthorization struct {
	Authorization TPMRootMigrationAuthorization `json:"authorization"`
	KeyID         string                        `json:"key_id"`
	Signature     string                        `json:"signature"`
}

func ValidateTPMRootMigrationAuthorization(auth TPMRootMigrationAuthorization) error {
	if auth.Version != TPMRootMigrationAuthorizationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTPMRootMigrationAuthorization, auth.Version)
	}
	if strings.TrimSpace(auth.MigrationID) == "" {
		return fmt.Errorf("%w: migration_id is required", ErrTPMRootMigrationAuthorization)
	}
	if !validSHA256Ref(auth.SourceDeviceIdentity) {
		return fmt.Errorf("%w: source_device_identity is invalid", ErrTPMRootMigrationAuthorization)
	}
	if !validSHA256Ref(auth.SourceStateDigest) {
		return fmt.Errorf("%w: source_state_digest is invalid", ErrTPMRootMigrationAuthorization)
	}
	if auth.SourceGeneration == 0 {
		return fmt.Errorf("%w: source_generation must be non-zero", ErrTPMRootMigrationAuthorization)
	}
	if !validSHA256Ref(auth.DestinationDeviceIdentity) {
		return fmt.Errorf("%w: destination_device_identity is invalid", ErrTPMRootMigrationAuthorization)
	}
	if auth.DestinationGeneration == 0 {
		return fmt.Errorf("%w: destination_generation must be non-zero", ErrTPMRootMigrationAuthorization)
	}
	if auth.DestinationNVIndex == 0 {
		return fmt.Errorf("%w: destination_nv_index is required", ErrTPMRootMigrationAuthorization)
	}
	if !validSHA256Ref(auth.DestinationAttestationDigest) {
		return fmt.Errorf("%w: destination_attestation_digest is invalid", ErrTPMRootMigrationAuthorization)
	}
	if auth.SourceDeviceIdentity == auth.DestinationDeviceIdentity {
		return fmt.Errorf("%w: source and destination device identities must differ", ErrTPMRootMigrationAuthorization)
	}
	if auth.NotBefore.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.NotBefore) {
		return fmt.Errorf("%w: validity window is invalid", ErrTPMRootMigrationAuthorization)
	}
	return nil
}

func SignTPMRootMigrationAuthorization(
	auth TPMRootMigrationAuthorization,
	privateKey ed25519.PrivateKey,
) (SignedTPMRootMigrationAuthorization, error) {
	if err := ValidateTPMRootMigrationAuthorization(auth); err != nil {
		return SignedTPMRootMigrationAuthorization{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTPMRootMigrationAuthorization{}, errors.New("invalid Ed25519 TPM root migration key")
	}
	payload, err := canonicalTPMRootMigrationAuthorizationPayload(auth)
	if err != nil {
		return SignedTPMRootMigrationAuthorization{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedTPMRootMigrationAuthorization{
		Authorization: auth,
		KeyID:         tpmRootMigrationKeyID(publicKey),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTPMRootMigrationAuthorization(
	signed SignedTPMRootMigrationAuthorization,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := ValidateTPMRootMigrationAuthorization(signed.Authorization); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 public key", ErrTPMRootMigrationAuthorization)
	}
	if signed.KeyID != tpmRootMigrationKeyID(publicKey) {
		return fmt.Errorf("%w: signer key mismatch", ErrTPMRootMigrationAuthorization)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrTPMRootMigrationAuthorization)
	}
	payload, err := canonicalTPMRootMigrationAuthorizationPayload(signed.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("%w: signature verification failed", ErrTPMRootMigrationAuthorization)
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(signed.Authorization.NotBefore.UTC()) || !now.Before(signed.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrTPMRootMigrationAuthorization)
	}
	return nil
}

func TPMRootMigrationAuthorizationDigest(signed SignedTPMRootMigrationAuthorization) (string, error) {
	payload, err := canonicalTPMRootMigrationAuthorizationPayload(signed.Authorization)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		Payload   []byte `json:"payload"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{
		Payload:   payload,
		KeyID:     signed.KeyID,
		Signature: signed.Signature,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/tpm-root-migration-commitment/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func MigrateTPMNVMonotonicRoot(
	ctx context.Context,
	sourceStatePath string,
	destination *TPMNVMonotonicRoot,
	signed SignedTPMRootMigrationAuthorization,
	migrationPublicKey ed25519.PublicKey,
	destinationAttestation SignedTPMRootMigrationDestinationAttestation,
	attestationPublicKey ed25519.PublicKey,
	now time.Time,
) error {
	if destination == nil {
		return fmt.Errorf("%w: destination root is required", ErrTPMRootMigrationAuthorization)
	}
	if err := VerifySignedTPMRootMigrationAuthorization(signed, migrationPublicKey, now); err != nil {
		return err
	}
	if err := VerifySignedTPMRootMigrationDestinationAttestation(destinationAttestation, attestationPublicKey, now); err != nil {
		return err
	}
	if len(migrationPublicKey) != ed25519.PublicKeySize ||
		len(attestationPublicKey) != ed25519.PublicKeySize ||
		string(migrationPublicKey) == string(attestationPublicKey) {
		return fmt.Errorf("%w: migration and attestation authorities must be independent", ErrTPMRootMigrationAuthorization)
	}
	auth := signed.Authorization
	att := destinationAttestation.Attestation
	attestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		return err
	}
	if auth.DestinationAttestationDigest != attestationDigest ||
		att.MigrationID != auth.MigrationID ||
		att.DestinationDeviceIdentity != auth.DestinationDeviceIdentity ||
		att.DestinationGeneration != auth.DestinationGeneration {
		return fmt.Errorf("%w: destination attestation does not match migration authorization", ErrTPMRootMigrationAuthorization)
	}

	source, ok, err := readTPMNVRootState(sourceStatePath)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: source state is missing", ErrTPMRootMigrationAuthorization)
	}
	if source.DeviceIdentity != auth.SourceDeviceIdentity ||
		source.Digest != auth.SourceStateDigest ||
		source.Generation != auth.SourceGeneration {
		return fmt.Errorf("%w: source state does not match authorization", ErrTPMRootMigrationAuthorization)
	}
	if len(source.Scopes) == 0 {
		return fmt.Errorf("%w: source root has no authority state", ErrTPMRootMigrationAuthorization)
	}
	if uint32(destination.cfg.NVIndex) != auth.DestinationNVIndex {
		return fmt.Errorf("%w: destination NV index mismatch", ErrTPMRootMigrationAuthorization)
	}

	commitment, err := TPMRootMigrationAuthorizationDigest(signed)
	if err != nil {
		return err
	}

	destination.mu.Lock()
	defer destination.mu.Unlock()

	state, err := destination.recoverLocked(ctx)
	if err != nil {
		return err
	}
	if state.MigrationAuthorizationDigest == commitment {
		return ErrTPMRootMigrationReplay
	}
	if state.DeviceIdentity != auth.DestinationDeviceIdentity ||
		state.Generation != auth.DestinationGeneration {
		return fmt.Errorf("%w: destination root does not match authorization", ErrTPMRootMigrationAuthorization)
	}
	if state.DeviceIdentity != att.DestinationDeviceIdentity ||
		state.MeasuredBootIdentity != att.DestinationMeasuredBootIdentity ||
		state.Generation != att.DestinationGeneration {
		return fmt.Errorf("%w: live destination does not match independently attested identity", ErrTPMRootMigrationDestinationAttestation)
	}
	if len(state.Scopes) != 0 {
		return ErrTPMRootMigrationDestination
	}
	if state.Generation == ^uint64(0) {
		return fmt.Errorf("%w: destination generation exhausted", ErrTPMRootMigrationAuthorization)
	}

	next := cloneTPMNVRootState(state)
	next.PreviousGeneration = state.Generation
	next.Generation = state.Generation + 1
	next.PredecessorDeviceIdentity = source.DeviceIdentity
	next.MigrationSourceStateDigest = source.Digest
	next.MigrationAuthorizationDigest = commitment
	next.MigrationDestinationAttestationDigest = attestationDigest
	next.Scopes = make(map[string]egeproto.CapabilityAuthoritySnapshot, len(source.Scopes))
	for key, snapshot := range source.Scopes {
		next.Scopes[key] = snapshot
	}

	pendingPath := destination.cfg.StatePath + ".pending"
	if err := writeTPMNVRootStateAtomic(pendingPath, next); err != nil {
		return fmt.Errorf("persist pending TPM root migration: %w", err)
	}
	generation, err := destination.incrementCounter(ctx)
	if err != nil {
		return fmt.Errorf("increment destination TPM root counter: %w", err)
	}
	if generation != next.Generation {
		return fmt.Errorf("%w: destination counter=%d expected=%d", ErrTPMMonotonicRootRollback, generation, next.Generation)
	}
	if err := promoteTPMNVRootPending(pendingPath, destination.cfg.StatePath); err != nil {
		return fmt.Errorf("promote TPM root migration state: %w", err)
	}
	return nil
}

func canonicalTPMRootMigrationAuthorizationPayload(auth TPMRootMigrationAuthorization) ([]byte, error) {
	auth.MigrationID = strings.TrimSpace(auth.MigrationID)
	auth.SourceDeviceIdentity = strings.TrimSpace(auth.SourceDeviceIdentity)
	auth.SourceStateDigest = strings.TrimSpace(auth.SourceStateDigest)
	auth.DestinationDeviceIdentity = strings.TrimSpace(auth.DestinationDeviceIdentity)
	auth.NotBefore = auth.NotBefore.UTC()
	auth.ExpiresAt = auth.ExpiresAt.UTC()
	body, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/tpm-root-migration-authorization/v1\x00"), body...), nil
}

func tpmRootMigrationKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256Ref(value string) bool {
	const prefix = "sha256:"
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

