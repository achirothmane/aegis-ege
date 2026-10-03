package kernelfabric

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TaintRecoveryPersistenceVersion          = "aegis.ege/taint-recovery-persistence/v0"
	TaintRecoveryPersistenceOutcomeCommitted = "RECOVERY_COMMITTED"
)

var ErrTaintRecoveryPersistence = errors.New("taint recovery persistence record is invalid")

type TaintRecoveryPersistenceRecord struct {
	Version                 string    `json:"version"`
	RecordID                string    `json:"record_id"`
	BootIDHash              string    `json:"boot_id_hash"`
	PlanDigest              string    `json:"plan_digest"`
	CgroupID                uint64    `json:"cgroup_id"`
	EnrollmentEpoch         uint64    `json:"enrollment_epoch"`
	DirtyGeneration         uint64    `json:"dirty_generation"`
	CleanWatermark          uint64    `json:"clean_watermark"`
	AuthorizationCommitment string    `json:"authorization_commitment"`
	Outcome                 string    `json:"outcome"`
	RecordedAt              time.Time `json:"recorded_at"`
}

type SignedTaintRecoveryPersistenceRecord struct {
	Record    TaintRecoveryPersistenceRecord `json:"record"`
	KeyID     string                         `json:"key_id"`
	Signature string                         `json:"signature"`
}

func ValidateTaintRecoveryPersistenceRecord(record TaintRecoveryPersistenceRecord) error {
	if record.Version != TaintRecoveryPersistenceVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTaintRecoveryPersistence, record.Version)
	}
	if strings.TrimSpace(record.RecordID) == "" {
		return fmt.Errorf("%w: record_id is required", ErrTaintRecoveryPersistence)
	}
	if _, err := ParseSHA256Digest(record.BootIDHash); err != nil {
		return fmt.Errorf("%w: boot_id_hash: %v", ErrTaintRecoveryPersistence, err)
	}
	if _, err := ParseSHA256Digest(record.PlanDigest); err != nil {
		return fmt.Errorf("%w: plan_digest: %v", ErrTaintRecoveryPersistence, err)
	}
	if _, err := ParseSHA256Digest(record.AuthorizationCommitment); err != nil {
		return fmt.Errorf("%w: authorization_commitment: %v", ErrTaintRecoveryPersistence, err)
	}
	if record.CgroupID == 0 || record.EnrollmentEpoch == 0 {
		return fmt.Errorf("%w: cgroup and enrollment epoch are required", ErrTaintRecoveryPersistence)
	}
	if record.Outcome != TaintRecoveryPersistenceOutcomeCommitted {
		return fmt.Errorf("%w: unsupported outcome %q", ErrTaintRecoveryPersistence, record.Outcome)
	}
	if record.DirtyGeneration != record.CleanWatermark {
		return fmt.Errorf("%w: committed recovery requires dirty generation to equal clean watermark", ErrTaintRecoveryPersistence)
	}
	if record.RecordedAt.IsZero() {
		return fmt.Errorf("%w: recorded_at is required", ErrTaintRecoveryPersistence)
	}
	return nil
}

func SignTaintRecoveryPersistenceRecord(
	record TaintRecoveryPersistenceRecord,
	privateKey ed25519.PrivateKey,
) (SignedTaintRecoveryPersistenceRecord, error) {
	if err := ValidateTaintRecoveryPersistenceRecord(record); err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTaintRecoveryPersistenceRecord{}, errors.New("invalid Ed25519 taint recovery persistence key")
	}
	payload, err := canonicalTaintRecoveryPersistencePayload(record)
	if err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, err
	}
	return SignedTaintRecoveryPersistenceRecord{
		Record:    record,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTaintRecoveryPersistenceRecord(
	signed SignedTaintRecoveryPersistenceRecord,
	publicKey ed25519.PublicKey,
) error {
	if err := ValidateTaintRecoveryPersistenceRecord(signed.Record); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrBootstrapSignatureInvalid
	}
	expectedKeyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if expectedKeyID != signed.KeyID {
		return ErrBootstrapSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalTaintRecoveryPersistencePayload(signed.Record)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func VerifySignedTaintRecoveryPersistenceRecordForBoot(
	signed SignedTaintRecoveryPersistenceRecord,
	publicKey ed25519.PublicKey,
	currentBootIDHash string,
) error {
	if err := VerifySignedTaintRecoveryPersistenceRecord(signed, publicKey); err != nil {
		return err
	}
	if _, err := ParseSHA256Digest(currentBootIDHash); err != nil {
		return fmt.Errorf("current boot identity: %w", err)
	}
	if signed.Record.BootIDHash != currentBootIDHash {
		return fmt.Errorf("%w: boot identity mismatch; persistent record is historical only", ErrTaintRecoveryPersistence)
	}
	return nil
}

func WriteSignedTaintRecoveryPersistenceRecordDurable(
	path string,
	signed SignedTaintRecoveryPersistenceRecord,
) error {
	if err := ValidateTaintRecoveryPersistenceRecord(signed.Record); err != nil {
		return err
	}
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return errors.New("taint recovery persistence path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create taint recovery persistence directory: %w", err)
	}
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal taint recovery persistence record: %w", err)
	}
	payload = append(payload, '\n')

	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create taint recovery persistence temp file: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write taint recovery persistence record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync taint recovery persistence record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close taint recovery persistence record: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit taint recovery persistence record: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open taint recovery persistence directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync taint recovery persistence directory: %w", err)
	}
	ok = true
	return nil
}

func LoadSignedTaintRecoveryPersistenceRecord(path string) (SignedTaintRecoveryPersistenceRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, err
	}
	var signed SignedTaintRecoveryPersistenceRecord
	if err := json.Unmarshal(payload, &signed); err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, fmt.Errorf("decode taint recovery persistence record: %w", err)
	}
	if err := ValidateTaintRecoveryPersistenceRecord(signed.Record); err != nil {
		return SignedTaintRecoveryPersistenceRecord{}, err
	}
	return signed, nil
}

func canonicalTaintRecoveryPersistencePayload(record TaintRecoveryPersistenceRecord) ([]byte, error) {
	normalized := record
	normalized.RecordedAt = record.RecordedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/taint-recovery-persistence/v0\x00"), body...), nil
}

func TaintRecoveryCommitmentHex(commitment [32]byte) string {
	return "sha256:" + hex.EncodeToString(commitment[:])
}
