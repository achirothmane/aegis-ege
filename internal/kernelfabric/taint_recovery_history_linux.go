//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	TaintRecoveryHistoryReceiptVersion = "aegis.ege/taint-recovery-history/v1"

	TaintRecoveryHistoryEventRecoveryCommitted = "RECOVERY_COMMITTED"
	TaintRecoveryHistoryEventReenrolled        = "FRESH_REENROLLMENT_COMMITTED"

	taintRecoveryHistoryHeadVersion = "aegis.ege/taint-recovery-history-head/v1"
)

var ErrTaintRecoveryHistory = errors.New("taint recovery history is invalid")

// TaintRecoveryHistoryReceipt is historical evidence only. It records a
// continuity-restoration fact that was true on one exact Linux boot. It is not
// an authorization token and must never be accepted as effect authority on a
// later boot.
type TaintRecoveryHistoryReceipt struct {
	Version               string    `json:"version"`
	ReceiptID             string    `json:"receipt_id"`
	Event                 string    `json:"event"`
	BootIDHash            string    `json:"boot_id_hash"`
	PlanDigest            string    `json:"plan_digest"`
	CgroupID              uint64    `json:"cgroup_id"`
	EnrollmentEpoch       uint64    `json:"enrollment_epoch"`
	DirtyGeneration       uint64    `json:"dirty_generation"`
	CleanGeneration       uint64    `json:"clean_generation"`
	CleanEffectAllowed    bool      `json:"clean_effect_allowed"`
	TaintedEffectDenied   bool      `json:"tainted_effect_denied"`
	PreviousReceiptDigest string    `json:"previous_receipt_digest,omitempty"`
	RecordedAt            time.Time `json:"recorded_at"`
}

type SignedTaintRecoveryHistoryReceipt struct {
	Receipt   TaintRecoveryHistoryReceipt `json:"receipt"`
	KeyID     string                      `json:"key_id"`
	Signature string                      `json:"signature"`
}

type taintRecoveryHistoryHead struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type TaintRecoveryHistoryStore struct {
	Dir string
}

func ValidateTaintRecoveryHistoryReceipt(receipt TaintRecoveryHistoryReceipt) error {
	if receipt.Version != TaintRecoveryHistoryReceiptVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTaintRecoveryHistory, receipt.Version)
	}
	if strings.TrimSpace(receipt.ReceiptID) == "" {
		return fmt.Errorf("%w: receipt_id is required", ErrTaintRecoveryHistory)
	}
	switch receipt.Event {
	case TaintRecoveryHistoryEventRecoveryCommitted, TaintRecoveryHistoryEventReenrolled:
	default:
		return fmt.Errorf("%w: unsupported event %q", ErrTaintRecoveryHistory, receipt.Event)
	}
	if _, err := ParseSHA256Digest(receipt.BootIDHash); err != nil {
		return fmt.Errorf("%w: boot_id_hash: %v", ErrTaintRecoveryHistory, err)
	}
	if _, err := ParseSHA256Digest(receipt.PlanDigest); err != nil {
		return fmt.Errorf("%w: plan_digest: %v", ErrTaintRecoveryHistory, err)
	}
	if receipt.CgroupID == 0 {
		return fmt.Errorf("%w: cgroup_id is required", ErrTaintRecoveryHistory)
	}
	if receipt.EnrollmentEpoch == 0 {
		return fmt.Errorf("%w: enrollment_epoch is required", ErrTaintRecoveryHistory)
	}
	if receipt.DirtyGeneration != receipt.CleanGeneration {
		return fmt.Errorf(
			"%w: committed continuity must be clean: dirty=%d clean=%d",
			ErrTaintRecoveryHistory,
			receipt.DirtyGeneration,
			receipt.CleanGeneration,
		)
	}
	if !receipt.CleanEffectAllowed || !receipt.TaintedEffectDenied {
		return fmt.Errorf("%w: effect-boundary evidence is incomplete", ErrTaintRecoveryHistory)
	}
	if receipt.PreviousReceiptDigest != "" {
		if _, err := ParseSHA256Digest(receipt.PreviousReceiptDigest); err != nil {
			return fmt.Errorf("%w: previous_receipt_digest: %v", ErrTaintRecoveryHistory, err)
		}
	}
	if receipt.RecordedAt.IsZero() {
		return fmt.Errorf("%w: recorded_at is required", ErrTaintRecoveryHistory)
	}
	return nil
}

func SignTaintRecoveryHistoryReceipt(
	receipt TaintRecoveryHistoryReceipt,
	privateKey ed25519.PrivateKey,
) (SignedTaintRecoveryHistoryReceipt, error) {
	if err := ValidateTaintRecoveryHistoryReceipt(receipt); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTaintRecoveryHistoryReceipt{}, errors.New("invalid Ed25519 taint recovery history key")
	}
	payload, err := canonicalTaintRecoveryHistoryPayload(receipt)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, err
	}
	return SignedTaintRecoveryHistoryReceipt{
		Receipt:   receipt,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedTaintRecoveryHistoryReceipt(
	signed SignedTaintRecoveryHistoryReceipt,
	publicKey ed25519.PublicKey,
) error {
	if err := ValidateTaintRecoveryHistoryReceipt(signed.Receipt); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrBootstrapSignatureInvalid
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if keyID != signed.KeyID {
		return ErrBootstrapSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalTaintRecoveryHistoryPayload(signed.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func TaintRecoveryHistoryReceiptDigest(
	signed SignedTaintRecoveryHistoryReceipt,
) (string, error) {
	if err := ValidateTaintRecoveryHistoryReceipt(signed.Receipt); err != nil {
		return "", err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/taint-recovery-history-digest/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s TaintRecoveryHistoryStore) Append(
	signed SignedTaintRecoveryHistoryReceipt,
	publicKey ed25519.PublicKey,
) (string, error) {
	if err := VerifySignedTaintRecoveryHistoryReceipt(signed, publicKey); err != nil {
		return "", err
	}
	dir, err := s.normalizedDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "receipts"), 0o700); err != nil {
		return "", err
	}

	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return "", err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	current, currentDigest, exists, err := s.currentLocked(dir, publicKey)
	if err != nil {
		return "", err
	}
	digest, err := TaintRecoveryHistoryReceiptDigest(signed)
	if err != nil {
		return "", err
	}
	if exists && digest == currentDigest {
		return digest, nil
	}
	if !exists {
		if signed.Receipt.PreviousReceiptDigest != "" {
			return "", fmt.Errorf("%w: first receipt cannot name a predecessor", ErrTaintRecoveryHistory)
		}
	} else if signed.Receipt.PreviousReceiptDigest != currentDigest {
		return "", fmt.Errorf(
			"%w: predecessor mismatch: got=%q want=%q current_receipt=%q",
			ErrTaintRecoveryHistory,
			signed.Receipt.PreviousReceiptDigest,
			currentDigest,
			current.Receipt.ReceiptID,
		)
	}

	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, '\n')
	receiptPath := filepath.Join(dir, "receipts", strings.TrimPrefix(digest, "sha256:")+".json")
	if err := writeTaintRecoveryHistoryImmutable(receiptPath, payload); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		existing, readErr := os.ReadFile(receiptPath)
		if readErr != nil {
			return "", readErr
		}
		if string(existing) != string(payload) {
			return "", fmt.Errorf("%w: immutable receipt collision at %s", ErrTaintRecoveryHistory, receiptPath)
		}
	}

	head := taintRecoveryHistoryHead{Version: taintRecoveryHistoryHeadVersion, Digest: digest}
	if err := writeTaintRecoveryHistoryJSONAtomic(filepath.Join(dir, "head.json"), head); err != nil {
		return "", err
	}
	if err := syncTaintRecoveryHistoryDirectory(filepath.Join(dir, "receipts")); err != nil {
		return "", err
	}
	if err := syncTaintRecoveryHistoryDirectory(dir); err != nil {
		return "", err
	}
	return digest, nil
}

func (s TaintRecoveryHistoryStore) Current(
	publicKey ed25519.PublicKey,
) (SignedTaintRecoveryHistoryReceipt, string, bool, error) {
	dir, err := s.normalizedDir()
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "receipts"), 0o700); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return s.currentLocked(dir, publicKey)
}

func (s TaintRecoveryHistoryStore) currentLocked(
	dir string,
	publicKey ed25519.PublicKey,
) (SignedTaintRecoveryHistoryReceipt, string, bool, error) {
	headPath := filepath.Join(dir, "head.json")
	if info, err := os.Lstat(headPath); err != nil {
		if os.IsNotExist(err) {
			return SignedTaintRecoveryHistoryReceipt{}, "", false, nil
		}
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: head path is symlink", ErrTaintRecoveryHistory)
	}
	data, err := os.ReadFile(headPath)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	var head taintRecoveryHistoryHead
	if err := json.Unmarshal(data, &head); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: decode head: %v", ErrTaintRecoveryHistory, err)
	}
	if head.Version != taintRecoveryHistoryHeadVersion {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: invalid head version", ErrTaintRecoveryHistory)
	}
	if _, err := ParseSHA256Digest(head.Digest); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: head digest: %v", ErrTaintRecoveryHistory, err)
	}
	receiptPath := filepath.Join(dir, "receipts", strings.TrimPrefix(head.Digest, "sha256:")+".json")
	if info, err := os.Lstat(receiptPath); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: receipt path is symlink", ErrTaintRecoveryHistory)
	}
	data, err = os.ReadFile(receiptPath)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	var signed SignedTaintRecoveryHistoryReceipt
	if err := json.Unmarshal(data, &signed); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: decode receipt: %v", ErrTaintRecoveryHistory, err)
	}
	if err := VerifySignedTaintRecoveryHistoryReceipt(signed, publicKey); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	digest, err := TaintRecoveryHistoryReceiptDigest(signed)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	if digest != head.Digest {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("%w: head/receipt digest mismatch", ErrTaintRecoveryHistory)
	}
	return signed, digest, true, nil
}

func (s TaintRecoveryHistoryStore) normalizedDir() (string, error) {
	dir := filepath.Clean(strings.TrimSpace(s.Dir))
	if dir == "." || dir == "" {
		return "", fmt.Errorf("%w: history directory is required", ErrTaintRecoveryHistory)
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("%w: history directory must be absolute", ErrTaintRecoveryHistory)
	}
	return dir, nil
}

func canonicalTaintRecoveryHistoryPayload(receipt TaintRecoveryHistoryReceipt) ([]byte, error) {
	normalized := receipt
	normalized.RecordedAt = receipt.RecordedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/taint-recovery-history/v1\x00"), body...), nil
}

func writeTaintRecoveryHistoryImmutable(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeTaintRecoveryHistoryJSONAtomic(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".recovery-history-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(append(body, '\n')); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncTaintRecoveryHistoryDirectory(dir)
}

func syncTaintRecoveryHistoryDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
