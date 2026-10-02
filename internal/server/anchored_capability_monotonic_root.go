package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"golang.org/x/sys/unix"
)

const anchoredCapabilityRootVersion = "aegis.ege/capability-monotonic-root/v1"

var (
	ErrCapabilityRootRollback = errors.New("anchored capability root rollback detected")
	ErrCapabilityRootCorrupt  = errors.New("anchored capability root ledger is corrupt")
	ErrCapabilityRootMissing  = errors.New("anchored capability root has no state for scope")
)

type CapabilityMonotonicAnchor interface {
	Identity(context.Context) (string, error)
	Read(context.Context) (uint64, error)
	Advance(context.Context, uint64) (uint64, error)
}

type AnchoredFileCapabilityMonotonicRoot struct {
	path   string
	anchor CapabilityMonotonicAnchor
}

type capabilityRootRecord struct {
	Version            string
	Index              uint64
	ScopeDigest        string
	Snapshot           egeproto.CapabilityAuthoritySnapshot
	AnchorID           string
	AnchorValue        uint64
	PreviousRecordHash string
	RecordHash         string
}

func NewAnchoredFileCapabilityMonotonicRoot(path string, anchor CapabilityMonotonicAnchor) (*AnchoredFileCapabilityMonotonicRoot, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("capability root ledger path is required")
	}
	if anchor == nil {
		return nil, errors.New("capability monotonic anchor is required")
	}
	return &AnchoredFileCapabilityMonotonicRoot{
		path:   filepath.Clean(path),
		anchor: anchor,
	}, nil
}

func (r *AnchoredFileCapabilityMonotonicRoot) Advance(
	ctx context.Context,
	scope CapabilityFenceScope,
	observed egeproto.CapabilityAuthoritySnapshot,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	if err := validateCapabilityAuthoritySnapshot(observed); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("invalid observed capability authority: %w", err)
	}
	scopeDigest, err := capabilityRootScopeDigest(scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}

	file, records, anchorID, anchorValue, err := r.openVerified(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	defer closeCapabilityRootFile(file)

	if current, ok := latestCapabilityRootSnapshot(records, scopeDigest); ok {
		relation, compareErr := compareCapabilityMonotonicRoot(current, observed)
		if compareErr != nil {
			return egeproto.CapabilityAuthoritySnapshot{}, compareErr
		}
		switch relation {
		case capabilityRootEqual, capabilityRootAhead:
			return current, nil
		case capabilityRootBehind:
		default:
			return egeproto.CapabilityAuthoritySnapshot{}, ErrCapabilityMonotonicRootInvalid
		}
	}

	if anchorValue == ^uint64(0) {
		return egeproto.CapabilityAuthoritySnapshot{}, errors.New("capability monotonic anchor is exhausted")
	}
	nextAnchor, err := r.anchor.Advance(ctx, anchorValue)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("advance capability monotonic anchor: %w", err)
	}
	expectedIndex := uint64(len(records) + 1)
	if nextAnchor != anchorValue+1 || nextAnchor != expectedIndex {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"capability monotonic anchor advanced to %d; expected %d",
			nextAnchor,
			expectedIndex,
		)
	}

	record := capabilityRootRecord{
		Version:     anchoredCapabilityRootVersion,
		Index:       expectedIndex,
		ScopeDigest: scopeDigest,
		Snapshot:    observed,
		AnchorID:    anchorID,
		AnchorValue: nextAnchor,
	}
	if len(records) != 0 {
		record.PreviousRecordHash = records[len(records)-1].RecordHash
	}
	record.RecordHash, err = capabilityRootRecordHash(record)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("encode capability root record: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("seek capability root ledger: %w", err)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("append capability root ledger: %w", err)
	}
	if err := file.Sync(); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("sync capability root ledger: %w", err)
	}
	if err := syncCapabilityRootDirectory(filepath.Dir(r.path)); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf("sync capability root directory: %w", err)
	}
	return observed, nil
}

func (r *AnchoredFileCapabilityMonotonicRoot) Current(
	ctx context.Context,
	scope CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	scopeDigest, err := capabilityRootScopeDigest(scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	file, records, _, _, err := r.openVerified(ctx)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	defer closeCapabilityRootFile(file)

	current, ok := latestCapabilityRootSnapshot(records, scopeDigest)
	if !ok {
		return egeproto.CapabilityAuthoritySnapshot{}, ErrCapabilityRootMissing
	}
	return current, nil
}

func (r *AnchoredFileCapabilityMonotonicRoot) openVerified(
	ctx context.Context,
) (*os.File, []capabilityRootRecord, string, uint64, error) {
	if r == nil || r.anchor == nil || strings.TrimSpace(r.path) == "" {
		return nil, nil, "", 0, errors.New("anchored capability monotonic root is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return nil, nil, "", 0, fmt.Errorf("create capability root directory: %w", err)
	}

	fd, err := unix.Open(r.path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("open capability root ledger: %w", err)
	}
	file := os.NewFile(uintptr(fd), r.path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, "", 0, errors.New("wrap capability root ledger file descriptor")
	}
	cleanup := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}

	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, nil, "", 0, fmt.Errorf("lock capability root ledger: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf("restrict capability root ledger permissions: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf("stat capability root ledger: %w", err)
	}
	if !info.Mode().IsRegular() {
		cleanup()
		return nil, nil, "", 0, errors.New("capability root ledger is not a regular file")
	}

	records, err := readCapabilityRootRecords(file)
	if err != nil {
		cleanup()
		return nil, nil, "", 0, err
	}
	anchorID, err := r.anchor.Identity(ctx)
	if err != nil {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf("read capability monotonic anchor identity: %w", err)
	}
	if strings.TrimSpace(anchorID) == "" {
		cleanup()
		return nil, nil, "", 0, errors.New("capability monotonic anchor returned empty identity")
	}
	anchorValue, err := r.anchor.Read(ctx)
	if err != nil {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf("read capability monotonic anchor: %w", err)
	}

	if len(records) == 0 {
		if anchorValue != 0 {
			cleanup()
			return nil, nil, "", 0, fmt.Errorf(
				"%w: empty ledger with anchor value %d",
				ErrCapabilityRootRollback,
				anchorValue,
			)
		}
		return file, records, anchorID, anchorValue, nil
	}

	last := records[len(records)-1]
	if last.AnchorID != anchorID {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf(
			"%w: anchor identity changed from %q to %q",
			ErrCapabilityRootCorrupt,
			last.AnchorID,
			anchorID,
		)
	}
	if anchorValue != last.AnchorValue {
		cleanup()
		return nil, nil, "", 0, fmt.Errorf(
			"%w: anchor=%d ledger=%d",
			ErrCapabilityRootRollback,
			anchorValue,
			last.AnchorValue,
		)
	}
	return file, records, anchorID, anchorValue, nil
}

func readCapabilityRootRecords(file *os.File) ([]capabilityRootRecord, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind capability root ledger: %w", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []capabilityRootRecord
	for line := 1; scanner.Scan(); line++ {
		payload := bytes.TrimSpace(scanner.Bytes())
		if len(payload) == 0 {
			return nil, fmt.Errorf("%w: empty record at line %d", ErrCapabilityRootCorrupt, line)
		}
		var record capabilityRootRecord
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrCapabilityRootCorrupt, line, err)
		}
		if err := validateCapabilityRootRecord(records, record); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrCapabilityRootCorrupt, line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read capability root ledger: %w", err)
	}
	return records, nil
}

func validateCapabilityRootRecord(previous []capabilityRootRecord, record capabilityRootRecord) error {
	if record.Version != anchoredCapabilityRootVersion {
		return fmt.Errorf("unsupported capability root record version %q", record.Version)
	}
	if record.Index == 0 || record.AnchorValue != record.Index {
		return errors.New("record index and anchor value must be equal and non-zero")
	}
	if strings.TrimSpace(record.AnchorID) == "" {
		return errors.New("anchor identity is required")
	}
	if !isCapabilityRootDigest(record.ScopeDigest) || !isCapabilityRootDigest(record.RecordHash) {
		return errors.New("scope digest and record hash must be sha256 digests")
	}
	if err := validateCapabilityAuthoritySnapshot(record.Snapshot); err != nil {
		return fmt.Errorf("invalid snapshot: %w", err)
	}
	expectedHash, err := capabilityRootRecordHash(record)
	if err != nil {
		return err
	}
	if expectedHash != record.RecordHash {
		return errors.New("record hash mismatch")
	}

	if len(previous) == 0 {
		if record.Index != 1 || record.PreviousRecordHash != "" {
			return errors.New("first record must start at index 1 without predecessor")
		}
		return nil
	}
	last := previous[len(previous)-1]
	if record.Index != last.Index+1 {
		return errors.New("record index is not contiguous")
	}
	if record.AnchorID != last.AnchorID {
		return errors.New("anchor identity changed inside capability root ledger")
	}
	if record.PreviousRecordHash != last.RecordHash {
		return errors.New("capability root hash chain is broken")
	}

	if prior, ok := latestCapabilityRootSnapshot(previous, record.ScopeDigest); ok {
		relation, err := compareCapabilityMonotonicRoot(prior, record.Snapshot)
		if err != nil {
			return err
		}
		if relation != capabilityRootBehind {
			return errors.New("scope snapshot did not advance monotonically")
		}
	}
	return nil
}

func latestCapabilityRootSnapshot(
	records []capabilityRootRecord,
	scopeDigest string,
) (egeproto.CapabilityAuthoritySnapshot, bool) {
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].ScopeDigest == scopeDigest {
			return records[i].Snapshot, true
		}
	}
	return egeproto.CapabilityAuthoritySnapshot{}, false
}

func capabilityRootScopeDigest(scope CapabilityFenceScope) (string, error) {
	parts := []string{
		strings.TrimSpace(scope.IntentID),
		strings.TrimSpace(scope.Kind),
		strings.TrimSpace(scope.Target.Type),
		strings.TrimSpace(scope.Target.Name),
	}
	for i, part := range parts {
		if part == "" {
			return "", fmt.Errorf("capability root scope component %d is empty", i)
		}
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/capability-root-scope/v1\x00"))
	h.Write([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func capabilityRootRecordHash(record capabilityRootRecord) (string, error) {
	stable := record
	stable.RecordHash = ""
	payload, err := json.Marshal(stable)
	if err != nil {
		return "", fmt.Errorf("encode capability root record hash input: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/capability-root-record/v1\x00"))
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func isCapabilityRootDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func closeCapabilityRootFile(file *os.File) {
	if file == nil {
		return
	}
	fd := int(file.Fd())
	_ = unix.Flock(fd, unix.LOCK_UN)
	_ = file.Close()
}

func syncCapabilityRootDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
