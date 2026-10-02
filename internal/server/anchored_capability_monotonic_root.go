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

const anchoredCapabilityRootVersion = "aegis.ege/capability-monotonic-root/v2"

var (
	ErrCapabilityRootRollback       = errors.New("anchored capability root rollback detected")
	ErrCapabilityRootCorrupt        = errors.New("anchored capability root ledger is corrupt")
	ErrCapabilityRootMissing        = errors.New("anchored capability root has no state for scope")
	ErrCapabilityRootAnchorMismatch = errors.New("anchored capability root commitment mismatch")
)

// CapabilityRootAnchorState is the state that must live outside the mutable
// coordination and local-ledger failure domain.
//
// Sequence prevents rollback to an older number of accepted root records.
// Commitment binds the exact ledger head; sequence alone is insufficient
// because a same-length ledger can otherwise be rewritten and re-hashed.
type CapabilityRootAnchorState struct {
	Sequence   uint64
	Commitment string
}

// CapabilityRootAnchor is an independently protected compare-and-advance store.
//
// Current must return the protected sequence and exact head commitment.
// Advance must atomically replace expected with next or fail. Implementations
// that only expose a monotonic counter do not satisfy this contract.
type CapabilityRootAnchor interface {
	Identity(context.Context) (string, error)
	Current(context.Context) (CapabilityRootAnchorState, error)
	Advance(
		context.Context,
		CapabilityRootAnchorState,
		CapabilityRootAnchorState,
	) (CapabilityRootAnchorState, error)
}

type AnchoredFileCapabilityMonotonicRoot struct {
	path   string
	anchor CapabilityRootAnchor
}

type capabilityRootRecord struct {
	Version            string
	Index              uint64
	ScopeDigest        string
	Snapshot           egeproto.CapabilityAuthoritySnapshot
	AnchorID           string
	AnchorSequence     uint64
	PreviousRecordHash string
	RecordHash         string
}

func NewAnchoredFileCapabilityMonotonicRoot(
	path string,
	anchor CapabilityRootAnchor,
) (*AnchoredFileCapabilityMonotonicRoot, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("capability root ledger path is required")
	}
	if anchor == nil {
		return nil, errors.New("capability root anchor is required")
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
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"invalid observed capability authority: %w",
			err,
		)
	}
	scopeDigest, err := capabilityRootScopeDigest(scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}

	file, records, anchorID, anchorState, err := r.openVerified(ctx)
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

	if anchorState.Sequence == ^uint64(0) {
		return egeproto.CapabilityAuthoritySnapshot{}, errors.New(
			"capability root anchor sequence is exhausted",
		)
	}
	expectedIndex := uint64(len(records) + 1)
	if expectedIndex != anchorState.Sequence+1 {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"%w: next ledger index=%d anchor sequence=%d",
			ErrCapabilityRootAnchorMismatch,
			expectedIndex,
			anchorState.Sequence,
		)
	}

	record := capabilityRootRecord{
		Version:        anchoredCapabilityRootVersion,
		Index:          expectedIndex,
		ScopeDigest:    scopeDigest,
		Snapshot:       observed,
		AnchorID:       anchorID,
		AnchorSequence: expectedIndex,
	}
	if len(records) != 0 {
		record.PreviousRecordHash = records[len(records)-1].RecordHash
	}
	record.RecordHash, err = capabilityRootRecordHash(record)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}

	nextAnchor := CapabilityRootAnchorState{
		Sequence:   expectedIndex,
		Commitment: record.RecordHash,
	}
	advanced, err := r.anchor.Advance(ctx, anchorState, nextAnchor)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"advance capability root anchor: %w",
			err,
		)
	}
	if advanced != nextAnchor {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"%w: anchor advanced to sequence=%d commitment=%q; expected sequence=%d commitment=%q",
			ErrCapabilityRootAnchorMismatch,
			advanced.Sequence,
			advanced.Commitment,
			nextAnchor.Sequence,
			nextAnchor.Commitment,
		)
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"encode capability root record: %w",
			err,
		)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"seek capability root ledger: %w",
			err,
		)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"append capability root ledger: %w",
			err,
		)
	}
	if err := file.Sync(); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"sync capability root ledger: %w",
			err,
		)
	}
	if err := syncCapabilityRootDirectory(filepath.Dir(r.path)); err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"sync capability root directory: %w",
			err,
		)
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
) (*os.File, []capabilityRootRecord, string, CapabilityRootAnchorState, error) {
	if r == nil || r.anchor == nil || strings.TrimSpace(r.path) == "" {
		return nil, nil, "", CapabilityRootAnchorState{}, errors.New(
			"anchored capability monotonic root is unavailable",
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, "", CapabilityRootAnchorState{}, err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"create capability root directory: %w",
			err,
		)
	}

	fd, err := unix.Open(
		r.path,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"open capability root ledger: %w",
			err,
		)
	}
	file := os.NewFile(uintptr(fd), r.path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, "", CapabilityRootAnchorState{}, errors.New(
			"wrap capability root ledger file descriptor",
		)
	}
	cleanup := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}

	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"lock capability root ledger: %w",
			err,
		)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"restrict capability root ledger permissions: %w",
			err,
		)
	}
	info, err := file.Stat()
	if err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"stat capability root ledger: %w",
			err,
		)
	}
	if !info.Mode().IsRegular() {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, errors.New(
			"capability root ledger is not a regular file",
		)
	}

	records, err := readCapabilityRootRecords(file)
	if err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, err
	}
	anchorID, err := r.anchor.Identity(ctx)
	if err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"read capability root anchor identity: %w",
			err,
		)
	}
	if strings.TrimSpace(anchorID) == "" {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, errors.New(
			"capability root anchor returned empty identity",
		)
	}
	anchorState, err := r.anchor.Current(ctx)
	if err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"read capability root anchor: %w",
			err,
		)
	}
	if err := validateCapabilityRootAnchorState(anchorState); err != nil {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, err
	}

	if len(records) == 0 {
		if anchorState.Sequence != 0 || anchorState.Commitment != "" {
			cleanup()
			return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
				"%w: empty ledger with anchor sequence=%d commitment=%q",
				ErrCapabilityRootRollback,
				anchorState.Sequence,
				anchorState.Commitment,
			)
		}
		return file, records, anchorID, anchorState, nil
	}

	last := records[len(records)-1]
	if last.AnchorID != anchorID {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: anchor identity changed from %q to %q",
			ErrCapabilityRootCorrupt,
			last.AnchorID,
			anchorID,
		)
	}
	if anchorState.Sequence != last.Index {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: anchor sequence=%d ledger index=%d",
			ErrCapabilityRootRollback,
			anchorState.Sequence,
			last.Index,
		)
	}
	if anchorState.Commitment != last.RecordHash {
		cleanup()
		return nil, nil, "", CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: anchor head=%q ledger head=%q",
			ErrCapabilityRootAnchorMismatch,
			anchorState.Commitment,
			last.RecordHash,
		)
	}
	return file, records, anchorID, anchorState, nil
}

func validateCapabilityRootAnchorState(state CapabilityRootAnchorState) error {
	if state.Sequence == 0 {
		if state.Commitment != "" {
			return fmt.Errorf(
				"%w: zero sequence with non-empty commitment",
				ErrCapabilityRootAnchorMismatch,
			)
		}
		return nil
	}
	if !isCapabilityRootDigest(state.Commitment) {
		return fmt.Errorf(
			"%w: non-zero sequence requires sha256 commitment",
			ErrCapabilityRootAnchorMismatch,
		)
	}
	return nil
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
			return nil, fmt.Errorf(
				"%w: empty record at line %d",
				ErrCapabilityRootCorrupt,
				line,
			)
		}
		var record capabilityRootRecord
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf(
				"%w: line %d: %v",
				ErrCapabilityRootCorrupt,
				line,
				err,
			)
		}
		if err := validateCapabilityRootRecord(records, record); err != nil {
			return nil, fmt.Errorf(
				"%w: line %d: %v",
				ErrCapabilityRootCorrupt,
				line,
				err,
			)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read capability root ledger: %w", err)
	}
	return records, nil
}

func validateCapabilityRootRecord(
	previous []capabilityRootRecord,
	record capabilityRootRecord,
) error {
	if record.Version != anchoredCapabilityRootVersion {
		return fmt.Errorf("unsupported capability root record version %q", record.Version)
	}
	if record.Index == 0 || record.AnchorSequence != record.Index {
		return errors.New("record index and anchor sequence must be equal and non-zero")
	}
	if strings.TrimSpace(record.AnchorID) == "" {
		return errors.New("anchor identity is required")
	}
	if !isCapabilityRootDigest(record.ScopeDigest) ||
		!isCapabilityRootDigest(record.RecordHash) {
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
	h.Write([]byte("aegis-ege/capability-root-record/v2\x00"))
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
