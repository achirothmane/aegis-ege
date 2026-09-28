package genesisbootstrap

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
	"time"

	"github.com/ucarion/jcs"
	"golang.org/x/sys/unix"

	"github.com/achirothmane/easl/genesis"
)

const AcceptanceLedgerVersion = "aegis.ege/genesis-acceptance-ledger/v1"

var (
	ErrAcceptanceRollback   = errors.New("Genesis acceptance rollback detected")
	ErrAcceptanceContinuity = errors.New("Genesis acceptance continuity violation")
	ErrAcceptanceCorrupt    = errors.New("Genesis acceptance ledger is corrupt")
)

type AcceptanceRecord struct {
	Version                     string    `json:"version"`
	Index                       uint64    `json:"index"`
	AcceptedAt                  time.Time `json:"accepted_at"`
	GenesisEpoch                uint64    `json:"genesis_epoch"`
	Sequence                    uint64    `json:"sequence"`
	ManifestHash                string    `json:"manifest_hash"`
	PreviousManifestHash        string    `json:"previous_manifest_hash,omitempty"`
	DoctrineEpoch               uint64    `json:"doctrine_epoch"`
	DoctrineManifestHash        string    `json:"doctrine_manifest_hash"`
	RevocationEpoch             uint64    `json:"revocation_epoch"`
	RevocationDigest            string    `json:"revocation_digest"`
	TrustRootEpoch              uint64    `json:"trust_root_epoch"`
	PreviousAcceptanceRecordHash string   `json:"previous_acceptance_record_hash,omitempty"`
	RecordHash                  string    `json:"record_hash"`
}

type AcceptanceCandidate struct {
	AcceptedAt           time.Time
	GenesisEpoch         uint64
	Sequence             uint64
	ManifestHash         string
	PreviousManifestHash string
	DoctrineEpoch        uint64
	DoctrineManifestHash string
	RevocationEpoch      uint64
	RevocationDigest     string
	TrustRootEpoch       uint64
}

type AcceptanceFloor struct {
	GenesisEpoch         uint64
	Sequence             uint64
	ManifestHash         string
	DoctrineEpoch        uint64
	DoctrineManifestHash string
	RevocationEpoch      uint64
	TrustRootEpoch       uint64
}

type FileAcceptanceLedger struct {
	path string
}

type AcceptanceSession struct {
	ledger     *FileAcceptanceLedger
	file       *os.File
	last       *AcceptanceRecord
	candidate  AcceptanceCandidate
	idempotent bool
	closed     bool
}

func NewFileAcceptanceLedger(path string) (*FileAcceptanceLedger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("Genesis acceptance ledger path is required")
	}
	return &FileAcceptanceLedger{path: filepath.Clean(path)}, nil
}

func NewAcceptanceCandidate(m genesis.Manifest, revocations SignedRevocationList, now time.Time) (AcceptanceCandidate, error) {
	if now.IsZero() {
		return AcceptanceCandidate{}, errors.New("acceptance time is zero")
	}
	manifestHash, err := ManifestHash(m)
	if err != nil {
		return AcceptanceCandidate{}, fmt.Errorf("hash Genesis manifest: %w", err)
	}
	revocationDigest, err := SignedRevocationListDigest(revocations)
	if err != nil {
		return AcceptanceCandidate{}, fmt.Errorf("hash signed revocation list: %w", err)
	}
	return AcceptanceCandidate{
		AcceptedAt:           now.UTC(),
		GenesisEpoch:         m.GenesisEpoch,
		Sequence:             m.Sequence,
		ManifestHash:         manifestHash,
		PreviousManifestHash: m.PreviousManifestHash,
		DoctrineEpoch:        m.Doctrine.DoctrineEpoch,
		DoctrineManifestHash: m.Doctrine.DoctrineManifestHash,
		RevocationEpoch:      revocations.List.Epoch,
		RevocationDigest:     revocationDigest,
		TrustRootEpoch:       m.Trust.TrustRootEpoch,
	}, nil
}

func (l *FileAcceptanceLedger) Begin(_ context.Context, candidate AcceptanceCandidate) (*AcceptanceSession, AcceptanceFloor, error) {
	if l == nil || strings.TrimSpace(l.path) == "" {
		return nil, AcceptanceFloor{}, errors.New("Genesis acceptance ledger is unavailable")
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return nil, AcceptanceFloor{}, fmt.Errorf("create acceptance ledger directory: %w", err)
	}

	fd, err := unix.Open(l.path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, AcceptanceFloor{}, fmt.Errorf("open Genesis acceptance ledger: %w", err)
	}
	file := os.NewFile(uintptr(fd), l.path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, AcceptanceFloor{}, errors.New("wrap Genesis acceptance ledger file descriptor")
	}
	cleanup := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}

	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, AcceptanceFloor{}, fmt.Errorf("lock Genesis acceptance ledger: %w", err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		cleanup()
		return nil, AcceptanceFloor{}, fmt.Errorf("restrict Genesis acceptance ledger permissions: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		cleanup()
		return nil, AcceptanceFloor{}, fmt.Errorf("stat Genesis acceptance ledger: %w", err)
	}
	if !info.Mode().IsRegular() {
		cleanup()
		return nil, AcceptanceFloor{}, errors.New("Genesis acceptance ledger is not a regular file")
	}

	records, err := readAcceptanceRecords(file)
	if err != nil {
		cleanup()
		return nil, AcceptanceFloor{}, err
	}
	var last *AcceptanceRecord
	if len(records) != 0 {
		last = &records[len(records)-1]
	}
	idempotent, err := validateAcceptanceCandidate(last, candidate)
	if err != nil {
		cleanup()
		return nil, AcceptanceFloor{}, err
	}

	session := &AcceptanceSession{
		ledger:     l,
		file:       file,
		last:       last,
		candidate:  candidate,
		idempotent: idempotent,
	}
	return session, floorFromRecord(last), nil
}

func (s *AcceptanceSession) Commit() error {
	if s == nil || s.file == nil || s.closed {
		return errors.New("Genesis acceptance session is closed")
	}
	if s.idempotent {
		return nil
	}

	record := AcceptanceRecord{
		Version:              AcceptanceLedgerVersion,
		Index:                1,
		AcceptedAt:           s.candidate.AcceptedAt.UTC(),
		GenesisEpoch:         s.candidate.GenesisEpoch,
		Sequence:             s.candidate.Sequence,
		ManifestHash:         s.candidate.ManifestHash,
		PreviousManifestHash: s.candidate.PreviousManifestHash,
		DoctrineEpoch:        s.candidate.DoctrineEpoch,
		DoctrineManifestHash: s.candidate.DoctrineManifestHash,
		RevocationEpoch:      s.candidate.RevocationEpoch,
		RevocationDigest:     s.candidate.RevocationDigest,
		TrustRootEpoch:       s.candidate.TrustRootEpoch,
	}
	if s.last != nil {
		record.Index = s.last.Index + 1
		record.PreviousAcceptanceRecordHash = s.last.RecordHash
	}
	hash, err := acceptanceRecordHash(record)
	if err != nil {
		return err
	}
	record.RecordHash = hash
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode Genesis acceptance record: %w", err)
	}
	if _, err := s.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek Genesis acceptance ledger: %w", err)
	}
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("append Genesis acceptance ledger: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("sync Genesis acceptance ledger: %w", err)
	}
	if err := syncDirectory(filepath.Dir(s.ledger.path)); err != nil {
		return fmt.Errorf("sync Genesis acceptance ledger directory: %w", err)
	}
	s.last = &record
	s.idempotent = true
	return nil
}

func (s *AcceptanceSession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	fd := int(s.file.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := s.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func ManifestHash(m genesis.Manifest) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/genesis-manifest/v1\x00"))
	h.Write([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func readAcceptanceRecords(file *os.File) ([]AcceptanceRecord, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind Genesis acceptance ledger: %w", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var records []AcceptanceRecord
	for line := uint64(1); scanner.Scan(); line++ {
		payload := bytes.TrimSpace(scanner.Bytes())
		if len(payload) == 0 {
			return nil, fmt.Errorf("%w: empty record at line %d", ErrAcceptanceCorrupt, line)
		}
		var record AcceptanceRecord
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrAcceptanceCorrupt, line, err)
		}
		if err := validateAcceptanceRecord(records, record); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrAcceptanceCorrupt, line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Genesis acceptance ledger: %w", err)
	}
	return records, nil
}

func validateAcceptanceRecord(previous []AcceptanceRecord, record AcceptanceRecord) error {
	if record.Version != AcceptanceLedgerVersion {
		return fmt.Errorf("unsupported record version %q", record.Version)
	}
	if record.Index == 0 || record.AcceptedAt.IsZero() {
		return errors.New("record index and accepted_at are required")
	}
	for name, digest := range map[string]string{
		"manifest_hash":          record.ManifestHash,
		"doctrine_manifest_hash": record.DoctrineManifestHash,
		"revocation_digest":      record.RevocationDigest,
		"record_hash":            record.RecordHash,
	} {
		if !isSHA256Digest(digest) {
			return fmt.Errorf("%s is not a sha256 digest", name)
		}
	}
	expectedHash, err := acceptanceRecordHash(record)
	if err != nil {
		return err
	}
	if expectedHash != record.RecordHash {
		return errors.New("record hash mismatch")
	}

	if len(previous) == 0 {
		if record.Index != 1 {
			return errors.New("first record index must be 1")
		}
		if record.PreviousAcceptanceRecordHash != "" {
			return errors.New("first record cannot reference a previous acceptance record")
		}
		return nil
	}

	last := previous[len(previous)-1]
	if record.Index != last.Index+1 {
		return errors.New("acceptance record index is not contiguous")
	}
	if record.PreviousAcceptanceRecordHash != last.RecordHash {
		return errors.New("acceptance hash chain is broken")
	}
	candidate := AcceptanceCandidate{
		AcceptedAt:           record.AcceptedAt,
		GenesisEpoch:         record.GenesisEpoch,
		Sequence:             record.Sequence,
		ManifestHash:         record.ManifestHash,
		PreviousManifestHash: record.PreviousManifestHash,
		DoctrineEpoch:        record.DoctrineEpoch,
		DoctrineManifestHash: record.DoctrineManifestHash,
		RevocationEpoch:      record.RevocationEpoch,
		RevocationDigest:     record.RevocationDigest,
		TrustRootEpoch:       record.TrustRootEpoch,
	}
	idempotent, err := validateAcceptanceCandidate(&last, candidate)
	if err != nil {
		return err
	}
	if idempotent {
		return errors.New("duplicate idempotent acceptance record is not permitted")
	}
	return nil
}

func validateAcceptanceCandidate(last *AcceptanceRecord, candidate AcceptanceCandidate) (bool, error) {
	for name, digest := range map[string]string{
		"manifest_hash":          candidate.ManifestHash,
		"doctrine_manifest_hash": candidate.DoctrineManifestHash,
		"revocation_digest":      candidate.RevocationDigest,
	} {
		if !isSHA256Digest(digest) {
			return false, fmt.Errorf("%w: candidate %s is not a sha256 digest", ErrAcceptanceContinuity, name)
		}
	}

	if last == nil {
		if candidate.Sequence != 0 {
			return false, fmt.Errorf("%w: cannot initialize acceptance ledger from sequence %d without predecessor state", ErrAcceptanceContinuity, candidate.Sequence)
		}
		return false, nil
	}

	if candidate.GenesisEpoch < last.GenesisEpoch {
		return false, fmt.Errorf("%w: Genesis epoch %d is below accepted epoch %d", ErrAcceptanceRollback, candidate.GenesisEpoch, last.GenesisEpoch)
	}
	if candidate.DoctrineEpoch < last.DoctrineEpoch {
		return false, fmt.Errorf("%w: doctrine epoch %d is below accepted epoch %d", ErrAcceptanceRollback, candidate.DoctrineEpoch, last.DoctrineEpoch)
	}
	if candidate.DoctrineEpoch == last.DoctrineEpoch && candidate.DoctrineManifestHash != last.DoctrineManifestHash {
		return false, fmt.Errorf("%w: doctrine manifest changed without an epoch advance", ErrAcceptanceContinuity)
	}
	if candidate.RevocationEpoch < last.RevocationEpoch {
		return false, fmt.Errorf("%w: revocation epoch %d is below accepted epoch %d", ErrAcceptanceRollback, candidate.RevocationEpoch, last.RevocationEpoch)
	}
	if candidate.TrustRootEpoch < last.TrustRootEpoch {
		return false, fmt.Errorf("%w: trust-root epoch %d is below accepted epoch %d", ErrAcceptanceRollback, candidate.TrustRootEpoch, last.TrustRootEpoch)
	}

	if candidate.GenesisEpoch == last.GenesisEpoch {
		if candidate.Sequence < last.Sequence {
			return false, fmt.Errorf("%w: Genesis sequence %d is below accepted sequence %d", ErrAcceptanceRollback, candidate.Sequence, last.Sequence)
		}
		if candidate.Sequence == last.Sequence {
			if candidate.ManifestHash != last.ManifestHash {
				return false, fmt.Errorf("%w: same Genesis epoch/sequence has a different manifest hash", ErrAcceptanceContinuity)
			}
			return true, nil
		}
	}

	if candidate.PreviousManifestHash != last.ManifestHash {
		return false, fmt.Errorf("%w: previous_manifest_hash %q does not match last accepted manifest %q", ErrAcceptanceContinuity, candidate.PreviousManifestHash, last.ManifestHash)
	}
	return false, nil
}

func acceptanceRecordHash(record AcceptanceRecord) (string, error) {
	stable := record
	stable.RecordHash = ""
	raw, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/genesis-acceptance-record/v1\x00"))
	h.Write([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func floorFromRecord(record *AcceptanceRecord) AcceptanceFloor {
	if record == nil {
		return AcceptanceFloor{}
	}
	return AcceptanceFloor{
		GenesisEpoch:         record.GenesisEpoch,
		Sequence:             record.Sequence,
		ManifestHash:         record.ManifestHash,
		DoctrineEpoch:        record.DoctrineEpoch,
		DoctrineManifestHash: record.DoctrineManifestHash,
		RevocationEpoch:      record.RevocationEpoch,
		TrustRootEpoch:       record.TrustRootEpoch,
	}
}

func isSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
