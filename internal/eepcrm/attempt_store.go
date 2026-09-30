package eepcrm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const AttemptRecordVersion = "aegis.eep/crm-attempt/v1"

var (
	ErrAttemptAlreadyClaimed = errors.New("CRM mutation attempt already claimed")
	ErrAttemptNotFound       = errors.New("CRM mutation attempt not found")
	ErrAttemptTransition     = errors.New("CRM mutation attempt transition invalid")
)

type AttemptState string

const (
	AttemptClaimed        AttemptState = "CLAIMED"
	AttemptPossibleEffect AttemptState = "POSSIBLE_EFFECT"
	AttemptAccepted       AttemptState = "ACCEPTED"
	AttemptBlocked        AttemptState = "BLOCKED"
	AttemptCompleted      AttemptState = "COMPLETED"
	AttemptRetiredUnknown AttemptState = "RETIRED_UNKNOWN"
)

type AttemptRecord struct {
	Version                 string       `json:"version"`
	AttemptID               string       `json:"attempt_id"`
	State                   AttemptState `json:"state"`
	IntentID                string       `json:"intent_id"`
	PermitDigest            string       `json:"permit_digest"`
	PlanDigest              string       `json:"plan_digest"`
	DestinationID           string       `json:"destination_id"`
	AccountID               string       `json:"account_id"`
	Endpoint                string       `json:"endpoint"`
	AdapterProfile          string       `json:"adapter_profile"`
	CustomerID              string       `json:"customer_id"`
	Operation               string       `json:"operation"`
	ExpectedResourceVersion string       `json:"expected_resource_version"`
	ObservationHandle       string       `json:"observation_handle"`
	ClaimedAt               time.Time    `json:"claimed_at"`
	UpdatedAt               time.Time    `json:"updated_at"`
	HTTPStatus              int          `json:"http_status,omitempty"`
	Detail                  string       `json:"detail,omitempty"`
}

type AttemptStore interface {
	Claim(context.Context, AttemptRecord) error
	Transition(context.Context, string, AttemptState, AttemptState, int, string, time.Time) (AttemptRecord, error)
	Load(context.Context, string) (AttemptRecord, error)
}

type FileAttemptStore struct {
	dir string
	mu  sync.Mutex
}

func NewFileAttemptStore(dir string) (*FileAttemptStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("CRM attempt store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CRM attempt store: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure CRM attempt store: %w", err)
	}
	return &FileAttemptStore{dir: dir}, nil
}

func MutationAttemptID(permitDigest, planDigest string) (string, error) {
	permitDigest = strings.TrimSpace(permitDigest)
	planDigest = strings.TrimSpace(planDigest)
	if permitDigest == "" || planDigest == "" {
		return "", errors.New("permit and plan digests are required for attempt identity")
	}
	sum := sha256.Sum256([]byte(permitDigest + "\x00" + planDigest))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *FileAttemptStore) Claim(ctx context.Context, record AttemptRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateAttemptRecord(record); err != nil {
		return err
	}
	if record.State != AttemptClaimed {
		return fmt.Errorf("%w: new attempt must start CLAIMED", ErrAttemptTransition)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.path(record.AttemptID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode CRM attempt: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAttemptAlreadyClaimed
	}
	if err != nil {
		return fmt.Errorf("claim CRM mutation attempt: %w", err)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write CRM mutation attempt: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync CRM mutation attempt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close CRM mutation attempt: %w", err)
	}
	return syncAttemptDir(s.dir)
}

func (s *FileAttemptStore) Transition(
	ctx context.Context,
	attemptID string,
	from AttemptState,
	to AttemptState,
	httpStatus int,
	detail string,
	at time.Time,
) (AttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return AttemptRecord{}, err
	}
	if !allowedAttemptTransition(from, to) {
		return AttemptRecord{}, ErrAttemptTransition
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.loadUnlocked(attemptID)
	if err != nil {
		return AttemptRecord{}, err
	}
	if record.State != from {
		return AttemptRecord{}, fmt.Errorf("%w: state=%s want=%s", ErrAttemptTransition, record.State, from)
	}
	record.State = to
	record.HTTPStatus = httpStatus
	record.Detail = strings.TrimSpace(detail)
	record.UpdatedAt = at.UTC()
	if err := s.writeAtomic(record); err != nil {
		return AttemptRecord{}, err
	}
	return record, nil
}

func (s *FileAttemptStore) Load(ctx context.Context, attemptID string) (AttemptRecord, error) {
	if err := ctx.Err(); err != nil {
		return AttemptRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadUnlocked(attemptID)
}

func (s *FileAttemptStore) loadUnlocked(attemptID string) (AttemptRecord, error) {
	path, err := s.path(attemptID)
	if err != nil {
		return AttemptRecord{}, err
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return AttemptRecord{}, ErrAttemptNotFound
	}
	if err != nil {
		return AttemptRecord{}, fmt.Errorf("read CRM mutation attempt: %w", err)
	}
	var record AttemptRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return AttemptRecord{}, fmt.Errorf("decode CRM mutation attempt: %w", err)
	}
	if err := validateAttemptRecord(record); err != nil {
		return AttemptRecord{}, err
	}
	if record.AttemptID != attemptID {
		return AttemptRecord{}, fmt.Errorf("%w: attempt identity mismatch", ErrAttemptTransition)
	}
	return record, nil
}

func (s *FileAttemptStore) writeAtomic(record AttemptRecord) error {
	path, err := s.path(record.AttemptID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode CRM mutation attempt: %w", err)
	}
	file, err := os.CreateTemp(s.dir, ".attempt-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncAttemptDir(s.dir)
}

func (s *FileAttemptStore) path(attemptID string) (string, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(attemptID, prefix) {
		return "", errors.New("CRM attempt id must be sha256")
	}
	hexPart := strings.TrimPrefix(attemptID, prefix)
	if len(hexPart) != 64 {
		return "", errors.New("CRM attempt id has invalid length")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", errors.New("CRM attempt id has invalid hex")
	}
	return filepath.Join(s.dir, hexPart+".json"), nil
}

func validateAttemptRecord(record AttemptRecord) error {
	switch {
	case record.Version != AttemptRecordVersion:
		return fmt.Errorf("unsupported CRM attempt record version %q", record.Version)
	case strings.TrimSpace(record.AttemptID) == "":
		return errors.New("CRM attempt id is required")
	case strings.TrimSpace(record.IntentID) == "":
		return errors.New("CRM attempt intent id is required")
	case strings.TrimSpace(record.PermitDigest) == "":
		return errors.New("CRM attempt permit digest is required")
	case strings.TrimSpace(record.PlanDigest) == "":
		return errors.New("CRM attempt plan digest is required")
	case strings.TrimSpace(record.DestinationID) == "":
		return errors.New("CRM attempt destination id is required")
	case strings.TrimSpace(record.AccountID) == "":
		return errors.New("CRM attempt account id is required")
	case strings.TrimSpace(record.Endpoint) == "":
		return errors.New("CRM attempt endpoint is required")
	case strings.TrimSpace(record.AdapterProfile) == "":
		return errors.New("CRM attempt adapter profile is required")
	case strings.TrimSpace(record.CustomerID) == "":
		return errors.New("CRM attempt customer id is required")
	case strings.TrimSpace(record.Operation) == "":
		return errors.New("CRM attempt operation is required")
	case strings.TrimSpace(record.ExpectedResourceVersion) == "":
		return errors.New("CRM attempt expected resource version is required")
	case strings.TrimSpace(record.ObservationHandle) == "":
		return errors.New("CRM attempt observation handle is required")
	case record.ClaimedAt.IsZero() || record.UpdatedAt.IsZero():
		return errors.New("CRM attempt timestamps are required")
	default:
		return nil
	}
}

func allowedAttemptTransition(from, to AttemptState) bool {
	switch from {
	case AttemptClaimed:
		return to == AttemptBlocked || to == AttemptPossibleEffect || to == AttemptCompleted
	case AttemptPossibleEffect:
		return to == AttemptBlocked || to == AttemptAccepted || to == AttemptCompleted || to == AttemptRetiredUnknown
	case AttemptAccepted:
		return to == AttemptCompleted || to == AttemptRetiredUnknown
	default:
		return false
	}
}

func syncAttemptDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
