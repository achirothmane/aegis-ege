package server

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

	"github.com/achirothmane/aegis-ege/internal/decision"
)

var (
	ErrExecutionReplay          = errors.New("authorization was already claimed for execution")
	ErrExecutionClaimNotFound   = errors.New("execution claim state was not found")
	ErrExecutionClaimTransition = errors.New("execution claim state transition is invalid")
)

const ExecutionClaimRecordVersion = "aegis.ege/execution-claim/v0alpha1"

type ExecutionClaimState string

const (
	ExecutionClaimIssued   ExecutionClaimState = "ISSUED"
	ExecutionClaimClaimed  ExecutionClaimState = "CLAIMED"
	ExecutionClaimConsumed ExecutionClaimState = "CONSUMED"
	ExecutionClaimAborted  ExecutionClaimState = "ABORTED"
)

type ExecutionClaimRecord struct {
	Version            string              `json:"version"`
	State              ExecutionClaimState `json:"state"`
	ActionID           string              `json:"action_id"`
	Target             string              `json:"target"`
	AuthorityDomain    string              `json:"authority_domain,omitempty"`
	AuthorityTerm      uint64              `json:"authority_term,omitempty"`
	DecisionEpoch      uint64              `json:"decision_epoch,omitempty"`
	RevocationEpoch    uint64              `json:"revocation_epoch,omitempty"`
	TargetIdentity     string              `json:"target_identity,omitempty"`
	StateBindingDigest string              `json:"state_binding_digest,omitempty"`
	Outcome            string              `json:"outcome,omitempty"`
	Reason             string              `json:"reason,omitempty"`
}

type ReplayGuard interface {
	Claim(context.Context, decision.Authorization) error
}

type CapabilityClaimLifecycle interface {
	ReplayGuard
	Issue(context.Context, decision.Authorization) error
	Consume(context.Context, decision.Authorization, string) error
	Abort(context.Context, decision.Authorization, string) error
	State(context.Context, decision.Authorization) (ExecutionClaimRecord, error)
}

type FileReplayGuard struct {
	dir string
}

func NewFileReplayGuard(dir string) (*FileReplayGuard, error) {
	if dir == "" {
		return nil, fmt.Errorf("replay guard directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create replay guard directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure replay guard directory: %w", err)
	}
	return &FileReplayGuard{dir: dir}, nil
}

func (g *FileReplayGuard) Issue(ctx context.Context, auth decision.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return err
	}
	if _, err := os.Stat(g.claimPath(key)); err == nil {
		return ErrExecutionReplay
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect execution claim marker: %w", err)
	}

	record := newExecutionClaimRecord(auth, ExecutionClaimIssued)
	if err := writeNewExecutionClaimRecord(g.statePath(key), record); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("issue execution capability: %w", err)
		}
		existing, readErr := readExecutionClaimRecord(g.statePath(key))
		if readErr != nil {
			return fmt.Errorf("read existing issued execution capability: %w", readErr)
		}
		if validationErr := validateExecutionClaimRecord(existing, auth); validationErr != nil {
			return validationErr
		}
		if existing.State == ExecutionClaimIssued {
			return nil
		}
		return ErrExecutionReplay
	}
	if err := syncDirectory(g.dir); err != nil {
		return fmt.Errorf("sync issued execution capability directory: %w", err)
	}
	return nil
}

func (g *FileReplayGuard) Claim(ctx context.Context, auth decision.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return err
	}

	marker, err := os.OpenFile(g.claimPath(key), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrExecutionReplay
	}
	if err != nil {
		return fmt.Errorf("claim execution authorization: %w", err)
	}
	if _, err := marker.Write([]byte(auth.ActionID + "\n")); err != nil {
		_ = marker.Close()
		return fmt.Errorf("write execution claim marker: %w", err)
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		return fmt.Errorf("sync execution claim marker: %w", err)
	}
	if err := marker.Close(); err != nil {
		return fmt.Errorf("close execution claim marker: %w", err)
	}
	if err := syncDirectory(g.dir); err != nil {
		return fmt.Errorf("sync execution claim marker directory: %w", err)
	}

	record, err := readExecutionClaimRecord(g.statePath(key))
	switch {
	case err == nil:
		if err := validateExecutionClaimRecord(record, auth); err != nil {
			return err
		}
		if record.State != ExecutionClaimIssued {
			return ErrExecutionReplay
		}
		record.State = ExecutionClaimClaimed
		record.Outcome = ""
		record.Reason = ""
	case errors.Is(err, os.ErrNotExist):
		// Legacy replay-guard callers may claim without a prior capability Issue.
		record = newExecutionClaimRecord(auth, ExecutionClaimClaimed)
	default:
		return fmt.Errorf("read execution claim state: %w", err)
	}

	if err := writeExecutionClaimRecordAtomic(g.dir, g.statePath(key), record); err != nil {
		// The claim marker intentionally remains. A failed transition is fail-closed:
		// the capability cannot be replayed even if state persistence is unavailable.
		return fmt.Errorf("persist claimed execution capability: %w", err)
	}
	return nil
}

func (g *FileReplayGuard) Consume(
	ctx context.Context,
	auth decision.Authorization,
	outcome string,
) error {
	return g.finalize(ctx, auth, ExecutionClaimConsumed, strings.TrimSpace(outcome))
}

func (g *FileReplayGuard) Abort(
	ctx context.Context,
	auth decision.Authorization,
	reason string,
) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("%w: abort reason is required", ErrExecutionClaimTransition)
	}
	return g.finalize(ctx, auth, ExecutionClaimAborted, reason)
}

func (g *FileReplayGuard) State(
	ctx context.Context,
	auth decision.Authorization,
) (ExecutionClaimRecord, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionClaimRecord{}, err
	}
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return ExecutionClaimRecord{}, err
	}
	record, err := readExecutionClaimRecord(g.statePath(key))
	if err == nil {
		if err := validateExecutionClaimRecord(record, auth); err != nil {
			return ExecutionClaimRecord{}, err
		}
		return record, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ExecutionClaimRecord{}, err
	}
	if _, markerErr := os.Stat(g.claimPath(key)); markerErr == nil {
		// Backward compatibility for replay markers written before the lifecycle
		// record existed. Such markers are conservatively treated as CLAIMED.
		return newExecutionClaimRecord(auth, ExecutionClaimClaimed), nil
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return ExecutionClaimRecord{}, markerErr
	}
	return ExecutionClaimRecord{}, ErrExecutionClaimNotFound
}

func (g *FileReplayGuard) finalize(
	ctx context.Context,
	auth decision.Authorization,
	state ExecutionClaimState,
	detail string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return err
	}

	markerPath := g.finalizePath(key)
	markerValue := string(state) + "\n" + detail + "\n"
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		payload, readErr := os.ReadFile(markerPath)
		if readErr != nil {
			return fmt.Errorf("read execution finalization marker: %w", readErr)
		}
		if string(payload) != markerValue {
			return ErrExecutionClaimTransition
		}
	} else if err != nil {
		return fmt.Errorf("create execution finalization marker: %w", err)
	} else {
		if _, err := marker.Write([]byte(markerValue)); err != nil {
			_ = marker.Close()
			return fmt.Errorf("write execution finalization marker: %w", err)
		}
		if err := marker.Sync(); err != nil {
			_ = marker.Close()
			return fmt.Errorf("sync execution finalization marker: %w", err)
		}
		if err := marker.Close(); err != nil {
			return fmt.Errorf("close execution finalization marker: %w", err)
		}
		if err := syncDirectory(g.dir); err != nil {
			return fmt.Errorf("sync execution finalization marker directory: %w", err)
		}
	}

	record, err := readExecutionClaimRecord(g.statePath(key))
	if err != nil {
		return fmt.Errorf("read execution claim state for finalization: %w", err)
	}
	if err := validateExecutionClaimRecord(record, auth); err != nil {
		return err
	}
	if record.State == state {
		if state == ExecutionClaimConsumed && record.Outcome == detail {
			return nil
		}
		if state == ExecutionClaimAborted && record.Reason == detail {
			return nil
		}
		return ErrExecutionClaimTransition
	}
	if record.State != ExecutionClaimClaimed {
		return ErrExecutionClaimTransition
	}

	record.State = state
	record.Outcome = ""
	record.Reason = ""
	switch state {
	case ExecutionClaimConsumed:
		record.Outcome = detail
	case ExecutionClaimAborted:
		record.Reason = detail
	default:
		return ErrExecutionClaimTransition
	}
	if err := writeExecutionClaimRecordAtomic(g.dir, g.statePath(key), record); err != nil {
		return fmt.Errorf("persist terminal execution claim state: %w", err)
	}
	return nil
}

func (g *FileReplayGuard) statePath(key string) string {
	return filepath.Join(g.dir, key+".state.json")
}

func (g *FileReplayGuard) claimPath(key string) string {
	return filepath.Join(g.dir, key+".claimed")
}

func (g *FileReplayGuard) finalizePath(key string) string {
	return filepath.Join(g.dir, key+".finalized")
}

func newExecutionClaimRecord(
	auth decision.Authorization,
	state ExecutionClaimState,
) ExecutionClaimRecord {
	return ExecutionClaimRecord{
		Version:            ExecutionClaimRecordVersion,
		State:              state,
		ActionID:           auth.ActionID,
		Target:             auth.Target,
		AuthorityDomain:    auth.AuthorityDomain,
		AuthorityTerm:      auth.AuthorityTerm,
		DecisionEpoch:      auth.DecisionEpoch,
		RevocationEpoch:    auth.RevocationEpoch,
		TargetIdentity:     auth.TargetIdentity,
		StateBindingDigest: auth.StateBindingDigest,
	}
}


func validateExecutionClaimRecord(
	record ExecutionClaimRecord,
	auth decision.Authorization,
) error {
	if record.Version != ExecutionClaimRecordVersion {
		return fmt.Errorf(
			"unsupported execution claim record version %q",
			record.Version,
		)
	}
	if record.ActionID != auth.ActionID ||
		record.Target != auth.Target ||
		record.AuthorityDomain != auth.AuthorityDomain ||
		record.AuthorityTerm != auth.AuthorityTerm ||
		record.DecisionEpoch != auth.DecisionEpoch ||
		record.RevocationEpoch != auth.RevocationEpoch ||
		record.TargetIdentity != auth.TargetIdentity ||
		record.StateBindingDigest != auth.StateBindingDigest {
		return fmt.Errorf(
			"%w: persisted claim binding does not match authorization",
			ErrExecutionClaimTransition,
		)
	}
	return nil
}

func readExecutionClaimRecord(path string) (ExecutionClaimRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return ExecutionClaimRecord{}, err
	}
	var record ExecutionClaimRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return ExecutionClaimRecord{}, fmt.Errorf("decode execution claim state: %w", err)
	}
	if record.Version != ExecutionClaimRecordVersion {
		return ExecutionClaimRecord{}, fmt.Errorf(
			"unsupported execution claim record version %q",
			record.Version,
		)
	}
	return record, nil
}

func writeNewExecutionClaimRecord(path string, record ExecutionClaimRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode execution claim state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
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
	return file.Close()
}

func writeExecutionClaimRecordAtomic(
	dir string,
	path string,
	record ExecutionClaimRecord,
) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode execution claim state: %w", err)
	}
	file, err := os.CreateTemp(dir, ".claim-state-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

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
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func authorizationReplayKey(auth decision.Authorization) (string, error) {
	payload, err := json.Marshal(struct {
		ActionID           string
		Action             string
		Target             string
		ResourceVersion    string
		EvidenceDigest     string
		PlanDigest         string
		AuthorityDomain    string
		AuthorityTerm      uint64
		DecisionEpoch      uint64
		RevocationEpoch    uint64
		TargetIdentity     string
		StateBindingDigest string
		ValidUntil         string
	}{
		ActionID:           auth.ActionID,
		Action:             auth.Action,
		Target:             auth.Target,
		ResourceVersion:    auth.ResourceVersion,
		EvidenceDigest:     auth.EvidenceDigest,
		PlanDigest:         auth.PlanDigest,
		AuthorityDomain:    auth.AuthorityDomain,
		AuthorityTerm:      auth.AuthorityTerm,
		DecisionEpoch:      auth.DecisionEpoch,
		RevocationEpoch:    auth.RevocationEpoch,
		TargetIdentity:     auth.TargetIdentity,
		StateBindingDigest: auth.StateBindingDigest,
		ValidUntil:         auth.ValidUntil.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
	if err != nil {
		return "", fmt.Errorf("encode authorization replay key: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
