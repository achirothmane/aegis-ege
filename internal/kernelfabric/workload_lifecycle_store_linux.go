//go:build linux

package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type WorkloadLifecycleStore struct {
	Dir string
}

func (s WorkloadLifecycleStore) Read(
	deviceID string,
	workloadID string,
) (WorkloadLifecycleState, bool, error) {
	var out WorkloadLifecycleState
	var exists bool
	err := s.withLockedState(
		deviceID,
		workloadID,
		func(_ string, state WorkloadLifecycleState, found bool) error {
			out = state
			exists = found
			return nil
		},
	)
	return out, exists, err
}

func (s WorkloadLifecycleStore) withLockedState(
	deviceID string,
	workloadID string,
	fn func(path string, state WorkloadLifecycleState, exists bool) error,
) error {
	dir := filepath.Clean(strings.TrimSpace(s.Dir))
	if dir == "." || !filepath.IsAbs(dir) {
		return errors.New("workload lifecycle directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create workload lifecycle directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure workload lifecycle directory: %w", err)
	}

	key := sha256.Sum256([]byte(strings.TrimSpace(deviceID) + "\x00" + strings.TrimSpace(workloadID)))
	base := hex.EncodeToString(key[:])
	lockPath := filepath.Join(dir, base+".lock")
	statePath := filepath.Join(dir, base+".state.json")

	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open workload lifecycle lock: %w", err)
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock workload lifecycle: %w", err)
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)

	state, exists, err := readLifecycleState(statePath)
	if err != nil {
		return err
	}
	if exists && (state.DeviceID != strings.TrimSpace(deviceID) || state.WorkloadID != strings.TrimSpace(workloadID)) {
		return ErrLifecycleInvalidLineage
	}
	return fn(statePath, state, exists)
}

func readLifecycleState(path string) (WorkloadLifecycleState, bool, error) {
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return WorkloadLifecycleState{}, false, nil
	}
	if err != nil {
		return WorkloadLifecycleState{}, false, fmt.Errorf("read workload lifecycle state: %w", err)
	}
	var state WorkloadLifecycleState
	if err := json.Unmarshal(payload, &state); err != nil {
		return WorkloadLifecycleState{}, false, fmt.Errorf("decode workload lifecycle state: %w", err)
	}
	if state.Version != WorkloadLifecycleStateVersion ||
		strings.TrimSpace(state.DeviceID) == "" ||
		strings.TrimSpace(state.WorkloadID) == "" ||
		state.Generation == 0 ||
		(state.State != LifecycleStateRunning && state.State != LifecycleStateExited) ||
		state.UpdatedAt.IsZero() {
		return WorkloadLifecycleState{}, false, errors.New("workload lifecycle state is invalid")
	}
	if _, err := ParseSHA256Digest(state.ActivationDigest); err != nil {
		return WorkloadLifecycleState{}, false, fmt.Errorf("lifecycle activation digest: %w", err)
	}
	if state.State == LifecycleStateExited {
		if _, err := ParseSHA256Digest(state.ExitDigest); err != nil {
			return WorkloadLifecycleState{}, false, fmt.Errorf("lifecycle exit digest: %w", err)
		}
	}
	return state, true, nil
}

func writeLifecycleState(path string, state WorkloadLifecycleState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".lifecycle-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
