//go:build linux

package kernelfabric

import (
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLifecycleStorePersistsAndReadsState(t *testing.T) {
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	now := time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC)
	state := WorkloadLifecycleState{
		Version:                WorkloadLifecycleStateVersion,
		DeviceID:               "device-1",
		WorkloadID:             "workload-1",
		Generation:             1,
		State:                  LifecycleStateRunning,
		ActivationDigest:       "sha256:" + string(make([]byte, 0)),
		RestartCountInWindow:   0,
		RestartWindowStartedAt: now,
		UpdatedAt:              now,
	}
	state.ActivationDigest = "sha256:" + repeatHex("a", 64)

	err := store.withLockedState(
		state.DeviceID,
		state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, exists bool) error {
			if exists {
				t.Fatal("unexpected pre-existing lifecycle state")
			}
			return writeLifecycleState(path, state)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, exists, err := store.Read(state.DeviceID, state.WorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || got.Generation != 1 || got.State != LifecycleStateRunning ||
		got.ActivationDigest != state.ActivationDigest {
		t.Fatalf("unexpected lifecycle state: %+v exists=%v", got, exists)
	}
}

func TestLifecycleStoreSerializesConcurrentMutation(t *testing.T) {
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	now := time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC)
	initial := WorkloadLifecycleState{
		Version:                WorkloadLifecycleStateVersion,
		DeviceID:               "device-1",
		WorkloadID:             "workload-1",
		Generation:             1,
		State:                  LifecycleStateRunning,
		ActivationDigest:       "sha256:" + repeatHex("a", 64),
		RestartWindowStartedAt: now,
		UpdatedAt:              now,
	}
	if err := store.withLockedState(
		initial.DeviceID,
		initial.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, initial)
		},
	); err != nil {
		t.Fatal(err)
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.withLockedState(
				initial.DeviceID,
				initial.WorkloadID,
				func(path string, state WorkloadLifecycleState, exists bool) error {
					if !exists {
						return errors.New("state disappeared")
					}
					state.Generation++
					state.UpdatedAt = state.UpdatedAt.Add(time.Nanosecond)
					return writeLifecycleState(path, state)
				},
			)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, exists, err := store.Read(initial.DeviceID, initial.WorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || got.Generation != 1+workers {
		t.Fatalf("lost serialized lifecycle updates: %+v", got)
	}
}

func TestLifecycleStoreRejectsInvalidStateOnWrite(t *testing.T) {
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	err := store.withLockedState(
		"device-1",
		"workload-1",
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, WorkloadLifecycleState{
				Version:    WorkloadLifecycleStateVersion,
				DeviceID:   "device-1",
				WorkloadID: "workload-1",
				Generation: 1,
				State:      LifecycleStateRunning,
			})
		},
	)
	if err == nil {
		t.Fatal("expected invalid lifecycle state write rejection")
	}
}

func TestClassifyProcessExit(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		wantClass string
		wantCode  int
		wantSig   int
	}{
		{"clean", "exit 0", ExitClassClean, 0, 0},
		{"nonzero", "exit 7", ExitClassNonZero, 7, 0},
		{"signal", "kill -TERM $$", ExitClassSignal, 143, 15},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", tc.script)
			err := cmd.Run()
			class, code, sig, classifyErr := classifyProcessExit(cmd, err)
			if classifyErr != nil {
				t.Fatal(classifyErr)
			}
			if class != tc.wantClass || code != tc.wantCode || sig != tc.wantSig {
				t.Fatalf("got class=%s code=%d sig=%d want class=%s code=%d sig=%d",
					class, code, sig, tc.wantClass, tc.wantCode, tc.wantSig)
			}
		})
	}
}

func repeatHex(ch string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ch
	}
	return out
}
