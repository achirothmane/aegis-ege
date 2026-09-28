//go:build linux

package kernelfabric

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyQuarantineReleaseAdvancesEpochAndIsOneShot(t *testing.T) {
	q := newQuarantineFixture(t)
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		q.state.DeviceID,
		q.state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, exists bool) error {
			if exists {
				t.Fatal("unexpected existing lifecycle state")
			}
			return writeLifecycleState(path, q.state)
		},
	); err != nil {
		t.Fatal(err)
	}

	applyAt := q.recovery.base.Add(12 * time.Second)
	state, err := ApplyQuarantineRelease(
		store,
		q.release,
		q.recovery.lifecyclePub,
		applyAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(q.release)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != LifecycleStateExitedUnknown ||
		state.LifecycleEpoch != 2 ||
		state.RecoveryDigest != releaseDigest {
		t.Fatalf("unexpected released lifecycle state: %+v", state)
	}

	_, err = ApplyQuarantineRelease(
		store,
		q.release,
		q.recovery.lifecyclePub,
		applyAt,
	)
	if !errors.Is(err, ErrLifecycleInvalidLineage) {
		t.Fatalf("release decision was replayable: %v", err)
	}
}

func TestLifecycleStoreNormalizesLegacyMissingEpochToOne(t *testing.T) {
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	state := WorkloadLifecycleState{
		Version:                WorkloadLifecycleStateVersion,
		DeviceID:               "device-legacy",
		WorkloadID:             "workload-legacy",
		Generation:             1,
		LifecycleEpoch:         0,
		State:                  LifecycleStateExitedUnknown,
		ActivationDigest:       "sha256:" + repeatHex("a", 64),
		RecoveryDigest:         "sha256:" + repeatHex("b", 64),
		RestartWindowStartedAt: time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC),
		UpdatedAt:              time.Date(2026, 9, 28, 4, 0, 1, 0, time.UTC),
	}
	if err := store.withLockedState(
		state.DeviceID,
		state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, state)
		},
	); err != nil {
		t.Fatal(err)
	}
	got, exists, err := store.Read(state.DeviceID, state.WorkloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || got.LifecycleEpoch != 1 {
		t.Fatalf("legacy lifecycle epoch was not normalized: %+v", got)
	}
}
