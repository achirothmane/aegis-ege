//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"time"
)

func ApplyQuarantineRelease(
	store WorkloadLifecycleStore,
	release SignedQuarantineReleaseDecision,
	lifecycleAuthorityPublicKey ed25519.PublicKey,
	now time.Time,
) (WorkloadLifecycleState, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedQuarantineReleaseDecision(
		release,
		lifecycleAuthorityPublicKey,
		now,
	); err != nil {
		return WorkloadLifecycleState{}, err
	}
	d := release.Decision
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(release)
	if err != nil {
		return WorkloadLifecycleState{}, err
	}
	var updated WorkloadLifecycleState
	err = store.withLockedState(
		d.DeviceID,
		d.WorkloadID,
		func(path string, state WorkloadLifecycleState, exists bool) error {
			if !exists {
				return ErrLifecycleInvalidLineage
			}
			state = NormalizeWorkloadLifecycleState(state)
			if state.State != LifecycleStateQuarantined ||
				state.Generation != d.Generation ||
				state.LifecycleEpoch != d.PreviousLifecycleEpoch ||
				state.ActivationDigest != d.ActivationDigest ||
				state.RecoveryDigest != d.QuarantineRecoveryDigest ||
				d.NewLifecycleEpoch != state.LifecycleEpoch+1 {
				return ErrLifecycleInvalidLineage
			}
			state.State = LifecycleStateExitedUnknown
			state.LifecycleEpoch = d.NewLifecycleEpoch
			state.ExitDigest = ""
			state.RecoveryDigest = releaseDigest
			state.UpdatedAt = d.DecidedAt.UTC()
			if err := writeLifecycleState(path, state); err != nil {
				return err
			}
			updated = state
			return nil
		},
	)
	if err != nil {
		return WorkloadLifecycleState{}, err
	}
	return updated, nil
}
