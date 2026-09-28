//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func ApplyRuntimeTrustLease(
	store WorkloadLifecycleStore,
	lease SignedRuntimeTrustLease,
	lifecycleAuthorityPublicKey ed25519.PublicKey,
	now time.Time,
) (WorkloadLifecycleState, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedRuntimeTrustLease(
		lease,
		lifecycleAuthorityPublicKey,
		now,
	); err != nil {
		return WorkloadLifecycleState{}, err
	}
	leaseDigest, err := SignedRuntimeTrustLeaseDigest(lease)
	if err != nil {
		return WorkloadLifecycleState{}, err
	}
	l := lease.Lease
	var updated WorkloadLifecycleState
	err = store.withLockedState(
		l.DeviceID,
		l.WorkloadID,
		func(path string, state WorkloadLifecycleState, exists bool) error {
			if !exists {
				return ErrLifecycleInvalidLineage
			}
			state = NormalizeWorkloadLifecycleState(state)
			expectedEpoch := state.RuntimeTrustEpoch + 1
			if state.State != LifecycleStateRunning ||
				state.Generation != l.Generation ||
				EffectiveLifecycleEpoch(state) != l.LifecycleEpoch ||
				state.ActivationDigest != l.ActivationDigest ||
				l.LeaseEpoch != expectedEpoch {
				return ErrRuntimeTrustRollback
			}
			state.RuntimeTrustEpoch = l.LeaseEpoch
			state.RuntimeTrustLeaseDigest = leaseDigest
			state.RuntimeTrustExpiresAt = l.ExpiresAt.UTC()
			state.UpdatedAt = now.UTC()
			if err := writeLifecycleState(path, state); err != nil {
				return fmt.Errorf("persist runtime trust lease: %w", err)
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

func ContainRuntimeTrustRevocation(
	ctx context.Context,
	installer Installer,
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	decision SignedRuntimeTrustDecision,
	lifecycleAuthorityPublicKey ed25519.PublicKey,
	hostAttestorPrivateKey ed25519.PrivateKey,
	now time.Time,
) (SignedWorkloadRecoveryObservation, ScopeFenceState, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	if state.State != LifecycleStateRunning {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, ErrRuntimeTrustInvalid
	}
	if len(hostAttestorPrivateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, errors.New("host attestor private key is required")
	}
	hostPub := hostAttestorPrivateKey.Public().(ed25519.PublicKey)
	if err := VerifySignedWorkloadActivationReceipt(activation, hostPub); err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	if err := VerifySignedRuntimeTrustDecision(
		decision,
		lifecycleAuthorityPublicKey,
	); err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	if decision.Decision.Outcome != RuntimeTrustRevoke {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, ErrRuntimeTrustRevokeRequired
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	runtimeDigest, err := SignedRuntimeTrustDecisionDigest(decision)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	d := decision.Decision
	if d.DeviceID != state.DeviceID ||
		d.WorkloadID != state.WorkloadID ||
		d.Generation != state.Generation ||
		d.LifecycleEpoch != EffectiveLifecycleEpoch(state) ||
		d.ActivationDigest != activationDigest ||
		d.RuntimeLeaseEpoch != state.RuntimeTrustEpoch ||
		d.RuntimeLeaseDigest != state.RuntimeTrustLeaseDigest ||
		d.TargetCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(d.TargetCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) ||
		state.ActivationDigest != activationDigest {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, ErrLifecycleInvalidLineage
	}

	fenceKey, err := FenceKey(d.TargetCgroupID, ActionClassNetworkConnect)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, err
	}
	nextFence, err := installer.RevokeCurrentScope(ctx, fenceKey)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, ScopeFenceState{}, fmt.Errorf(
			"revoke runtime network authority before quarantine evidence: %w",
			err,
		)
	}

	if activation.Receipt.Version != WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil {
		return SignedWorkloadRecoveryObservation{}, nextFence, errors.New(
			"runtime trust containment requires process-bound activation receipt v2",
		)
	}
	current, err := ObserveLinuxProcess(activation.Receipt.ProcessID)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, nextFence, fmt.Errorf(
			"observe process after kernel revocation: %w",
			err,
		)
	}
	if !current.Exists {
		return SignedWorkloadRecoveryObservation{}, nextFence, errors.New(
			"workload exited after kernel revocation before runtime quarantine observation",
		)
	}
	expected := *activation.Receipt.ProcessIdentity
	if current.Identity != expected ||
		current.ObservedCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(current.ObservedCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) {
		return SignedWorkloadRecoveryObservation{}, nextFence, errors.New(
			"workload process identity changed after kernel revocation",
		)
	}
	observed := current.Identity
	observationID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, nextFence, err
	}
	obs := WorkloadRecoveryObservation{
		Version:                    WorkloadRecoveryObservationVersion,
		ObservationID:              observationID,
		DeviceID:                   state.DeviceID,
		WorkloadID:                 state.WorkloadID,
		Generation:                 state.Generation,
		ActivationID:               activation.Receipt.ActivationID,
		ActivationDigest:           activationDigest,
		RuntimeTrustDecisionDigest: runtimeDigest,
		ProcessID:                  activation.Receipt.ProcessID,
		ExpectedProcessIdentity:    &expected,
		ObservedProcessIdentity:    &observed,
		CurrentBootIDHash:          expected.BootIDHash,
		ExpectedCgroup:             filepath.Clean(activation.Receipt.TargetCgroup),
		ExpectedCgroupID:           activation.Receipt.TargetCgroupID,
		ObservedCgroup:             filepath.Clean(current.ObservedCgroup),
		ObservedCgroupID:           current.ObservedCgroupID,
		State:                      RecoveryObservationRuntimeTrustRevoked,
		Detail:                     "kernel network authority revoked after runtime trust failure",
		ObservedAt:                 now.UTC(),
	}
	signed, err := SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, nextFence, err
	}
	return signed, nextFence, nil
}
