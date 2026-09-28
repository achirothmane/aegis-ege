//go:build linux

package kernelfabric

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func ObserveOrphanedWorkload(
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	hostAttestorPublicKey ed25519.PublicKey,
	hostAttestorPrivateKey ed25519.PrivateKey,
	now time.Time,
) (SignedWorkloadRecoveryObservation, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	if state.State != LifecycleStateRunning && state.State != LifecycleStateQuarantined {
		return SignedWorkloadRecoveryObservation{}, ErrReconciliationRejected
	}
	if err := VerifySignedWorkloadActivationReceipt(activation, hostAttestorPublicKey); err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	if activation.Receipt.DeviceID != state.DeviceID ||
		activation.Receipt.WorkloadID != state.WorkloadID ||
		activationDigest != state.ActivationDigest {
		return SignedWorkloadRecoveryObservation{}, ErrLifecycleInvalidLineage
	}

	observationID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	obs := WorkloadRecoveryObservation{
		Version:          WorkloadRecoveryObservationVersion,
		ObservationID:    observationID,
		DeviceID:         state.DeviceID,
		WorkloadID:       state.WorkloadID,
		Generation:       state.Generation,
		ActivationID:     activation.Receipt.ActivationID,
		ActivationDigest: activationDigest,
		ProcessID:        activation.Receipt.ProcessID,
		ExpectedCgroup:   filepath.Clean(activation.Receipt.TargetCgroup),
		ExpectedCgroupID: activation.Receipt.TargetCgroupID,
		ObservedAt:       now.UTC(),
	}
	if state.State == LifecycleStateQuarantined {
		obs.PriorRecoveryDigest = state.RecoveryDigest
	}

	if activation.Receipt.Version != WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil {
		obs.State = RecoveryObservationLegacy
		obs.Detail = "activation receipt predates persistent process identity"
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	expected := *activation.Receipt.ProcessIdentity
	obs.ExpectedProcessIdentity = &expected

	bootHash, err := ReadBootIDHash(DefaultBootIDPath)
	if err != nil {
		obs.State = RecoveryObservationUnverifiable
		obs.Detail = "cannot read current boot identity: " + err.Error()
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	currentBoot := "sha256:" + hex.EncodeToString(bootHash[:])
	obs.CurrentBootIDHash = currentBoot
	if currentBoot != expected.BootIDHash {
		obs.State = RecoveryObservationBootChanged
		obs.Detail = "current boot differs from activation boot"
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}

	current, err := ObserveLinuxProcess(activation.Receipt.ProcessID)
	if err != nil {
		obs.State = RecoveryObservationUnverifiable
		obs.Detail = "process observation failed: " + err.Error()
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	if !current.Exists {
		obs.State = RecoveryObservationAbsent
		obs.Detail = "activation pid is absent"
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	observed := current.Identity
	obs.ObservedProcessIdentity = &observed
	obs.ObservedCgroup = current.ObservedCgroup
	obs.ObservedCgroupID = current.ObservedCgroupID

	if current.Identity != expected {
		obs.State = RecoveryObservationPIDReused
		obs.Detail = "pid exists but persistent process identity differs"
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	if current.ObservedCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(current.ObservedCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) {
		obs.State = RecoveryObservationCgroupMismatch
		obs.Detail = "matching process identity is outside signed target cgroup"
		return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
	}
	obs.State = RecoveryObservationMatchRunning
	obs.Detail = "process identity and cgroup match signed activation"
	return SignWorkloadRecoveryObservation(obs, hostAttestorPrivateKey)
}

func ApplyWorkloadReconciliation(
	store WorkloadLifecycleStore,
	decision SignedWorkloadReconciliationDecision,
	lifecycleAuthorityPublicKey ed25519.PublicKey,
) (WorkloadLifecycleState, error) {
	if err := VerifySignedWorkloadReconciliationDecision(
		decision,
		lifecycleAuthorityPublicKey,
	); err != nil {
		return WorkloadLifecycleState{}, err
	}
	d := decision.Decision
	digest, err := SignedWorkloadReconciliationDecisionDigest(decision)
	if err != nil {
		return WorkloadLifecycleState{}, err
	}
	var updated WorkloadLifecycleState
	err = store.withLockedState(
		d.DeviceID,
		d.WorkloadID,
		func(path string, state WorkloadLifecycleState, exists bool) error {
			if !exists ||
				state.State != LifecycleStateRunning ||
				state.Generation != d.Generation ||
				state.ActivationDigest != d.ActivationDigest {
				return ErrLifecycleInvalidLineage
			}
			switch d.Outcome {
			case ReconciliationKeepRunning:
				state.UpdatedAt = d.DecidedAt.UTC()
			case ReconciliationMarkExitedUnknown:
				state.State = LifecycleStateExitedUnknown
				state.ExitDigest = ""
				state.RecoveryDigest = digest
				clearRuntimeTrustState(&state)
				state.UpdatedAt = d.DecidedAt.UTC()
			case ReconciliationQuarantine:
				state.State = LifecycleStateQuarantined
				state.ExitDigest = ""
				state.RecoveryDigest = digest
				state.RuntimeTrustEpoch = 0
				state.RuntimeTrustLeaseDigest = ""
				state.RuntimeTrustExpiresAt = time.Time{}
				state.UpdatedAt = d.DecidedAt.UTC()
			default:
				return ErrReconciliationRejected
			}
			if err := writeLifecycleState(path, state); err != nil {
				return fmt.Errorf("persist reconciled lifecycle state: %w", err)
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

func RequireRecoverableLifecycle(state WorkloadLifecycleState) error {
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return err
	}
	switch state.State {
	case LifecycleStateRunning, LifecycleStateExitedUnknown:
		return nil
	case LifecycleStateQuarantined:
		return errors.New("workload lifecycle is quarantined and requires explicit operator recovery")
	default:
		return ErrReconciliationRejected
	}
}
