//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

type GovernedWorkloadLaunchRequest struct {
	LaunchRequest               AttestedWorkloadLaunchRequest
	LifecycleStore              WorkloadLifecycleStore
	RestartDecision             *SignedWorkloadRestartDecision
	LifecycleAuthorityPublicKey ed25519.PublicKey
}

func StartGovernedWorkload(
	ctx context.Context,
	req GovernedWorkloadLaunchRequest,
) (AttestedWorkloadProcess, WorkloadLifecycleState, error) {
	grant := req.LaunchRequest.SignedGrant.Grant
	now := req.LaunchRequest.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var started AttestedWorkloadProcess
	var nextState WorkloadLifecycleState
	err := req.LifecycleStore.withLockedState(
		grant.DeviceID,
		grant.WorkloadID,
		func(path string, state WorkloadLifecycleState, exists bool) error {
			if exists && state.State == LifecycleStateRunning {
				return ErrLifecycleAlreadyRunning
			}

			if !exists {
				if req.RestartDecision != nil {
					return ErrLifecycleInvalidLineage
				}
				nextState = WorkloadLifecycleState{
					Version:                WorkloadLifecycleStateVersion,
					DeviceID:               grant.DeviceID,
					WorkloadID:             grant.WorkloadID,
					Generation:             1,
					LifecycleEpoch:         1,
					State:                  LifecycleStateRunning,
					RestartCountInWindow:   0,
					RestartWindowStartedAt: now,
					UpdatedAt:              now,
				}
			} else {
				if (state.State != LifecycleStateExited && state.State != LifecycleStateExitedUnknown) ||
					req.RestartDecision == nil {
					return ErrRestartDecisionRejected
				}
				if len(req.LifecycleAuthorityPublicKey) != ed25519.PublicKeySize {
					return errors.New("lifecycle authority public key is required for restart")
				}
				if err := ValidateRestartForLifecycleState(
					state,
					req.LaunchRequest.SignedGrant,
					*req.RestartDecision,
					req.LifecycleAuthorityPublicKey,
					now,
				); err != nil {
					return err
				}
				decision := req.RestartDecision.Decision
				nextState = state
				nextState.Generation = state.Generation + 1
				nextState.State = LifecycleStateRunning
				nextState.ExitDigest = ""
				nextState.RecoveryDigest = ""
				nextState.RestartCountInWindow = decision.RestartCountInWindow + 1
				nextState.RestartWindowStartedAt = decision.RestartWindowStartedAt
				nextState.UpdatedAt = now
			}

			var err error
			started, err = StartAttestedWorkload(ctx, req.LaunchRequest)
			if err != nil {
				return err
			}
			activationDigest, err := SignedWorkloadActivationReceiptDigest(started.SignedReceipt)
			if err != nil {
				_ = started.Command.Process.Kill()
				_, _ = started.Command.Process.Wait()
				return err
			}
			nextState.ActivationDigest = activationDigest
			if err := writeLifecycleState(path, nextState); err != nil {
				_ = started.Command.Process.Kill()
				_, _ = started.Command.Process.Wait()
				return fmt.Errorf("persist RUNNING lifecycle state after start; workload killed: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return AttestedWorkloadProcess{}, WorkloadLifecycleState{}, err
	}
	return started, nextState, nil
}

func WaitGovernedWorkload(
	started AttestedWorkloadProcess,
	store WorkloadLifecycleStore,
	hostAttestorKey ed25519.PrivateKey,
) (SignedWorkloadExitReceipt, int, error) {
	if started.Command == nil || started.Command.Process == nil {
		return SignedWorkloadExitReceipt{}, 0, errors.New("attested workload process is not initialized")
	}
	if len(hostAttestorKey) != ed25519.PrivateKeySize {
		return SignedWorkloadExitReceipt{}, 0, errors.New("host lifecycle attestor private key is required")
	}

	waitErr := started.Command.Wait()
	exitedAt := time.Now().UTC()
	exitClass, exitCode, signal, classifyErr := classifyProcessExit(started.Command, waitErr)
	if classifyErr != nil {
		return SignedWorkloadExitReceipt{}, 0, classifyErr
	}
	activation := started.SignedReceipt.Receipt
	activationDigest, err := SignedWorkloadActivationReceiptDigest(started.SignedReceipt)
	if err != nil {
		return SignedWorkloadExitReceipt{}, exitCode, err
	}
	exitID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadExitReceipt{}, exitCode, err
	}
	signedExit, err := SignWorkloadExitReceipt(
		WorkloadExitReceipt{
			Version:            WorkloadExitReceiptVersion,
			ExitID:             exitID,
			ActivationID:       activation.ActivationID,
			ActivationDigest:   activationDigest,
			GrantID:            activation.GrantID,
			GrantDigest:        activation.GrantDigest,
			DeviceID:           activation.DeviceID,
			WorkloadID:         activation.WorkloadID,
			WorkloadSpecDigest: activation.WorkloadSpecDigest,
			TargetCgroup:       activation.TargetCgroup,
			TargetCgroupID:     activation.TargetCgroupID,
			ProcessID:          activation.ProcessID,
			ExitClass:          exitClass,
			ExitCode:           exitCode,
			Signal:             signal,
			StartedAt:          activation.StartedAt,
			ExitedAt:           exitedAt,
		},
		hostAttestorKey,
	)
	if err != nil {
		return SignedWorkloadExitReceipt{}, exitCode, err
	}
	exitDigest, err := SignedWorkloadExitReceiptDigest(signedExit)
	if err != nil {
		return SignedWorkloadExitReceipt{}, exitCode, err
	}

	err = store.withLockedState(
		activation.DeviceID,
		activation.WorkloadID,
		func(path string, state WorkloadLifecycleState, exists bool) error {
			if !exists ||
				state.State != LifecycleStateRunning ||
				state.ActivationDigest != activationDigest {
				return ErrLifecycleInvalidLineage
			}
			state.State = LifecycleStateExited
			state.ExitDigest = exitDigest
			state.UpdatedAt = exitedAt
			return writeLifecycleState(path, state)
		},
	)
	if err != nil {
		return signedExit, exitCode, fmt.Errorf("persist EXITED lifecycle state: %w", err)
	}
	return signedExit, exitCode, nil
}

func classifyProcessExit(
	cmd *exec.Cmd,
	waitErr error,
) (string, int, int, error) {
	if cmd.ProcessState == nil {
		if waitErr != nil {
			return "", 0, 0, fmt.Errorf("workload wait failed without process state: %w", waitErr)
		}
		return "", 0, 0, errors.New("workload exited without process state")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return "", 0, 0, errors.New("workload process state is not a Linux wait status")
	}
	if status.Signaled() {
		sig := int(status.Signal())
		return ExitClassSignal, 128 + sig, sig, nil
	}
	code := status.ExitStatus()
	if code == 0 {
		return ExitClassClean, 0, 0, nil
	}
	return ExitClassNonZero, code, 0, nil
}
