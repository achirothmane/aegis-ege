//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func EnforceCurrentRuntimeTrustExpiry(
	ctx context.Context,
	store WorkloadLifecycleStore,
	installer Installer,
	deviceID string,
	workloadID string,
	activation SignedWorkloadActivationReceipt,
	hostAttestorPrivateKey ed25519.PrivateKey,
	clock ClockSnapshot,
	observedAt time.Time,
) (SignedRuntimeTrustExpiryEvidence, ScopeFenceState, error) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if len(hostAttestorPrivateKey) != ed25519.PrivateKeySize {
		return SignedRuntimeTrustExpiryEvidence{}, ScopeFenceState{}, errors.New("host attestor private key is required")
	}
	hostPub := hostAttestorPrivateKey.Public().(ed25519.PublicKey)
	if err := VerifySignedWorkloadActivationReceipt(activation, hostPub); err != nil {
		return SignedRuntimeTrustExpiryEvidence{}, ScopeFenceState{}, err
	}
	if activation.Receipt.Version != WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil {
		return SignedRuntimeTrustExpiryEvidence{}, ScopeFenceState{}, errors.New(
			"runtime trust watchdog requires process-bound activation receipt v2",
		)
	}
	if clock.WallNow.IsZero() || clock.MonoNowNS == 0 || clock.BootIDHash == [32]byte{} {
		return SignedRuntimeTrustExpiryEvidence{}, ScopeFenceState{}, errors.New("runtime trust watchdog clock snapshot is invalid")
	}

	var signed SignedRuntimeTrustExpiryEvidence
	var nextFence ScopeFenceState
	err := store.withLockedState(
		deviceID,
		workloadID,
		func(_ string, state WorkloadLifecycleState, exists bool) error {
			if !exists {
				return ErrLifecycleInvalidLineage
			}
			state = NormalizeWorkloadLifecycleState(state)
			if err := ValidateWorkloadLifecycleState(state); err != nil {
				return err
			}
			if state.State != LifecycleStateRunning ||
				state.RuntimeTrustEpoch == 0 ||
				state.RuntimeTrustLeaseDigest == "" {
				return ErrRuntimeTrustInvalid
			}

			activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
			if err != nil {
				return err
			}
			if activation.Receipt.DeviceID != state.DeviceID ||
				activation.Receipt.WorkloadID != state.WorkloadID ||
				activationDigest != state.ActivationDigest {
				return ErrLifecycleInvalidLineage
			}

			currentBoot := "sha256:" + hex.EncodeToString(clock.BootIDHash[:])
			if state.RuntimeTrustBootIDHash != currentBoot {
				return ErrRuntimeTrustBootChanged
			}
			if clock.MonoNowNS < state.RuntimeTrustDeadlineBootNS {
				return ErrRuntimeTrustDeadlineNotReached
			}

			fenceKey, err := FenceKey(
				activation.Receipt.TargetCgroupID,
				ActionClassNetworkConnect,
			)
			if err != nil {
				return err
			}
			nextFence, err = installer.RevokeCurrentScope(ctx, fenceKey)
			if err != nil {
				return fmt.Errorf("revoke runtime trust network authority: %w", err)
			}
			kernelBoot := "sha256:" + hex.EncodeToString(nextFence.BootIDHash[:])
			if kernelBoot != currentBoot {
				return ErrRuntimeTrustBootChanged
			}

			evidenceID, err := randomToken(24)
			if err != nil {
				return err
			}
			expected := *activation.Receipt.ProcessIdentity
			evidence := RuntimeTrustExpiryEvidence{
				Version:                     RuntimeTrustExpiryEvidenceVersion,
				EvidenceID:                  evidenceID,
				DeviceID:                    state.DeviceID,
				WorkloadID:                  state.WorkloadID,
				Generation:                  state.Generation,
				LifecycleEpoch:              EffectiveLifecycleEpoch(state),
				ActivationDigest:            activationDigest,
				RuntimeTrustLeaseDigest:     state.RuntimeTrustLeaseDigest,
				RuntimeTrustLeaseEpoch:      state.RuntimeTrustEpoch,
				RuntimeTrustExpiresAt:       state.RuntimeTrustExpiresAt.UTC(),
				RuntimeTrustBootIDHash:      state.RuntimeTrustBootIDHash,
				RuntimeTrustInstalledBootNS: state.RuntimeTrustInstalledBootNS,
				RuntimeTrustDeadlineBootNS:  state.RuntimeTrustDeadlineBootNS,
				ObservedBootIDHash:          currentBoot,
				ObservedBootNS:              clock.MonoNowNS,
				TargetCgroup:                filepath.Clean(activation.Receipt.TargetCgroup),
				TargetCgroupID:              activation.Receipt.TargetCgroupID,
				KernelFenceBootIDHash:       kernelBoot,
				KernelAuthorityTerm:         nextFence.AuthorityTerm,
				KernelDecisionEpoch:         nextFence.DecisionEpoch,
				KernelRevocationEpoch:       nextFence.RevocationEpoch,
				ProcessID:                   activation.Receipt.ProcessID,
				ExpectedProcessIdentity:     &expected,
				ObservedAt:                  observedAt.UTC(),
			}

			current, observeErr := ObserveLinuxProcess(activation.Receipt.ProcessID)
			if observeErr != nil {
				return fmt.Errorf("observe process after runtime trust expiry revocation: %w", observeErr)
			}
			if !current.Exists {
				evidence.ProcessState = RuntimeExpiryProcessAbsent
			} else {
				observed := current.Identity
				evidence.ObservedProcessIdentity = &observed
				evidence.ObservedCgroup = filepath.Clean(current.ObservedCgroup)
				evidence.ObservedCgroupID = current.ObservedCgroupID

				switch {
				case current.Identity != expected:
					evidence.ProcessState = RuntimeExpiryProcessPIDReused
				case current.ObservedCgroupID != activation.Receipt.TargetCgroupID ||
					filepath.Clean(current.ObservedCgroup) != filepath.Clean(activation.Receipt.TargetCgroup):
					evidence.ProcessState = RuntimeExpiryProcessCgroupMismatch
				default:
					evidence.ProcessState = RuntimeExpiryProcessRunning
				}
			}

			signed, err = SignRuntimeTrustExpiryEvidence(
				evidence,
				hostAttestorPrivateKey,
			)
			return err
		},
	)
	if err != nil {
		return SignedRuntimeTrustExpiryEvidence{}, nextFence, err
	}
	return signed, nextFence, nil
}

func RuntimeTrustWatchdogRemaining(
	state WorkloadLifecycleState,
	clock ClockSnapshot,
) (time.Duration, bool, error) {
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return 0, false, err
	}
	if state.State != LifecycleStateRunning ||
		state.RuntimeTrustEpoch == 0 ||
		state.RuntimeTrustLeaseDigest == "" {
		return 0, false, ErrRuntimeTrustInvalid
	}
	if clock.MonoNowNS == 0 || clock.BootIDHash == [32]byte{} {
		return 0, false, errors.New("runtime trust watchdog clock snapshot is invalid")
	}
	currentBoot := "sha256:" + hex.EncodeToString(clock.BootIDHash[:])
	if state.RuntimeTrustBootIDHash != currentBoot {
		return 0, false, ErrRuntimeTrustBootChanged
	}
	if clock.MonoNowNS >= state.RuntimeTrustDeadlineBootNS {
		return 0, true, nil
	}
	remainingNS := state.RuntimeTrustDeadlineBootNS - clock.MonoNowNS
	if remainingNS > uint64(^uint64(0)>>1) {
		return 0, false, errors.New("runtime trust watchdog remaining duration overflow")
	}
	return time.Duration(remainingNS), false, nil
}
