//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeTrustWatchdogRemainingUsesBootClock(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	boot, err := ParseSHA256Digest(f.state.RuntimeTrustBootIDHash)
	if err != nil {
		t.Fatal(err)
	}
	before := ClockSnapshot{
		WallNow:    f.now,
		MonoNowNS:  f.state.RuntimeTrustDeadlineBootNS - 10,
		BootIDHash: boot,
	}
	remaining, expired, err := RuntimeTrustWatchdogRemaining(f.state, before)
	if err != nil {
		t.Fatal(err)
	}
	if expired || remaining != 10 {
		t.Fatalf("remaining=%s expired=%v", remaining, expired)
	}

	atDeadline := before
	atDeadline.MonoNowNS = f.state.RuntimeTrustDeadlineBootNS
	remaining, expired, err = RuntimeTrustWatchdogRemaining(f.state, atDeadline)
	if err != nil {
		t.Fatal(err)
	}
	if !expired || remaining != 0 {
		t.Fatalf("deadline remaining=%s expired=%v", remaining, expired)
	}
}

func TestRuntimeTrustWatchdogRejectsBootChange(t *testing.T) {
	f := newRuntimeTrustFixture(t)
	var otherBoot [32]byte
	otherBoot[0] = 1
	_, _, err := RuntimeTrustWatchdogRemaining(
		f.state,
		ClockSnapshot{
			WallNow:    f.now,
			MonoNowNS:  f.state.RuntimeTrustDeadlineBootNS,
			BootIDHash: otherBoot,
		},
	)
	if !errors.Is(err, ErrRuntimeTrustBootChanged) {
		t.Fatalf("boot change not rejected: %v", err)
	}
}

func liveRuntimeExpiryFixture(
	t *testing.T,
	deadlineOffset int64,
) (
	WorkloadLifecycleStore,
	WorkloadLifecycleState,
	SignedWorkloadActivationReceipt,
	ed25519KeyPair,
	ClockSnapshot,
	*recordingKernelStore,
) {
	t.Helper()
	now := time.Now().UTC()
	clock, err := CaptureBootClockSnapshot(now, DefaultBootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ObserveLinuxProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !current.Exists {
		t.Fatal("test process is unexpectedly absent")
	}
	hostPub, hostPriv := admissionTestKeys(t)
	identity := current.Identity
	activation, err := SignWorkloadActivationReceipt(
		WorkloadActivationReceipt{
			Version:            WorkloadActivationReceiptVersionV2,
			ActivationID:       "watchdog-live-activation",
			GrantID:            "watchdog-grant",
			GrantDigest:        "sha256:" + strings.Repeat("a", 64),
			DeviceID:           "watchdog-device",
			WorkloadID:         "watchdog-workload",
			WorkloadSpecDigest: "sha256:" + strings.Repeat("b", 64),
			TargetCgroup:       filepath.Clean(current.ObservedCgroup),
			TargetCgroupID:     current.ObservedCgroupID,
			ProcessID:          os.Getpid(),
			ProcessIdentity:    &identity,
			StartedAt:          now.Add(-time.Minute),
		},
		hostPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		t.Fatal(err)
	}
	installed := clock.MonoNowNS - 100
	deadline := clock.MonoNowNS
	if deadlineOffset > 0 {
		deadline += uint64(deadlineOffset)
	}
	if deadlineOffset < 0 {
		deadline -= uint64(-deadlineOffset)
	}
	if deadline <= installed {
		installed = deadline - 1
	}
	bootDigest := "sha256:" + hex.EncodeToString(clock.BootIDHash[:])
	state := WorkloadLifecycleState{
		Version:                    WorkloadLifecycleStateVersion,
		DeviceID:                   activation.Receipt.DeviceID,
		WorkloadID:                 activation.Receipt.WorkloadID,
		Generation:                 1,
		LifecycleEpoch:             1,
		State:                      LifecycleStateRunning,
		ActivationDigest:           activationDigest,
		RuntimeTrustEpoch:          1,
		RuntimeTrustLeaseDigest:    "sha256:" + strings.Repeat("c", 64),
		RuntimeTrustExpiresAt:      now,
		RuntimeTrustBootIDHash:     bootDigest,
		RuntimeTrustInstalledBootNS: installed,
		RuntimeTrustDeadlineBootNS:  deadline,
		RestartWindowStartedAt:     now.Add(-time.Minute),
		UpdatedAt:                  now.Add(-time.Second),
	}
	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		state.DeviceID,
		state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, exists bool) error {
			if exists {
				t.Fatal("unexpected existing lifecycle state")
			}
			return writeLifecycleState(path, state)
		},
	); err != nil {
		t.Fatal(err)
	}
	kernelStore := &recordingKernelStore{
		fence: ScopeFenceState{
			BootIDHash:      clock.BootIDHash,
			AuthorityTerm:   3,
			DecisionEpoch:   9,
			RevocationEpoch: 11,
		},
	}
	return store, state, activation, ed25519KeyPair{pub: hostPub, priv: hostPriv}, clock, kernelStore
}

type ed25519KeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func TestRuntimeTrustWatchdogDoesNotRevokeBeforeDeadline(t *testing.T) {
	store, state, activation, host, clock, kernelStore := liveRuntimeExpiryFixture(t, 1_000_000_000)
	_, _, err := EnforceCurrentRuntimeTrustExpiry(
		context.Background(),
		store,
		Installer{Store: kernelStore},
		state.DeviceID,
		state.WorkloadID,
		activation,
		host.priv,
		clock,
		time.Now().UTC(),
	)
	if !errors.Is(err, ErrRuntimeTrustDeadlineNotReached) {
		t.Fatalf("pre-deadline enforcement returned %v", err)
	}
	if len(kernelStore.ops) != 0 {
		t.Fatalf("kernel was touched before deadline: %v", kernelStore.ops)
	}
}

func TestRuntimeTrustWatchdogRevokesAtDeadlineAndSignsEvidence(t *testing.T) {
	store, state, activation, host, clock, kernelStore := liveRuntimeExpiryFixture(t, 0)
	evidence, fence, err := EnforceCurrentRuntimeTrustExpiry(
		context.Background(),
		store,
		Installer{Store: kernelStore},
		state.DeviceID,
		state.WorkloadID,
		activation,
		host.priv,
		clock,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if fence.RevocationEpoch != 12 ||
		evidence.Evidence.KernelPreviousRevocationEpoch != 11 ||
		evidence.Evidence.KernelRevocationEpoch != 12 {
		t.Fatalf("unexpected revocation transition: fence=%+v evidence=%+v", fence, evidence.Evidence)
	}
	if evidence.Evidence.ProcessState != RuntimeExpiryProcessRunning {
		t.Fatalf("live process state=%s", evidence.Evidence.ProcessState)
	}
	if err := VerifySignedRuntimeTrustExpiryEvidence(evidence, host.pub); err != nil {
		t.Fatalf("expiry evidence signature rejected: %v", err)
	}
	wantOps := []string{"get-fence", "fence"}
	if len(kernelStore.ops) != len(wantOps) {
		t.Fatalf("kernel ops=%v want=%v", kernelStore.ops, wantOps)
	}
	for i := range wantOps {
		if kernelStore.ops[i] != wantOps[i] {
			t.Fatalf("kernel ops=%v want=%v", kernelStore.ops, wantOps)
		}
	}
}

func TestApplyRuntimeTrustRenewalFailsAfterCurrentMonotonicDeadline(t *testing.T) {
	f := newRecoveryFixture(t)
	now := time.Now().UTC()
	clock, err := CaptureBootClockSnapshot(now, DefaultBootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(f.activation)
	if err != nil {
		t.Fatal(err)
	}
	state := f.state
	state.RuntimeTrustEpoch = 1
	state.RuntimeTrustLeaseDigest = "sha256:" + strings.Repeat("c", 64)
	state.RuntimeTrustExpiresAt = now.Add(-time.Second)
	state.RuntimeTrustBootIDHash = "sha256:" + hex.EncodeToString(clock.BootIDHash[:])
	state.RuntimeTrustInstalledBootNS = clock.MonoNowNS - 2
	state.RuntimeTrustDeadlineBootNS = clock.MonoNowNS - 1
	state.ActivationDigest = activationDigest

	store := WorkloadLifecycleStore{Dir: filepath.Join(t.TempDir(), "lifecycle")}
	if err := store.withLockedState(
		state.DeviceID,
		state.WorkloadID,
		func(path string, _ WorkloadLifecycleState, _ bool) error {
			return writeLifecycleState(path, state)
		},
	); err != nil {
		t.Fatal(err)
	}

	renewed, err := SignRuntimeTrustLease(
		RuntimeTrustLease{
			Version:              RuntimeTrustLeaseVersion,
			LeaseID:              "renewed-after-expiry",
			LeaseEpoch:           2,
			DeviceID:             state.DeviceID,
			WorkloadID:           state.WorkloadID,
			Generation:           state.Generation,
			LifecycleEpoch:       EffectiveLifecycleEpoch(state),
			ActivationDigest:     activationDigest,
			WorkloadSpecDigest:   f.activation.Receipt.WorkloadSpecDigest,
			TargetCgroup:         f.activation.Receipt.TargetCgroup,
			TargetCgroupID:       f.activation.Receipt.TargetCgroupID,
			BootstrapDigest:      f.bootstrap,
			PolicyDigest:         "sha256:" + strings.Repeat("d", 64),
			RemoteDecisionID:     "remote-renewed",
			RemoteDecisionDigest: "sha256:" + strings.Repeat("e", 64),
			RemoteVerifiedAt:     now.Add(-time.Second),
			AuthorityID:          "lifecycle-authority",
			IssuedAt:             now.Add(-time.Second),
			ExpiresAt:            now.Add(time.Minute),
		},
		f.lifecyclePriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyRuntimeTrustLease(
		store,
		renewed,
		f.lifecyclePub,
		now,
	)
	if !errors.Is(err, ErrRuntimeTrustLeaseExpired) {
		t.Fatalf("post-deadline renewal was not rejected: %v", err)
	}
}
