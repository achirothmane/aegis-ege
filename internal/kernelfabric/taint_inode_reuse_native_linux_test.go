//go:build linux && taintnative

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	taintInodeReuseHelperEnv    = "AEGIS_TAINT_INODE_REUSE_HELPER"
	taintRestartObserverEnv     = "AEGIS_TAINT_RESTART_OBSERVER"
	taintRecoveryCrashHelperEnv = "AEGIS_TAINT_RECOVERY_CRASH_HELPER"
	taintRecoveryPlanEnv        = "AEGIS_TAINT_RECOVERY_PLAN"
	taintRecoveryAuthEnv        = "AEGIS_TAINT_RECOVERY_AUTH"
	taintRecoveryKeyEnv         = "AEGIS_TAINT_RECOVERY_KEY"
	taintRecoveryNowEnv         = "AEGIS_TAINT_RECOVERY_NOW"
	taintRecoveryBoundaryEnv    = "AEGIS_TAINT_RECOVERY_BOUNDARY"
)

func TestTaintRestartObserver(t *testing.T) {
	if os.Getenv(taintRestartObserverEnv) != "1" {
		return
	}

	cgroupID, err := strconv.ParseUint(os.Getenv(taintNativeHelperCgroupID), 10, 64)
	if err != nil {
		t.Fatalf("parse restart observer cgroup id: %v", err)
	}
	active, err := TaintCgroupActivationState(os.Getenv(taintNativeHelperBPFFSRoot), cgroupID)
	if err != nil {
		t.Fatalf("restart observer activation state: %v", err)
	}
	if !active {
		t.Fatal("restart observer lost protected-cgroup activation")
	}
	dirty, err := TaintSourceIdentityDirtyState(os.Getenv(taintNativeHelperBPFFSRoot))
	if err != nil {
		t.Fatalf("restart observer source continuity: %v", err)
	}
	if dirty == 0 {
		t.Fatal("restart observer saw clean continuity after source lifetime loss")
	}
	if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
		t.Fatal(err)
	}
	t.Logf("fresh process recovered pinned fail-closed state: cgroup=%d dirty=%d", cgroupID, dirty)
}

func TestTaintRecoveryCrashHelper(t *testing.T) {
	if os.Getenv(taintRecoveryCrashHelperEnv) != "1" {
		return
	}

	plan, err := LoadTaintActivationPlan(os.Getenv(taintRecoveryPlanEnv))
	if err != nil {
		t.Fatalf("load crash recovery plan: %v", err)
	}
	payload, err := os.ReadFile(os.Getenv(taintRecoveryAuthEnv))
	if err != nil {
		t.Fatalf("read crash recovery authorization: %v", err)
	}
	var signed SignedTaintRecoveryAuthorization
	if err := json.Unmarshal(payload, &signed); err != nil {
		t.Fatalf("decode crash recovery authorization: %v", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(os.Getenv(taintRecoveryKeyEnv))
	if err != nil {
		t.Fatalf("decode crash recovery key: %v", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		t.Fatalf("crash recovery key size=%d want=%d", len(keyBytes), ed25519.PublicKeySize)
	}
	now, err := time.Parse(time.RFC3339Nano, os.Getenv(taintRecoveryNowEnv))
	if err != nil {
		t.Fatalf("parse crash recovery time: %v", err)
	}

	req := TaintRecoveryRequest{
		BPFFSRoot:            os.Getenv(taintNativeHelperBPFFSRoot),
		Plan:                 plan,
		SignedAuthorization:  signed,
		RecoveryAuthorityKey: ed25519.PublicKey(keyBytes),
		Now:                  now,
	}
	switch os.Getenv(taintRecoveryBoundaryEnv) {
	case "epoch":
		req.afterEpochCommit = func() { os.Exit(86) }
	case "clean":
		req.afterCleanCommit = func() { os.Exit(87) }
	default:
		t.Fatalf("unknown recovery crash boundary %q", os.Getenv(taintRecoveryBoundaryEnv))
	}

	_, err = RecoverTaintSourceContinuity(req)
	if err != nil {
		t.Fatalf("recovery failed before crash boundary: %v", err)
	}
	t.Fatal("recovery returned past crash boundary")
}

func TestTaintInodeReuseHelper(t *testing.T) {
	if os.Getenv(taintInodeReuseHelperEnv) != "1" {
		return
	}

	var trigger [1]byte
	if _, err := os.Stdin.Read(trigger[:]); err != nil {
		t.Fatalf("wait for source-lifetime trigger: %v", err)
	}
	if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
		t.Fatal(err)
	}
}

// TestNativeExt4SameInodeReuseFixture proves the allocator premise separately
// from BPF-LSM enforcement. A deliberately inode-starved ext4 filesystem is
// filled while source.txt remains alive. Once source.txt is unlinked, its inode
// is the only allocatable inode, so the next file must reuse the same numeric
// (device,inode). This test runs on the GitHub host, whose kernel has ext4.
func TestNativeExt4SameInodeReuseFixture(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ext4 same-inode reuse fixture requires root")
	}

	imagePath := filepath.Join("testdata", "aegis_inode_reuse.ext4")
	if _, err := os.Stat(imagePath); err != nil {
		t.Fatalf("inode-reuse ext4 image unavailable: %v", err)
	}
	loopPath, releaseLoop := attachNativeLoopDevice(t, imagePath)
	defer releaseLoop()

	mountPoint := filepath.Join(t.TempDir(), "inode-reuse-fs")
	if err := os.Mkdir(mountPoint, 0o700); err != nil {
		t.Fatalf("create inode-reuse mountpoint: %v", err)
	}
	if err := unix.Mount(loopPath, mountPoint, "ext4", unix.MS_NODEV|unix.MS_NOSUID, ""); err != nil {
		t.Fatalf("mount inode-reuse ext4 fixture: %v", err)
	}
	defer func() {
		if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
			t.Logf("unmount inode-reuse fixture: %v", err)
		}
	}()

	sourcePath := filepath.Join(mountPoint, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("retired-source"), 0o600); err != nil {
		t.Fatalf("write inode-reuse source: %v", err)
	}
	retiredKey, err := ResolveTaintFileKey(sourcePath)
	if err != nil {
		t.Fatalf("resolve retired source identity: %v", err)
	}

	// Consume every other allocatable inode while the source remains live.
	saturated := false
	for i := 0; i < 4096; i++ {
		path := filepath.Join(mountPoint, fmt.Sprintf("filler-%04d", i))
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			if errors.Is(createErr, syscall.ENOSPC) {
				saturated = true
				break
			}
			t.Fatalf("fill inode table at %s: %v", path, createErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			t.Fatalf("close inode filler %s: %v", path, closeErr)
		}
	}
	if !saturated {
		t.Fatal("inode-reuse fixture did not reach inode exhaustion")
	}

	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("unlink retired source: %v", err)
	}
	if err := os.WriteFile(sourcePath, []byte("future-object"), 0o600); err != nil {
		t.Fatalf("create future object after inode exhaustion: %v", err)
	}
	reusedKey, err := ResolveTaintFileKey(sourcePath)
	if err != nil {
		t.Fatalf("resolve future object identity: %v", err)
	}
	if reusedKey != retiredKey {
		t.Fatalf(
			"allocator did not reuse the only freed inode: retired=%+v future=%+v",
			retiredKey,
			reusedKey,
		)
	}

	t.Logf("forced exact same-number inode reuse: retired=%+v future=%+v", retiredKey, reusedKey)
}

// TestNativeTaintUnlinkContinuityIsSticky proves the enforcement half of the
// same-number reuse boundary on the BPF-LSM selftests kernel. It does not depend
// on that kernel supporting ext4. Once an enrolled source is unlinked, source
// continuity becomes DIRTY before any future object can be created. A clean
// pre-existing child then remains denied without reading the replacement,
// proving that effect authority cannot be recovered by a later allocation.
func TestNativeTaintUnlinkContinuityIsSticky(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint source-lifetime test requires root")
	}
	if len(nativeTaintBPFObject) == 0 {
		t.Fatal("embedded native taint BPF object is empty")
	}
	if err := prepareNativeTaintKernel(); err != nil {
		t.Fatalf("prepare native taint kernel environment: %v", err)
	}

	originalCgroup, err := currentUnifiedCgroupPath()
	if err != nil {
		t.Fatal(err)
	}
	testID := fmt.Sprintf("aegis-taint-lifetime-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create source-lifetime cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create source-lifetime bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	// Mount the source filesystem before loading the lifetime LSM hooks. Mounting
	// it after activation would correctly dirty continuity for an unrelated
	// reason and would not isolate the unlink invariant under test.
	sourceRoot := filepath.Join(t.TempDir(), "source-lifetime-tmpfs")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatalf("create source-lifetime mountpoint: %v", err)
	}
	if err := unix.Mount("aegis-source-lifetime", sourceRoot, "tmpfs", 0, "mode=0700,size=4m"); err != nil {
		t.Fatalf("mount source-lifetime tmpfs: %v", err)
	}
	defer func() {
		if err := unix.Unmount(sourceRoot, unix.MNT_DETACH); err != nil {
			t.Logf("unmount source-lifetime tmpfs: %v", err)
		}
	}()

	sourcePath := filepath.Join(sourceRoot, "source.txt")
	if err := os.WriteFile(sourcePath, []byte("enrolled-source"), 0o600); err != nil {
		t.Fatalf("write enrolled source: %v", err)
	}
	enrolledUserKey, err := ResolveTaintFileKey(sourcePath)
	if err != nil {
		t.Fatalf("resolve enrolled source identity: %v", err)
	}

	artifact := filepath.Join(t.TempDir(), "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize taint BPF object: %v", err)
	}

	now := time.Now().UTC()
	manifest, err := BuildTaintBootstrapManifest(
		artifact,
		now.Add(-time.Minute),
		now.Add(15*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest, err := SignBootstrapManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	releaseKeyID, err := BootstrapKeyID(releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	_, attestationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPublic := attestationPrivate.Public().(ed25519.PublicKey)

	loader := TaintBootstrapLoader{}
	loaded, err := loader.LoadAndAttach(context.Background(), TaintBootstrapLoadRequest{
		ArtifactPath:          artifact,
		CgroupPath:            cgroupPath,
		BPFFSRoot:             bpffsRoot,
		SignedManifest:        signedManifest,
		Trust:                 BootstrapTrustStore{releaseKeyID: releasePublic},
		AttestationPrivateKey: attestationPrivate,
		Now:                   now,
	})
	if err != nil {
		t.Fatalf("load source-lifetime taint BPF programs: %v", err)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, sourcePath)
	if err != nil {
		t.Fatalf("kernel-observe source-lifetime source: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("source-lifetime probe returned no kernel identities")
	}
	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources:       make([]TaintSourceBinding, 0, len(sourceKeys)),
	}
	for _, key := range sourceKeys {
		plan.Sources = append(plan.Sources, TaintSourceBinding{
			Path:   sourcePath,
			File:   key,
			Labels: 1,
		})
	}
	activated, err := ActivateTaintCgroup(TaintActivationRequest{
		BPFFSRoot:                     bpffsRoot,
		Plan:                          plan,
		SignedBootstrapReceipt:        loaded.SignedReceipt,
		BootstrapAttestationPublicKey: attestationPublic,
	})
	if err != nil {
		t.Fatalf("activate source-lifetime taint cgroup: %v", err)
	}

	dirtyBefore, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity before unlink: %v", err)
	}
	if dirtyBefore != 0 {
		t.Fatalf("source continuity dirty before unlink: %d", dirtyBefore)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move source-lifetime test into protected cgroup: %v", err)
	}
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("clean egress unexpectedly denied before unlink: %v", err)
	}
	_ = conn.Close()

	// Fork while the parent is clean. The child waits and never reads the
	// replacement object, so its later denial can only be attributed to the
	// continuity state rather than to source-map aliasing or process taint.
	child := exec.Command(os.Args[0], "-test.run=^TestTaintInodeReuseHelper$")
	child.Env = append(os.Environ(),
		taintInodeReuseHelperEnv+"=1",
		taintNativeHelperAddr+"="+listener.Addr().String(),
	)
	childStdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatalf("start clean source-lifetime child: %v", err)
	}
	childPID := uint32(child.Process.Pid)

	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("unlink enrolled source: %v", err)
	}
	dirtyAfterUnlink, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after enrolled unlink: %v", err)
	}
	if dirtyAfterUnlink <= dirtyBefore {
		t.Fatalf(
			"enrolled unlink did not invalidate source continuity: before=%d after=%d enrolled=%+v",
			dirtyBefore,
			dirtyAfterUnlink,
			sourceKeys,
		)
	}

	if err := os.WriteFile(sourcePath, []byte("future-object"), 0o600); err != nil {
		t.Fatalf("create future object after unlink: %v", err)
	}
	futureKey, err := ResolveTaintFileKey(sourcePath)
	if err != nil {
		t.Fatalf("resolve future object identity: %v", err)
	}
	if futureKey == enrolledUserKey {
		t.Fatalf(
			"tmpfs unexpectedly reused source identity; split proof no longer isolates premises: enrolled=%+v future=%+v",
			enrolledUserKey,
			futureKey,
		)
	}

	dirtyAfterFuture, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after future allocation: %v", err)
	}
	if dirtyAfterFuture < dirtyAfterUnlink {
		t.Fatalf(
			"source continuity regressed after future allocation: unlink=%d future=%d",
			dirtyAfterUnlink,
			dirtyAfterFuture,
		)
	}

	if _, err := childStdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := childStdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("clean child escaped after source lifetime became unknown: %v", err)
	}
	if err := assertNativeProcessUntainted(bpffsRoot, childPID); err != nil {
		t.Fatalf("source-lifetime denial was not isolated to continuity: %v", err)
	}

	isActive, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("source-lifetime schedule removed protected-cgroup activation")
	}

	// Model a userspace control-plane restart with a fresh process. The observer
	// has no in-memory activation state from this test process: it reopens the
	// pinned kernel maps, requires the protected cgroup and DIRTY continuity to
	// still be present, and must remain unable to egress while clean.
	restartObserver := exec.Command(os.Args[0], "-test.run=^TestTaintRestartObserver$")
	restartObserver.Env = append(os.Environ(),
		taintRestartObserverEnv+"=1",
		taintNativeHelperBPFFSRoot+"="+bpffsRoot,
		taintNativeHelperCgroupID+"="+strconv.FormatUint(activated.CgroupID, 10),
		taintNativeHelperAddr+"="+listener.Addr().String(),
	)
	restartObserver.Stdout = os.Stdout
	restartObserver.Stderr = os.Stderr
	if err := restartObserver.Run(); err != nil {
		t.Fatalf("fresh-process source-lifetime observation failed: %v", err)
	}

	// A restarted controller must not silently install a second taint substrate
	// over the pinned active one. The loader is intentionally stateless in
	// userspace, so a brand-new instance exercises the restart boundary directly.
	_, err = (TaintBootstrapLoader{}).LoadAndAttach(context.Background(), TaintBootstrapLoadRequest{
		ArtifactPath:          artifact,
		CgroupPath:            cgroupPath,
		BPFFSRoot:             bpffsRoot,
		SignedManifest:        signedManifest,
		Trust:                 BootstrapTrustStore{releaseKeyID: releasePublic},
		AttestationPrivateKey: attestationPrivate,
		Now:                   now,
	})
	if err == nil {
		t.Fatal("stale restart unexpectedly reloaded over pinned taint state")
	}
	if !strings.Contains(err.Error(), "pin already exists") {
		t.Fatalf("stale restart failed for an unexpected reason: %v", err)
	}

	// Replaying the old activation plan must also fail closed. Whether the
	// implementation reports the already-armed lifetime guard or DIRTY
	// continuity, stale enrollment must never become a second ALLOW transition.
	_, err = ActivateTaintCgroup(TaintActivationRequest{
		BPFFSRoot:                     bpffsRoot,
		Plan:                          plan,
		SignedBootstrapReceipt:        loaded.SignedReceipt,
		BootstrapAttestationPublicKey: attestationPublic,
	})
	if err == nil {
		t.Fatal("stale enrollment unexpectedly reactivated after continuity loss")
	}
	if !strings.Contains(err.Error(), "already armed") &&
		!strings.Contains(err.Error(), "continuity is dirty") {
		t.Fatalf("stale activation failed for an unexpected reason: %v", err)
	}

	dirtyAfterRestart, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after stale restart attempts: %v", err)
	}
	if dirtyAfterRestart != dirtyAfterFuture {
		t.Fatalf(
			"stale restart attempt mutated continuity state: before=%d after=%d",
			dirtyAfterFuture,
			dirtyAfterRestart,
		)
	}
	isActive, err = TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("stale restart attempt cleared protected-cgroup activation")
	}
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatalf("stale restart attempt recovered clean egress: %v", err)
	}

	t.Logf(
		"unlink continuity stayed fail-closed across future allocation and userspace restart: enrolled=%+v future=%+v dirty_before=%d dirty_after_unlink=%d dirty_after_future=%d dirty_after_restart=%d",
		enrolledUserKey,
		futureKey,
		dirtyBefore,
		dirtyAfterUnlink,
		dirtyAfterFuture,
		dirtyAfterRestart,
	)

	// Recovery is a control-plane operation, not workload execution. Move this
	// test controller back outside the protected cgroup before kernel re-probes;
	// the probe path still observes source identity, but the controller must not
	// acquire workload taint merely by proving the next source enrollment.
	if err := movePIDToCgroup(originalCgroup, os.Getpid()); err != nil {
		t.Fatalf("move recovery controller outside protected cgroup: %v", err)
	}

	// Recovery requires fresh kernel-observed evidence for the object that now
	// occupies the governed source path. The stale activation plan above is not
	// sufficient authority to restore continuity.
	initialEpoch, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatalf("read initial enrollment epoch: %v", err)
	}
	if initialEpoch != 1 || activated.EnrollmentEpoch != 1 {
		t.Fatalf(
			"unexpected initial enrollment epoch: map=%d activation=%d",
			initialEpoch,
			activated.EnrollmentEpoch,
		)
	}
	futureKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, sourcePath)
	if err != nil {
		t.Fatalf("kernel-observe recovery source: %v", err)
	}
	if len(futureKeys) == 0 {
		t.Fatal("recovery source probe returned no kernel identities")
	}
	recoveryPlan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: plan.AllowedLabels,
		Sources:       make([]TaintSourceBinding, 0, len(futureKeys)),
	}
	for _, key := range futureKeys {
		recoveryPlan.Sources = append(recoveryPlan.Sources, TaintSourceBinding{
			Path:   sourcePath,
			File:   key,
			Labels: 1,
		})
	}
	recoveryPlanDigest, err := TaintActivationPlanDigest(recoveryPlan)
	if err != nil {
		t.Fatal(err)
	}
	host, err := (LinuxBootstrapHostProvider{}).Snapshot(bpffsRoot)
	if err != nil {
		t.Fatalf("capture recovery host snapshot: %v", err)
	}
	recoveryPublic, recoveryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recoveryAuth := TaintRecoveryAuthorization{
		Version:         TaintRecoveryAuthorizationVersion,
		AuthorizationID: "native-source-recovery-epoch-1-to-2",
		PlanDigest:      recoveryPlanDigest,
		CgroupID:        activated.CgroupID,
		BPFFSRoot:       bpffsRoot,
		BootIDHash:      host.BootIDHash,
		FromEpoch:       initialEpoch,
		ToEpoch:         initialEpoch + 1,
		ExpectedDirty:   dirtyAfterRestart,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(10 * time.Minute),
	}
	signedRecovery, err := SignTaintRecoveryAuthorization(recoveryAuth, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-issue a second stale authorization for the *next* invalidation
	// generation while it still claims epoch 1. After the first recovery the
	// source plan remains identical, and a topology-only invalidation will make
	// its ExpectedDirty value correct. Epoch fencing must be the reason it fails.
	staleFutureAuth := recoveryAuth
	staleFutureAuth.AuthorizationID = "stale-preissued-recovery-epoch-1-dirty-next"
	staleFutureAuth.ExpectedDirty = dirtyAfterRestart + 1
	signedStaleFuture, err := SignTaintRecoveryAuthorization(staleFutureAuth, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}

	recoveryDir := t.TempDir()
	recoveryPlanPath := filepath.Join(recoveryDir, "plan.json")
	if err := WriteTaintActivationPlan(recoveryPlanPath, recoveryPlan); err != nil {
		t.Fatalf("write crash recovery plan: %v", err)
	}
	recoveryAuthPath := filepath.Join(recoveryDir, "authorization.json")
	recoveryAuthPayload, err := json.Marshal(signedRecovery)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recoveryAuthPath, recoveryAuthPayload, 0o600); err != nil {
		t.Fatalf("write crash recovery authorization: %v", err)
	}
	expectedCommitment, err := TaintRecoveryCommitmentDigest(signedRecovery)
	if err != nil {
		t.Fatal(err)
	}
	cleanBeforeCrash, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}

	crash := exec.Command(os.Args[0], "-test.run=^TestTaintRecoveryCrashHelper$")
	crash.Env = append(os.Environ(),
		taintRecoveryCrashHelperEnv+"=1",
		taintRecoveryPlanEnv+"="+recoveryPlanPath,
		taintRecoveryAuthEnv+"="+recoveryAuthPath,
		taintRecoveryKeyEnv+"="+base64.StdEncoding.EncodeToString(recoveryPublic),
		taintRecoveryNowEnv+"="+now.Format(time.RFC3339Nano),
		taintRecoveryBoundaryEnv+"=epoch",
		taintNativeHelperBPFFSRoot+"="+bpffsRoot,
	)
	crash.Stdout = os.Stdout
	crash.Stderr = os.Stderr
	err = crash.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("recovery controller did not die at epoch/CLEAN boundary: %v", err)
	}

	epochAfterCrash, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if epochAfterCrash != recoveryAuth.ToEpoch {
		t.Fatalf("crash boundary did not persist epoch: got=%d want=%d", epochAfterCrash, recoveryAuth.ToEpoch)
	}
	dirtyAfterCrash, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	cleanAfterCrash, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if dirtyAfterCrash != recoveryAuth.ExpectedDirty || cleanAfterCrash != cleanBeforeCrash || dirtyAfterCrash <= cleanAfterCrash {
		t.Fatalf(
			"crash boundary did not remain fail-closed: dirty=%d clean=%d expected_dirty=%d clean_before=%d",
			dirtyAfterCrash,
			cleanAfterCrash,
			recoveryAuth.ExpectedDirty,
			cleanBeforeCrash,
		)
	}
	pendingAfterCrash, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfterCrash != expectedCommitment {
		t.Fatal("crash boundary lost exact in-flight recovery commitment")
	}

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move workload into protected cgroup after recovery crash: %v", err)
	}
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatalf("recovery crash reopened egress before CLEAN commit: %v", err)
	}
	if err := movePIDToCgroup(originalCgroup, os.Getpid()); err != nil {
		t.Fatalf("move recovery controller back outside protected cgroup: %v", err)
	}

	// A separately signed authorization with identical numeric state is not an
	// in-flight resume. Only the exact pinned commitment may finish the transition.
	otherAuth := recoveryAuth
	otherAuth.AuthorizationID = "different-authority-at-same-recovery-state"
	signedOther, err := SignTaintRecoveryAuthorization(otherAuth, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedOther,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("different authorization resumed crashed recovery: %v", err)
	}
	pendingAfterWrongResume, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfterWrongResume != expectedCommitment {
		t.Fatal("rejected recovery authorization mutated in-flight commitment")
	}

	recovered, err := RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedRecovery,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("resume exact in-flight recovery after controller crash: %v", err)
	}
	var emptyCommitment [32]byte
	pendingAfterRecovery, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfterRecovery != emptyCommitment {
		t.Fatal("successful recovery left an in-flight commitment behind")
	}
	if recovered.PreviousEpoch != 1 ||
		recovered.EnrollmentEpoch != 2 ||
		recovered.AdmittedDirtyGen != dirtyAfterRestart {
		t.Fatalf("unexpected recovery transition: %+v", recovered)
	}
	dirtyAfterRecovery, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source invalidation generation after recovery: %v", err)
	}
	if dirtyAfterRecovery != dirtyAfterRestart {
		t.Fatalf(
			"recovery reset monotonic invalidation generation: before=%d after=%d",
			dirtyAfterRestart,
			dirtyAfterRecovery,
		)
	}
	cleanAfterRecovery, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatalf("read continuity watermark after recovery: %v", err)
	}
	if cleanAfterRecovery != dirtyAfterRecovery {
		t.Fatalf(
			"authorized recovery did not admit current generation: dirty=%d clean=%d",
			dirtyAfterRecovery,
			cleanAfterRecovery,
		)
	}
	epochAfterRecovery, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatalf("read enrollment epoch after recovery: %v", err)
	}
	if epochAfterRecovery != 2 {
		t.Fatalf("recovery did not advance enrollment epoch: %d", epochAfterRecovery)
	}
	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("return test workload to protected cgroup after recovery: %v", err)
	}
	conn, err = net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("freshly authorized clean egress remained denied after recovery: %v", err)
	}
	_ = conn.Close()

	// Create a new continuity loss without changing the enrolled source object.
	// A bind mount elsewhere changes mount topology, so DIRTY advances while the
	// fresh recovery plan remains valid. The pre-issued authorization now matches
	// the exact DIRTY generation but still carries stale FromEpoch=1.
	mountSource := filepath.Join(t.TempDir(), "topology-source")
	mountTarget := filepath.Join(t.TempDir(), "topology-target")
	if err := os.WriteFile(mountSource, []byte("topology-source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mountTarget, []byte("topology-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(mountSource, mountTarget, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount topology invalidation: %v", err)
	}
	defer func() {
		if err := unix.Unmount(mountTarget, unix.MNT_DETACH); err != nil {
			t.Logf("unmount topology fixture: %v", err)
		}
	}()

	secondDirty, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read second source continuity loss: %v", err)
	}
	if secondDirty != staleFutureAuth.ExpectedDirty {
		t.Fatalf(
			"topology invalidation generation mismatch: got=%d want=%d",
			secondDirty,
			staleFutureAuth.ExpectedDirty,
		)
	}
	cleanAfterSecondDirty, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cleanAfterSecondDirty != cleanAfterRecovery || secondDirty <= cleanAfterSecondDirty {
		t.Fatalf(
			"second invalidation did not reopen fail-closed gap: dirty=%d clean=%d",
			secondDirty,
			cleanAfterSecondDirty,
		)
	}
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatalf("second continuity loss did not deny egress: %v", err)
	}

	_, err = RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedStaleFuture,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err == nil {
		t.Fatal("stale epoch-1 recovery authorization was replayed after epoch-2 invalidation")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("stale recovery replay failed for an unexpected reason: %v", err)
	}
	dirtyAfterReplay, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if dirtyAfterReplay != secondDirty {
		t.Fatalf("stale recovery replay mutated DIRTY: before=%d after=%d", secondDirty, dirtyAfterReplay)
	}
	cleanAfterReplay, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cleanAfterReplay != cleanAfterSecondDirty {
		t.Fatalf(
			"stale recovery replay mutated clean watermark: before=%d after=%d",
			cleanAfterSecondDirty,
			cleanAfterReplay,
		)
	}
	epochAfterReplay, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if epochAfterReplay != epochAfterRecovery {
		t.Fatalf("stale recovery replay mutated epoch: before=%d after=%d", epochAfterRecovery, epochAfterReplay)
	}
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatalf("stale recovery replay restored egress: %v", err)
	}

	// The first crash boundary proved fail-closed resume before CLEAN. Now prove
	// the opposite lost-reply shape: recovery reaches CLEAN successfully, then
	// the controller dies before it clears the pending commitment or returns its
	// result. The next process must reconcile completion, not execute recovery
	// again.
	if err := movePIDToCgroup(originalCgroup, os.Getpid()); err != nil {
		t.Fatalf("move lost-receipt recovery controller outside protected cgroup: %v", err)
	}

	cleanCrashAuth := recoveryAuth
	cleanCrashAuth.AuthorizationID = "native-source-recovery-epoch-2-to-3-lost-receipt"
	cleanCrashAuth.FromEpoch = epochAfterRecovery
	cleanCrashAuth.ToEpoch = epochAfterRecovery + 1
	cleanCrashAuth.ExpectedDirty = secondDirty
	signedCleanCrash, err := SignTaintRecoveryAuthorization(cleanCrashAuth, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	cleanCrashCommitment, err := TaintRecoveryCommitmentDigest(signedCleanCrash)
	if err != nil {
		t.Fatal(err)
	}
	cleanCrashAuthPath := filepath.Join(recoveryDir, "clean-crash-authorization.json")
	cleanCrashPayload, err := json.Marshal(signedCleanCrash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cleanCrashAuthPath, cleanCrashPayload, 0o600); err != nil {
		t.Fatalf("write post-CLEAN crash authorization: %v", err)
	}

	cleanCrash := exec.Command(os.Args[0], "-test.run=^TestTaintRecoveryCrashHelper$")
	cleanCrash.Env = append(os.Environ(),
		taintRecoveryCrashHelperEnv+"=1",
		taintRecoveryPlanEnv+"="+recoveryPlanPath,
		taintRecoveryAuthEnv+"="+cleanCrashAuthPath,
		taintRecoveryKeyEnv+"="+base64.StdEncoding.EncodeToString(recoveryPublic),
		taintRecoveryNowEnv+"="+now.Format(time.RFC3339Nano),
		taintRecoveryBoundaryEnv+"=clean",
		taintNativeHelperBPFFSRoot+"="+bpffsRoot,
	)
	cleanCrash.Stdout = os.Stdout
	cleanCrash.Stderr = os.Stderr
	err = cleanCrash.Run()
	var cleanExitErr *exec.ExitError
	if !errors.As(err, &cleanExitErr) || cleanExitErr.ExitCode() != 87 {
		t.Fatalf("recovery controller did not die after CLEAN commit: %v", err)
	}

	epochAfterCleanCrash, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	dirtyAfterCleanCrash, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	cleanAfterCleanCrash, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	pendingAfterCleanCrash, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if epochAfterCleanCrash != cleanCrashAuth.ToEpoch ||
		dirtyAfterCleanCrash != cleanCrashAuth.ExpectedDirty ||
		cleanAfterCleanCrash != cleanCrashAuth.ExpectedDirty ||
		pendingAfterCleanCrash != cleanCrashCommitment {
		t.Fatalf(
			"lost-receipt state mismatch: epoch=%d dirty=%d clean=%d pending_match=%t",
			epochAfterCleanCrash,
			dirtyAfterCleanCrash,
			cleanAfterCleanCrash,
			pendingAfterCleanCrash == cleanCrashCommitment,
		)
	}

	// CLEAN already committed before the reply was lost, so the effect boundary
	// is open. This distinguishes lost reply from the pre-CLEAN crash case.
	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move workload into protected cgroup after lost recovery reply: %v", err)
	}
	conn, err = net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("committed recovery was not observable after lost reply: %v", err)
	}
	_ = conn.Close()
	if err := movePIDToCgroup(originalCgroup, os.Getpid()); err != nil {
		t.Fatalf("move reconciliation controller outside protected cgroup: %v", err)
	}

	// Same numeric state is insufficient to acknowledge the completed recovery.
	// The exact signed commitment that produced CLEAN must still match.
	wrongCompletedAuth := cleanCrashAuth
	wrongCompletedAuth.AuthorizationID = "different-completed-recovery-at-same-state"
	signedWrongCompleted, err := SignTaintRecoveryAuthorization(wrongCompletedAuth, recoveryPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedWrongCompleted,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("different authorization acknowledged completed recovery: %v", err)
	}
	pendingAfterWrongAck, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfterWrongAck != cleanCrashCommitment {
		t.Fatal("rejected completed-recovery acknowledgement mutated pending commitment")
	}

	sourcesBeforeAck := nativeTaintSourceSnapshot(t, bpffsRoot)
	acknowledged, err := RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedCleanCrash,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("reconcile completed recovery after lost reply: %v", err)
	}
	if acknowledged.PreviousEpoch != cleanCrashAuth.FromEpoch ||
		acknowledged.EnrollmentEpoch != cleanCrashAuth.ToEpoch ||
		acknowledged.AdmittedDirtyGen != cleanCrashAuth.ExpectedDirty {
		t.Fatalf("unexpected completed-recovery acknowledgement: %+v", acknowledged)
	}
	pendingAfterAck, err := TaintRecoveryCommitmentState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	var emptyCommitmentAfterAck [32]byte
	if pendingAfterAck != emptyCommitmentAfterAck {
		t.Fatal("completed recovery acknowledgement did not clear pending commitment")
	}
	epochAfterAck, err := TaintEnrollmentEpoch(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	dirtyAfterAck, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	cleanAfterAck, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if epochAfterAck != epochAfterCleanCrash ||
		dirtyAfterAck != dirtyAfterCleanCrash ||
		cleanAfterAck != cleanAfterCleanCrash {
		t.Fatalf(
			"completed recovery acknowledgement re-executed state transition: epoch=%d->%d dirty=%d->%d clean=%d->%d",
			epochAfterCleanCrash,
			epochAfterAck,
			dirtyAfterCleanCrash,
			dirtyAfterAck,
			cleanAfterCleanCrash,
			cleanAfterAck,
		)
	}
	sourcesAfterAck := nativeTaintSourceSnapshot(t, bpffsRoot)
	if !reflect.DeepEqual(sourcesBeforeAck, sourcesAfterAck) {
		t.Fatalf(
			"completed recovery acknowledgement rewrote source enrollment: before=%v after=%v",
			sourcesBeforeAck,
			sourcesAfterAck,
		)
	}

	// Once acknowledged, even the exact authorization is no longer an in-flight
	// operation. Re-presenting it must not manufacture a second SUCCESS.
	_, err = RecoverTaintSourceContinuity(TaintRecoveryRequest{
		BPFFSRoot:            bpffsRoot,
		Plan:                 recoveryPlan,
		SignedAuthorization:  signedCleanCrash,
		RecoveryAuthorityKey: recoveryPublic,
		Now:                  now,
	})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("acknowledged recovery was accepted a second time: %v", err)
	}

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move workload into protected cgroup after reconciliation: %v", err)
	}
	conn, err = net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("reconciliation changed already-committed recovery effect: %v", err)
	}
	_ = conn.Close()
	if err := movePIDToCgroup(originalCgroup, os.Getpid()); err != nil {
		t.Fatalf("restore controller cgroup after reconciliation: %v", err)
	}

	t.Logf(
		"recovery crash boundaries reconciled without duplicate recovery: first_epoch=%d second_dirty=%d lost_reply_epoch=%d lost_reply_dirty=%d lost_reply_clean=%d acknowledged_epoch=%d",
		epochAfterRecovery,
		secondDirty,
		epochAfterCleanCrash,
		dirtyAfterCleanCrash,
		cleanAfterCleanCrash,
		epochAfterAck,
	)
}

func nativeTaintSourceSnapshot(t *testing.T, bpffsRoot string) map[TaintFileKey]uint64 {
	t.Helper()
	m, err := openExactTaintMap(
		filepath.Join(bpffsRoot, "maps", "aegis_tsrc"),
		ebpf.Hash,
		16,
		8,
		32768,
	)
	if err != nil {
		t.Fatalf("open taint source map for snapshot: %v", err)
	}
	defer m.Close()
	snapshot, err := snapshotTaintSourceMap(m)
	if err != nil {
		t.Fatalf("snapshot taint source map: %v", err)
	}
	return snapshot
}

func attachNativeLoopDevice(t *testing.T, imagePath string) (string, func()) {
	t.Helper()

	cmd := exec.Command("losetup", "--find", "--show", imagePath)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("attach inode-reuse loop device: %v", err)
	}
	loopPath := string(output)
	for len(loopPath) > 0 && (loopPath[len(loopPath)-1] == '\n' || loopPath[len(loopPath)-1] == '\r') {
		loopPath = loopPath[:len(loopPath)-1]
	}
	if loopPath == "" {
		t.Fatal("losetup returned an empty loop device path")
	}

	return loopPath, func() {
		if err := exec.Command("losetup", "-d", loopPath).Run(); err != nil {
			t.Logf("detach inode-reuse loop device %s: %v", loopPath, err)
		}
	}
}
