//go:build linux && taintnative

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	taintInodeReuseHelperEnv   = "AEGIS_TAINT_INODE_REUSE_HELPER"
	taintRestartObserverEnv    = "AEGIS_TAINT_RESTART_OBSERVER"
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
