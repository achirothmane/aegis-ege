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
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestNativeTaintBindMountSubstitutionFailsClosed attacks source lifetime after
// activation without renaming or unlinking the enrolled inode. A bind mount
// shadows the enrolled path with a different regular file. Safety requires the
// mount-topology guard to make source continuity DIRTY before a clean reader can
// use the substituted path and regain egress.
func TestNativeTaintBindMountSubstitutionFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint mount-substitution test requires root")
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
	testID := fmt.Sprintf("aegis-taint-mount-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create mount-substitution cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create mount-substitution bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	artifact := filepath.Join(t.TempDir(), "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize taint BPF object: %v", err)
	}
	overlay := mountNativeOverlaySource(t)
	secretPath := overlay.SecretPath

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
		t.Fatalf("load mount-lifetime taint BPF programs: %v", err)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, secretPath)
	if err != nil {
		t.Fatalf("kernel-observe mount-lifetime source: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("mount-lifetime source probe returned no kernel identities")
	}
	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources:       make([]TaintSourceBinding, 0, len(sourceKeys)),
	}
	for _, key := range sourceKeys {
		plan.Sources = append(plan.Sources, TaintSourceBinding{
			Path:   secretPath,
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
		t.Fatalf("activate mount-lifetime taint cgroup: %v", err)
	}

	dirtyBefore, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity before bind substitution: %v", err)
	}
	if dirtyBefore != 0 {
		t.Fatalf("source continuity dirty before bind substitution: %d", dirtyBefore)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move mount-substitution test into protected cgroup: %v", err)
	}

	// Positive control: the parent is clean and source continuity is intact.
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("clean egress unexpectedly denied before bind substitution: %v", err)
	}
	_ = conn.Close()

	// Fork a clean child before the source path is shadowed. It waits until the
	// bind mount exists, then reads the substituted file and attempts egress.
	child := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	child.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=replacement",
		taintNativeHelperAddr+"="+listener.Addr().String(),
		taintNativeHelperSource+"="+secretPath,
	)
	childStdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatalf("start clean bind-substitution child: %v", err)
	}
	childPID := uint32(child.Process.Pid)

	substitutePath := filepath.Join(t.TempDir(), "substitute-secret.txt")
	if err := os.WriteFile(substitutePath, []byte("substituted-unenrolled-object"), 0o600); err != nil {
		t.Fatalf("write bind-mount substitute: %v", err)
	}
	substituteKey, err := ResolveTaintFileKey(substitutePath)
	if err != nil {
		t.Fatalf("resolve bind-mount substitute identity: %v", err)
	}

	if err := unix.Mount(substitutePath, secretPath, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind substitute over enrolled source path: %v", err)
	}
	defer func() {
		if err := unix.Unmount(secretPath, unix.MNT_DETACH); err != nil {
			t.Logf("unmount bind substitute: %v", err)
		}
	}()

	dirtyAfter, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after bind substitution: %v", err)
	}
	if dirtyAfter <= dirtyBefore {
		t.Fatalf(
			"bind mount did not invalidate source continuity: before=%d after=%d",
			dirtyBefore,
			dirtyAfter,
		)
	}
	t.Logf(
		"bind substitution invalidated source lifetime: enrolled=%+v substitute_userspace=%+v dirty=%d",
		sourceKeys,
		substituteKey,
		dirtyAfter,
	)

	if _, err := childStdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := childStdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("clean child escaped after bind-mount source substitution: %v", err)
	}
	if err := assertNativeProcessUntainted(bpffsRoot, childPID); err != nil {
		t.Fatalf(
			"bind-substitution denial was not isolated to source continuity: %v",
			err,
		)
	}

	isActive, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("mount-substitution schedule removed protected-cgroup activation")
	}
}

// TestNativeTaintAncestorRenameSubstitutionFailsClosed attacks the distinction
// between object identity and path identity. The enrolled source inode remains
// alive, but its parent directory is renamed and a clean sibling directory is
// moved into the original pathname. Without a path-topology lifetime guard the
// absolute source path can therefore resolve to an unenrolled object while the
// original enrolled inode was never renamed or unlinked.
func TestNativeTaintAncestorRenameSubstitutionFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint ancestor-substitution test requires root")
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
	testID := fmt.Sprintf("aegis-taint-ancestor-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create ancestor-substitution cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create ancestor-substitution bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	artifact := filepath.Join(t.TempDir(), "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize taint BPF object: %v", err)
	}

	overlay := mountNativeOverlaySource(t)
	mergedRoot := filepath.Dir(overlay.SecretPath)
	trustedParent := filepath.Join(mergedRoot, "trusted-parent")
	cleanParent := filepath.Join(mergedRoot, "clean-parent")
	for _, dir := range []string{trustedParent, cleanParent} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create source-lifetime directory %s: %v", dir, err)
		}
	}
	secretPath := filepath.Join(trustedParent, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("classified-ancestor-source"), 0o600); err != nil {
		t.Fatalf("write ancestor source: %v", err)
	}
	cleanReplacement := filepath.Join(cleanParent, "secret.txt")
	if err := os.WriteFile(cleanReplacement, []byte("unenrolled-ancestor-substitute"), 0o600); err != nil {
		t.Fatalf("write ancestor substitute: %v", err)
	}
	replacementKey, err := ResolveTaintFileKey(cleanReplacement)
	if err != nil {
		t.Fatalf("resolve ancestor substitute identity: %v", err)
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
		t.Fatalf("load ancestor-lifetime taint BPF programs: %v", err)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, secretPath)
	if err != nil {
		t.Fatalf("kernel-observe ancestor source: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("ancestor source probe returned no kernel identities")
	}
	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources:       make([]TaintSourceBinding, 0, len(sourceKeys)),
	}
	for _, key := range sourceKeys {
		plan.Sources = append(plan.Sources, TaintSourceBinding{
			Path:   secretPath,
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
		t.Fatalf("activate ancestor-lifetime taint cgroup: %v", err)
	}

	dirtyBefore, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity before ancestor substitution: %v", err)
	}
	if dirtyBefore != 0 {
		t.Fatalf("source continuity dirty before ancestor substitution: %d", dirtyBefore)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move ancestor-substitution test into protected cgroup: %v", err)
	}

	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("clean egress unexpectedly denied before ancestor substitution: %v", err)
	}
	_ = conn.Close()

	child := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	child.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=replacement",
		taintNativeHelperAddr+"="+listener.Addr().String(),
		taintNativeHelperSource+"="+secretPath,
	)
	childStdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatalf("start clean ancestor-substitution child: %v", err)
	}
	childPID := uint32(child.Process.Pid)

	retiredParent := filepath.Join(mergedRoot, "trusted-parent-retired")
	if err := os.Rename(trustedParent, retiredParent); err != nil {
		t.Fatalf("rename enrolled source parent away: %v", err)
	}
	if err := os.Rename(cleanParent, trustedParent); err != nil {
		t.Fatalf("move clean parent onto enrolled source pathname: %v", err)
	}

	resolvedReplacement, err := ResolveTaintFileKey(secretPath)
	if err != nil {
		t.Fatalf("resolve substituted ancestor source path: %v", err)
	}
	if resolvedReplacement != replacementKey {
		t.Fatalf(
			"ancestor substitution did not install expected replacement: got=%+v want=%+v",
			resolvedReplacement,
			replacementKey,
		)
	}

	dirtyAfter, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after ancestor substitution: %v", err)
	}
	if dirtyAfter <= dirtyBefore {
		t.Fatalf(
			"ancestor directory rename did not invalidate source continuity: before=%d after=%d enrolled=%+v replacement=%+v",
			dirtyBefore,
			dirtyAfter,
			sourceKeys,
			resolvedReplacement,
		)
	}

	if _, err := childStdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := childStdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("clean child escaped after ancestor source substitution: %v", err)
	}
	if err := assertNativeProcessUntainted(bpffsRoot, childPID); err != nil {
		t.Fatalf("ancestor-substitution denial was not isolated to source continuity: %v", err)
	}

	isActive, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("ancestor-substitution schedule removed protected-cgroup activation")
	}
}


// TestNativeTaintAncestorSymlinkSubstitutionFailsClosed proves that source
// identity is not confused with source-path meaning when an intermediate
// symlink is atomically redirected after activation. The enrolled regular-file
// inode remains alive and no mount topology changes, but the same absolute path
// resolves to a different unenrolled object.
func TestNativeTaintAncestorSymlinkSubstitutionFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint ancestor-symlink test requires root")
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
	testID := fmt.Sprintf("aegis-taint-symlink-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create ancestor-symlink cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create ancestor-symlink bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	artifact := filepath.Join(t.TempDir(), "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize taint BPF object: %v", err)
	}

	overlay := mountNativeOverlaySource(t)
	mergedRoot := filepath.Dir(overlay.SecretPath)
	trustedParent := filepath.Join(mergedRoot, "symlink-trusted")
	cleanParent := filepath.Join(mergedRoot, "symlink-clean")
	for _, dir := range []string{trustedParent, cleanParent} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create ancestor-symlink directory %s: %v", dir, err)
		}
	}
	trustedFile := filepath.Join(trustedParent, "secret.txt")
	if err := os.WriteFile(trustedFile, []byte("classified-symlink-source"), 0o600); err != nil {
		t.Fatalf("write ancestor-symlink source: %v", err)
	}
	cleanReplacement := filepath.Join(cleanParent, "secret.txt")
	if err := os.WriteFile(cleanReplacement, []byte("unenrolled-symlink-substitute"), 0o600); err != nil {
		t.Fatalf("write ancestor-symlink substitute: %v", err)
	}

	sourceLink := filepath.Join(mergedRoot, "source-view")
	if err := os.Symlink(trustedParent, sourceLink); err != nil {
		t.Fatalf("create enrolled source ancestor symlink: %v", err)
	}
	secretPath := filepath.Join(sourceLink, "secret.txt")
	replacementKey, err := ResolveTaintFileKey(cleanReplacement)
	if err != nil {
		t.Fatalf("resolve ancestor-symlink substitute identity: %v", err)
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
		t.Fatalf("load ancestor-symlink taint BPF programs: %v", err)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, secretPath)
	if err != nil {
		t.Fatalf("kernel-observe ancestor-symlink source: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("ancestor-symlink source probe returned no kernel identities")
	}
	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources:       make([]TaintSourceBinding, 0, len(sourceKeys)),
	}
	for _, key := range sourceKeys {
		plan.Sources = append(plan.Sources, TaintSourceBinding{
			Path:   secretPath,
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
		t.Fatalf("activate ancestor-symlink taint cgroup: %v", err)
	}

	dirtyBefore, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity before ancestor-symlink substitution: %v", err)
	}
	if dirtyBefore != 0 {
		t.Fatalf("source continuity dirty before ancestor-symlink substitution: %d", dirtyBefore)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move ancestor-symlink test into protected cgroup: %v", err)
	}
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("clean egress unexpectedly denied before ancestor-symlink substitution: %v", err)
	}
	_ = conn.Close()

	child := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	child.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=replacement",
		taintNativeHelperAddr+"="+listener.Addr().String(),
		taintNativeHelperSource+"="+secretPath,
	)
	childStdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatalf("start clean ancestor-symlink child: %v", err)
	}
	childPID := uint32(child.Process.Pid)

	replacementLink := filepath.Join(mergedRoot, "source-view-next")
	if err := os.Symlink(cleanParent, replacementLink); err != nil {
		t.Fatalf("create replacement ancestor symlink: %v", err)
	}
	if err := os.Rename(replacementLink, sourceLink); err != nil {
		t.Fatalf("atomically replace enrolled ancestor symlink: %v", err)
	}

	resolvedReplacement, err := ResolveTaintFileKey(secretPath)
	if err != nil {
		t.Fatalf("resolve substituted ancestor-symlink source path: %v", err)
	}
	if resolvedReplacement != replacementKey {
		t.Fatalf(
			"ancestor-symlink substitution did not install expected replacement: got=%+v want=%+v",
			resolvedReplacement,
			replacementKey,
		)
	}

	dirtyAfter, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatalf("read source continuity after ancestor-symlink substitution: %v", err)
	}
	if dirtyAfter <= dirtyBefore {
		t.Fatalf(
			"ancestor symlink replacement did not invalidate source continuity: before=%d after=%d enrolled=%+v replacement=%+v",
			dirtyBefore,
			dirtyAfter,
			sourceKeys,
			resolvedReplacement,
		)
	}

	if _, err := childStdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := childStdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("clean child escaped after ancestor-symlink source substitution: %v", err)
	}
	if err := assertNativeProcessUntainted(bpffsRoot, childPID); err != nil {
		t.Fatalf("ancestor-symlink denial was not isolated to source continuity: %v", err)
	}

	isActive, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("ancestor-symlink schedule removed protected-cgroup activation")
	}
}

func assertNativeProcessUntainted(bpffsRoot string, tgid uint32) error {
	m, err := openExactTaintMap(
		filepath.Join(bpffsRoot, "maps", "aegis_ptaint"),
		ebpf.Hash,
		4,
		8,
		65536,
	)
	if err != nil {
		return err
	}
	defer m.Close()

	var got uint64
	if err := m.Lookup(&tgid, &got); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("lookup tgid %d: %w", tgid, err)
	}
	if got != 0 {
		return fmt.Errorf("tgid %d unexpectedly tainted with labels=%#x", tgid, got)
	}
	return nil
}
