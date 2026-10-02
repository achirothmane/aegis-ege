//go:build linux && taintnative

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:embed testdata/aegis_taint.bpf.o
var nativeTaintBPFObject []byte

const (
	taintNativeHelperEnv          = "AEGIS_TAINT_NATIVE_HELPER"
	taintNativeHelperMode         = "AEGIS_TAINT_NATIVE_HELPER_MODE"
	taintNativeHelperAddr         = "AEGIS_TAINT_NATIVE_HELPER_ADDR"
	taintNativeHelperBridge       = "AEGIS_TAINT_NATIVE_HELPER_BRIDGE"
	taintNativeHelperBPFFSRoot    = "AEGIS_TAINT_NATIVE_HELPER_BPFFS_ROOT"
	taintNativeHelperEscapeCgroup = "AEGIS_TAINT_NATIVE_HELPER_ESCAPE_CGROUP"
	taintNativeHelperCgroupID     = "AEGIS_TAINT_NATIVE_HELPER_CGROUP_ID"
	taintNativeHelperHostUID      = "AEGIS_TAINT_NATIVE_HELPER_HOST_UID"
	taintNativeHelperHostGID      = "AEGIS_TAINT_NATIVE_HELPER_HOST_GID"
)

func TestTaintNativeHelper(t *testing.T) {
	if os.Getenv(taintNativeHelperEnv) != "1" {
		return
	}

	switch os.Getenv(taintNativeHelperMode) {
	case "fork":
		if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
			t.Fatal(err)
		}
	case "file":
		if _, err := io.ReadAll(os.Stdin); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(os.Getenv(taintNativeHelperBridge)); err != nil {
			t.Fatal(err)
		}
		if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
			t.Fatal(err)
		}
	case "hostile":
		cgroupID, err := strconv.ParseUint(os.Getenv(taintNativeHelperCgroupID), 10, 64)
		if err != nil {
			t.Fatalf("parse hostile helper cgroup id: %v", err)
		}
		if err := attemptHostileGuardDisable(
			os.Getenv(taintNativeHelperBPFFSRoot),
			os.Getenv(taintNativeHelperEscapeCgroup),
			cgroupID,
		); err != nil {
			t.Fatal(err)
		}
		if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
			t.Fatal(err)
		}
	case "hostile-isolated":
		time.Sleep(100 * time.Millisecond)
		hostUID, err := strconv.ParseUint(os.Getenv(taintNativeHelperHostUID), 10, 32)
		if err != nil {
			t.Fatalf("parse isolated hostile host uid: %v", err)
		}
		hostGID, err := strconv.ParseUint(os.Getenv(taintNativeHelperHostGID), 10, 32)
		if err != nil {
			t.Fatalf("parse isolated hostile host gid: %v", err)
		}
		if err := assertHostUserNamespaceMapping(uint32(hostUID), uint32(hostGID)); err != nil {
			t.Fatal(err)
		}
		cgroupID, err := strconv.ParseUint(os.Getenv(taintNativeHelperCgroupID), 10, 64)
		if err != nil {
			t.Fatalf("parse isolated hostile cgroup id: %v", err)
		}
		if err := attemptNamespacedHostileGuardDisable(
			os.Getenv(taintNativeHelperBPFFSRoot),
			os.Getenv(taintNativeHelperEscapeCgroup),
			cgroupID,
		); err != nil {
			t.Fatal(err)
		}
		if err := expectNativeDialDenied(os.Getenv(taintNativeHelperAddr)); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown native helper mode %q", os.Getenv(taintNativeHelperMode))
	}
}

func TestNativeTaintReadForkFileAndEgress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint test requires root")
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
	testID := fmt.Sprintf("aegis-taint-native-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create test bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	workDir := filepath.Join(t.TempDir(), "taintfs")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatalf("create native taint tmpfs mountpoint: %v", err)
	}
	if err := unix.Mount(
		"aegis-taint-native",
		workDir,
		"tmpfs",
		0,
		"mode=0700,size=16m",
	); err != nil {
		t.Fatalf("mount native taint tmpfs: %v", err)
	}
	defer func() {
		if err := unix.Unmount(workDir, unix.MNT_DETACH); err != nil {
			t.Logf("unmount native taint tmpfs: %v", err)
		}
	}()

	// Keep the first privileged proof on a non-stacked filesystem. The previous
	// run falsified the assumption that stat(2) device identity always matches
	// every file_permission identity observed through a stacked guest rootfs.
	// Stacked-filesystem source registration remains a separate fail-closed
	// claim boundary; this test proves the kernel hooks and propagation path.
	artifact := filepath.Join(workDir, "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize embedded taint BPF object: %v", err)
	}
	secretPath := mountNativeOverlaySource(t)
	bridgePath := filepath.Join(workDir, "bridge.txt")
	if err := os.WriteFile(bridgePath, nil, 0o600); err != nil {
		t.Fatal(err)
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
		t.Fatalf("load and attach taint BPF programs: %v", err)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, secretPath)
	if err != nil {
		t.Fatalf("kernel-observe overlay source identities: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("overlay source probe returned no kernel identities")
	}
	statKey, err := ResolveTaintFileKey(secretPath)
	if err != nil {
		t.Fatalf("resolve userspace overlay source identity: %v", err)
	}
	t.Logf("overlay source userspace identity=%+v kernel identities=%+v", statKey, sourceKeys)

	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources:       make([]TaintSourceBinding, 0, len(sourceKeys)),
	}
	for _, key := range sourceKeys {
		plan.Sources = append(plan.Sources, TaintSourceBinding{
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
		t.Fatalf("activate taint cgroup: %v", err)
	}
	if activated.CgroupID == 0 || activated.PlanDigest == "" {
		t.Fatal("activation result is incomplete")
	}
	isActive, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !isActive {
		t.Fatal("protected-cgroup activation is not observable after activation")
	}

	reader, err := OpenPinnedTaintEvidenceReader(bpffsRoot)
	if err != nil {
		t.Fatalf("open taint evidence reader: %v", err)
	}
	defer reader.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move test process into protected cgroup: %v", err)
	}

	// Positive control: clean process egress remains possible.
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("clean egress unexpectedly denied: %v", err)
	}
	_ = conn.Close()

	// Start an initially clean child before the parent becomes tainted. It will
	// later read a bridge file written by the tainted parent.
	fileChild := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	fileChild.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=file",
		taintNativeHelperAddr+"="+listener.Addr().String(),
		taintNativeHelperBridge+"="+bridgePath,
	)
	stdin, err := fileChild.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	fileChild.Stdout = os.Stdout
	fileChild.Stderr = os.Stderr
	if err := fileChild.Start(); err != nil {
		t.Fatalf("start clean file-propagation child: %v", err)
	}

	if _, err := os.ReadFile(secretPath); err != nil {
		t.Fatalf("read configured sensitive source: %v", err)
	}
	if err := assertNativeProcessTaint(bpffsRoot, uint32(os.Getpid()), 1); err != nil {
		diagnostic := diagnoseNativeReadKeys(
			reader,
			activated.CgroupID,
			uint32(os.Getpid()),
			sourceKeys,
		)
		t.Fatalf(
			"overlay sensitive read did not produce process taint: %v; kernel read observations: %s; configured kernel sources: %+v; userspace stat source: %+v",
			err,
			diagnostic,
			sourceKeys,
			statKey,
		)
	}
	if err := os.WriteFile(bridgePath, []byte("launder-attempt"), 0o600); err != nil {
		t.Fatalf("write bridge file: %v", err)
	}
	bridgeKey, err := ResolveTaintFileKey(bridgePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertNativeFileTaint(bpffsRoot, bridgeKey, 1); err != nil {
		t.Fatalf("tainted write did not propagate into bridge file: %v", err)
	}

	// Direct tainted egress must fail.
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	// Child forked after parent taint must inherit taint even without reading
	// the secret or bridge file itself.
	forkChild := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	forkChild.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=fork",
		taintNativeHelperAddr+"="+listener.Addr().String(),
	)
	forkChild.Stdout = os.Stdout
	forkChild.Stderr = os.Stderr
	if err := forkChild.Run(); err != nil {
		t.Fatalf("fork-propagation child escaped taint egress guard: %v", err)
	}

	// M15a: run the compromised workload as an unprivileged actor in the same
	// protected cgroup. It may inspect its environment and create child
	// processes, but it must not be able to remove BPF links, mutate the
	// protected-cgroup map, escape the cgroup, unmount bpffs, or regain egress.
	hostileChild := exec.Command(os.Args[0], "-test.run=^TestTaintNativeHelper$")
	hostileChild.Env = append(os.Environ(),
		taintNativeHelperEnv+"=1",
		taintNativeHelperMode+"=hostile",
		taintNativeHelperAddr+"="+listener.Addr().String(),
		taintNativeHelperBPFFSRoot+"="+bpffsRoot,
		taintNativeHelperEscapeCgroup+"="+originalCgroup,
		taintNativeHelperCgroupID+"="+strconv.FormatUint(activated.CgroupID, 10),
	)
	hostileChild.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:         65534,
			Gid:         65534,
			NoSetGroups: true,
		},
	}
	hostileChild.Stdout = os.Stdout
	hostileChild.Stderr = os.Stderr
	if err := hostileChild.Run(); err != nil {
		t.Fatalf("M15 hostile workload disabled or bypassed the taint guard: %v", err)
	}
	isActive, err = TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatalf("observe M15 activation state: %v", err)
	}
	if !isActive {
		t.Fatal("M15 hostile workload removed protected-cgroup activation")
	}

	// M15b: use the actual attested workload launcher with a signed isolation
	// profile. The workload is root only in a fresh user namespace mapped to
	// non-root host identities. It then repeats privileged guard-disable attacks.
	if err := runM15bIsolatedHostileWorkload(
		t,
		cgroupPath,
		originalCgroup,
		bpffsRoot,
		activated.CgroupID,
		listener.Addr().String(),
	); err != nil {
		t.Fatal(err)
	}
	isActive, err = TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatalf("observe M15b activation state: %v", err)
	}
	if !isActive {
		t.Fatal("M15b isolated hostile workload removed protected-cgroup activation")
	}

	// Release the child that was created while the parent was still clean.
	// Reading the tainted bridge file must taint that child before its connect.
	if _, err := stdin.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fileChild.Wait(); err != nil {
		t.Fatalf("file-propagation child escaped taint egress guard: %v", err)
	}

	if err := waitForNativeTaintEvidence(reader, activated.CgroupID); err != nil {
		t.Fatal(err)
	}
}

func mountNativeOverlaySource(t *testing.T) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "overlay-backing")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create overlay backing mountpoint: %v", err)
	}
	if err := unix.Mount(
		"aegis-overlay-backing",
		root,
		"tmpfs",
		0,
		"mode=0700,size=16m",
	); err != nil {
		t.Fatalf("mount overlay tmpfs backing: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, unix.MNT_DETACH); err != nil {
			t.Logf("unmount overlay tmpfs backing: %v", err)
		}
	})

	lower := filepath.Join(root, "lower")
	upper := filepath.Join(root, "upper")
	work := filepath.Join(root, "work")
	merged := filepath.Join(root, "merged")
	for _, dir := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create overlay directory %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "secret.txt"), []byte("classified"), 0o600); err != nil {
		t.Fatalf("write overlay lower secret: %v", err)
	}
	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		lower,
		upper,
		work,
	)
	if err := unix.Mount("overlay", merged, "overlay", 0, options); err != nil {
		t.Fatalf("mount native overlay source on tmpfs backing: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(merged, unix.MNT_DETACH); err != nil {
			t.Logf("unmount native overlay source: %v", err)
		}
	})
	return filepath.Join(merged, "secret.txt")
}

func runM15bIsolatedHostileWorkload(
	t *testing.T,
	cgroupPath string,
	escapeCgroup string,
	bpffsRoot string,
	cgroupID uint64,
	address string,
) error {
	t.Helper()

	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		return fmt.Errorf("resolve native helper executable: %w", err)
	}
	const hostUID = uint32(65534)
	const hostGID = uint32(65534)
	spec := WorkloadLaunchSpec{
		Executable: executable,
		Args:       []string{"-test.run=^TestTaintNativeHelper$"},
		Environment: []WorkloadEnvironmentVariable{
			{Name: taintNativeHelperEnv, Value: "1"},
			{Name: taintNativeHelperMode, Value: "hostile-isolated"},
			{Name: taintNativeHelperAddr, Value: address},
			{Name: taintNativeHelperBPFFSRoot, Value: bpffsRoot},
			{Name: taintNativeHelperEscapeCgroup, Value: escapeCgroup},
			{Name: taintNativeHelperCgroupID, Value: strconv.FormatUint(cgroupID, 10)},
			{Name: taintNativeHelperHostUID, Value: strconv.FormatUint(uint64(hostUID), 10)},
			{Name: taintNativeHelperHostGID, Value: strconv.FormatUint(uint64(hostGID), 10)},
		},
		LinuxIsolation: &LinuxWorkloadIsolationSpec{
			Mode:    LinuxWorkloadIsolationUserNamespaceV1,
			HostUID: hostUID,
			HostGID: hostGID,
		},
	}
	specDigest, err := WorkloadLaunchSpecDigest(spec)
	if err != nil {
		return err
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	grant, err := SignWorkloadAdmissionGrant(WorkloadAdmissionGrant{
		Version:              WorkloadAdmissionGrantVersion,
		GrantID:              "m15b-native-grant",
		RequestID:            "m15b-native-request",
		DeviceID:             "m15b-native-device",
		WorkloadID:           "m15b-hostile-workload",
		WorkloadSpecDigest:   specDigest,
		TargetCgroup:         cgroupPath,
		TargetCgroupID:       cgroupID,
		BootstrapDigest:      "sha256:" + strings.Repeat("a", 64),
		RemoteDecisionID:     "m15b-native-remote-decision",
		RemoteDecisionDigest: "sha256:" + strings.Repeat("b", 64),
		IssuerID:             "m15b-native-admission",
		NotBefore:            now.Add(-time.Second),
		ExpiresAt:            now.Add(time.Minute),
	}, issuerPrivate)
	if err != nil {
		return err
	}

	started, err := StartAttestedWorkload(context.Background(), AttestedWorkloadLaunchRequest{
		SignedGrant:     grant,
		IssuerPublicKey: issuerPublic,
		LaunchSpec:      spec,
		ConsumptionDir:  filepath.Join(t.TempDir(), "m15b-consumed"),
		DeviceID:        "m15b-native-device",
		HostAttestorKey: hostPrivate,
		Now:             now,
	})
	if err != nil {
		return fmt.Errorf("M15b start isolated hostile workload: %w", err)
	}
	if err := started.Command.Wait(); err != nil {
		return fmt.Errorf("M15b isolated hostile workload escaped separation: %w", err)
	}
	if err := VerifySignedWorkloadActivationReceipt(
		started.SignedReceipt,
		hostPrivate.Public().(ed25519.PublicKey),
	); err != nil {
		return fmt.Errorf("M15b activation receipt verification: %w", err)
	}
	return nil
}

func assertHostUserNamespaceMapping(hostUID, hostGID uint32) error {
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return fmt.Errorf("read isolated uid_map: %w", err)
	}
	gidMap, err := os.ReadFile("/proc/self/gid_map")
	if err != nil {
		return fmt.Errorf("read isolated gid_map: %w", err)
	}
	wantUID := fmt.Sprintf("0 %d 1", hostUID)
	wantGID := fmt.Sprintf("0 %d 1", hostGID)
	if !mappingContains(uidMap, wantUID) {
		return fmt.Errorf("host uid isolation missing: uid_map=%q want=%q", strings.TrimSpace(string(uidMap)), wantUID)
	}
	if !mappingContains(gidMap, wantGID) {
		return fmt.Errorf("host gid isolation missing: gid_map=%q want=%q", strings.TrimSpace(string(gidMap)), wantGID)
	}
	return nil
}

func mappingContains(payload []byte, want string) bool {
	wantFields := strings.Fields(want)
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) != len(wantFields) {
			continue
		}
		match := true
		for i := range fields {
			if fields[i] != wantFields[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func attemptNamespacedHostileGuardDisable(
	bpffsRoot string,
	escapeCgroup string,
	cgroupID uint64,
) error {
	for _, path := range []string{
		filepath.Join(bpffsRoot, "links", "aegis_tconn4"),
		filepath.Join(bpffsRoot, "links", "aegis_tconn6"),
		filepath.Join(bpffsRoot, "links", "aegis_fperm"),
		filepath.Join(bpffsRoot, "links", "aegis_fork"),
	} {
		if err := os.Remove(path); err == nil {
			return fmt.Errorf("namespaced hostile actor removed host enforcement link %s", path)
		}
	}

	mapPath := filepath.Join(bpffsRoot, "maps", "aegis_tcgroups")
	if protected, err := ebpf.LoadPinnedMap(mapPath, nil); err == nil {
		defer protected.Close()
		if err := protected.Delete(&cgroupID); err == nil {
			return errors.New("namespaced hostile actor deleted host protected-cgroup state")
		}
		var disabled uint32
		if err := protected.Update(&cgroupID, &disabled, ebpf.UpdateAny); err == nil {
			return errors.New("namespaced hostile actor disabled host protected-cgroup state")
		}
	}

	if err := os.WriteFile(
		filepath.Join(escapeCgroup, "cgroup.procs"),
		[]byte(strconv.Itoa(os.Getpid())),
		0o600,
	); err == nil {
		return errors.New("namespaced hostile actor escaped the protected cgroup")
	}

	if fd, err := unix.Open("/proc/1/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		defer unix.Close(fd)
		if err := unix.Setns(fd, unix.CLONE_NEWNS); err == nil {
			return errors.New("namespaced hostile actor joined the host mount namespace")
		}
	}

	// The actor may be able to alter only its private mount view. That is not
	// host enforcement authority; the parent verifies host pins and activation
	// after this process exits.
	_ = unix.Unmount(bpffsRoot, unix.MNT_DETACH)
	return nil
}

func attemptHostileGuardDisable(bpffsRoot, escapeCgroup string, cgroupID uint64) error {
	for _, path := range []string{
		filepath.Join(bpffsRoot, "links", "aegis_tconn4"),
		filepath.Join(bpffsRoot, "links", "aegis_tconn6"),
		filepath.Join(bpffsRoot, "links", "aegis_fperm"),
		filepath.Join(bpffsRoot, "links", "aegis_fork"),
	} {
		if err := os.Remove(path); err == nil {
			return fmt.Errorf("hostile actor removed pinned enforcement link %s", path)
		}
	}

	mapPath := filepath.Join(bpffsRoot, "maps", "aegis_tcgroups")
	if protected, err := ebpf.LoadPinnedMap(mapPath, nil); err == nil {
		defer protected.Close()
		if err := protected.Delete(&cgroupID); err == nil {
			return errors.New("hostile actor deleted protected-cgroup state")
		}
		var disabled uint32
		if err := protected.Update(&cgroupID, &disabled, ebpf.UpdateAny); err == nil {
			return errors.New("hostile actor disabled protected-cgroup state")
		}
	}

	if err := os.WriteFile(
		filepath.Join(escapeCgroup, "cgroup.procs"),
		[]byte(strconv.Itoa(os.Getpid())),
		0o600,
	); err == nil {
		return errors.New("hostile actor escaped the protected cgroup")
	}

	if err := unix.Unmount(bpffsRoot, unix.MNT_DETACH); err == nil {
		return errors.New("hostile actor unmounted the enforcement bpffs")
	}
	return nil
}

func expectNativeDialDenied(address string) error {
	conn, err := net.DialTimeout("tcp4", address, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("tainted network connect unexpectedly succeeded")
	}
	return nil
}

func acceptNativeConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func waitForNativeTaintEvidence(reader *TaintEvidenceReader, cgroupID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sawSource, sawFork, sawFile, sawDeny bool
	for !(sawSource && sawFork && sawFile && sawDeny) {
		event, continuity, err := reader.ReadContext(ctx)
		if err != nil {
			return fmt.Errorf(
				"read native taint evidence (source=%t fork=%t file=%t deny=%t): %w",
				sawSource,
				sawFork,
				sawFile,
				sawDeny,
				err,
			)
		}
		if continuity.Status != EvidenceContinuityIntact {
			return fmt.Errorf("native taint evidence continuity degraded: %+v", continuity)
		}
		if event.CgroupID != cgroupID {
			continue
		}
		switch event.EventType {
		case TaintEventSourceRead:
			sawSource = event.Labels&1 != 0
		case TaintEventForkPropagation:
			sawFork = event.Labels&1 != 0
		case TaintEventPropagatedRead:
			sawFile = event.Labels&1 != 0
		case TaintEventEgressDeny:
			sawDeny = event.Labels&1 != 0
		}
	}
	return nil
}

func currentUnifiedCgroupPath() (string, error) {
	payload, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		relative := strings.TrimPrefix(line, "0::")
		if relative == "" {
			relative = "/"
		}
		return filepath.Join("/sys/fs/cgroup", filepath.Clean(relative)), nil
	}
	return "", errors.New("unified cgroup v2 membership not found")
}

func movePIDToCgroup(path string, pid int) error {
	return os.WriteFile(
		filepath.Join(path, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)),
		0o600,
	)
}

func removeNativeTaintPins(root string) {
	for _, name := range []string{"aegis_fperm", "aegis_fork", "aegis_tconn4", "aegis_tconn6"} {
		_ = os.Remove(filepath.Join(root, "links", name))
	}
	_ = os.RemoveAll(root)
}

func prepareNativeTaintKernel() error {
	if err := ensureNativeFilesystem("/sys/fs/bpf", "bpf", uint64(bpfFSMagic)); err != nil {
		return err
	}
	if err := ensureNativeFilesystem("/sys/kernel/security", "securityfs", 0x73636673); err != nil {
		return err
	}
	if err := ensureNativeFilesystem("/sys/fs/cgroup", "cgroup2", uint64(cgroup2FSMagic)); err != nil {
		return err
	}

	lsmPayload, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("read active LSM list: %w", err)
	}
	active := "," + strings.TrimSpace(string(lsmPayload)) + ","
	if !strings.Contains(active, ",bpf,") {
		return fmt.Errorf("BPF LSM is not active: %s", strings.TrimSpace(string(lsmPayload)))
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("kernel BTF is unavailable: %w", err)
	}
	return nil
}

func ensureNativeFilesystem(path, fsType string, magic uint64) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create %s mountpoint: %w", fsType, err)
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err == nil && uint64(stat.Type) == magic {
		return nil
	}
	source := fsType
	if fsType == "cgroup2" {
		source = "none"
	}
	if err := unix.Mount(source, path, fsType, 0, ""); err != nil {
		return fmt.Errorf("mount %s at %s: %w", fsType, path, err)
	}
	if err := unix.Statfs(path, &stat); err != nil {
		return fmt.Errorf("stat %s after mount: %w", fsType, err)
	}
	if uint64(stat.Type) != magic {
		return fmt.Errorf("%s mounted with unexpected filesystem magic %#x", fsType, uint64(stat.Type))
	}
	return nil
}

func assertNativeProcessTaint(bpffsRoot string, tgid uint32, want uint64) error {
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
		return fmt.Errorf("lookup tgid %d: %w", tgid, err)
	}
	if got&want != want {
		return fmt.Errorf("tgid %d labels=%#x want bits=%#x", tgid, got, want)
	}
	return nil
}

func assertNativeFileTaint(bpffsRoot string, key TaintFileKey, want uint64) error {
	m, err := openExactTaintMap(
		filepath.Join(bpffsRoot, "maps", "aegis_ftaint"),
		ebpf.Hash,
		16,
		8,
		65536,
	)
	if err != nil {
		return err
	}
	defer m.Close()
	var got uint64
	if err := m.Lookup(&key, &got); err != nil {
		return fmt.Errorf("lookup file device=%d inode=%d: %w", key.Device, key.Inode, err)
	}
	if got&want != want {
		return fmt.Errorf(
			"file device=%d inode=%d labels=%#x want bits=%#x",
			key.Device,
			key.Inode,
			got,
			want,
		)
	}
	return nil
}

func diagnoseNativeReadKeys(
	reader *TaintEvidenceReader,
	cgroupID uint64,
	tgid uint32,
	sources []TaintFileKey,
) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	observations := make([]string, 0, 8)
	for len(observations) < 32 {
		event, _, err := reader.ReadContext(ctx)
		if err != nil {
			if len(observations) == 0 {
				return "unavailable: " + err.Error()
			}
			break
		}
		if event.CgroupID != cgroupID ||
			event.TGID != tgid ||
			event.EventType != TaintEventFileReadObserved {
			continue
		}
		match := false
		for _, source := range sources {
			if event.FileDevice == source.Device && event.FileInode == source.Inode {
				match = true
				break
			}
		}
		observations = append(observations, fmt.Sprintf(
			"device=%d inode=%d labels=%#x source_match=%t",
			event.FileDevice,
			event.FileInode,
			event.Labels,
			match,
		))
		if match {
			break
		}
	}
	if len(observations) == 0 {
		return "none"
	}
	return strings.Join(observations, "; ")
}
