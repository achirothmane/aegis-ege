//go:build linux && taintnative

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	taintNativeHelperEnv   = "AEGIS_TAINT_NATIVE_HELPER"
	taintNativeHelperMode  = "AEGIS_TAINT_NATIVE_HELPER_MODE"
	taintNativeHelperAddr  = "AEGIS_TAINT_NATIVE_HELPER_ADDR"
	taintNativeHelperBridge = "AEGIS_TAINT_NATIVE_HELPER_BRIDGE"
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
	default:
		t.Fatalf("unknown native helper mode %q", os.Getenv(taintNativeHelperMode))
	}
}

func TestNativeTaintReadForkFileAndEgress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native taint test requires root")
	}
	artifact := strings.TrimSpace(os.Getenv("AEGIS_TAINT_BPF_OBJECT"))
	if artifact == "" {
		t.Skip("AEGIS_TAINT_BPF_OBJECT is not set")
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

	workDir := t.TempDir()
	secretPath := filepath.Join(workDir, "secret.txt")
	bridgePath := filepath.Join(workDir, "bridge.txt")
	if err := os.WriteFile(secretPath, []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bridgePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sourceKey, err := ResolveTaintFileKey(secretPath)
	if err != nil {
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

	plan := TaintActivationPlan{
		CgroupPath:    cgroupPath,
		AllowedLabels: 0,
		Sources: []TaintSourceBinding{
			{File: sourceKey, Labels: 1},
		},
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
	if err := os.WriteFile(bridgePath, []byte("launder-attempt"), 0o600); err != nil {
		t.Fatalf("write bridge file: %v", err)
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
