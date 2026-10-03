//go:build linux && taintnative

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	taintRebootPhaseEnv = "AEGIS_TAINT_REBOOT_PHASE"
	taintRebootStateEnv = "AEGIS_TAINT_REBOOT_STATE"
)

type taintRebootProofState struct {
	BootIDHash       string                           `json:"boot_id_hash"`
	PublicKey        string                           `json:"public_key"`
	PrivateKey       string                           `json:"private_key"`
	Signed           SignedTaintRecoveryAuthorization `json:"signed"`
	BootBIDHash      string                           `json:"boot_b_id_hash,omitempty"`
	BootBSigned      SignedTaintRecoveryAuthorization `json:"boot_b_signed,omitempty"`
	HistoryPublicKey string                           `json:"history_public_key"`
	HistoryPrivateKey string                          `json:"history_private_key"`
	HistoryDigest    string                           `json:"history_digest,omitempty"`
}

type freshBootBProofResult struct {
	PlanDigest       string
	CgroupID         uint64
	EnrollmentEpoch  uint64
	DirtyGeneration  uint64
	CleanGeneration  uint64
}

// TestNativeTaintHostRebootBoundary is intentionally executed three times by
// CI in separate vimto VM invocations. Each invocation boots a new Linux kernel.
//
// Phase "before" pins real kernel state in bpffs and emits an authorization
// bound to boot A. Phase "after" boots B, proves trust reset, performs fresh
// source enrollment and real effect-boundary checks, then persists a signed
// historical receipt to an external fsync-backed store. Phase "history" boots
// C and proves that the receipt remains verifiable as history while all Boot-B
// effect authority is stale and denied.
func TestNativeTaintHostRebootBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("host reboot boundary proof requires root in the disposable VM")
	}
	statePath := strings.TrimSpace(os.Getenv(taintRebootStateEnv))
	if statePath == "" {
		t.Fatal("AEGIS_TAINT_REBOOT_STATE is required")
	}
	if err := ensureNativeBPFFSMounted(); err != nil {
		t.Fatalf("prepare bpffs: %v", err)
	}

	const proofRoot = "/sys/fs/bpf/aegis-ege-reboot-proof"
	switch os.Getenv(taintRebootPhaseEnv) {
	case "before":
		runTaintRebootBefore(t, proofRoot, statePath)
	case "after":
		runTaintRebootAfter(t, proofRoot, statePath)
	case "history":
		runTaintRebootHistory(t, proofRoot, statePath)
	default:
		t.Fatalf("unknown reboot proof phase %q", os.Getenv(taintRebootPhaseEnv))
	}
}

func runTaintRebootBefore(t *testing.T, proofRoot, statePath string) {
	t.Helper()
	if err := os.RemoveAll(proofRoot); err != nil {
		t.Fatalf("clear reboot proof root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(proofRoot, "maps"), 0o755); err != nil {
		t.Fatalf("create reboot proof bpffs root: %v", err)
	}

	host, err := (LinuxBootstrapHostProvider{}).Snapshot(proofRoot)
	if err != nil {
		t.Fatalf("capture boot A identity: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recovery authority key: %v", err)
	}
	historyPublicKey, historyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recovery history key: %v", err)
	}
	if err := os.RemoveAll(statePath + ".history"); err != nil {
		t.Fatalf("clear durable recovery history: %v", err)
	}
	planHash := sha256.Sum256([]byte("aegis-ege/host-reboot-proof-plan/v1"))
	now := time.Now().UTC()
	auth := TaintRecoveryAuthorization{
		Version:         TaintRecoveryAuthorizationVersion,
		AuthorizationID: "host-reboot-proof-boot-a",
		PlanDigest:      fmt.Sprintf("sha256:%x", planHash[:]),
		CgroupID:        1,
		BPFFSRoot:       proofRoot,
		BootIDHash:      host.BootIDHash,
		FromEpoch:       7,
		ToEpoch:         8,
		ExpectedDirty:   3,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
	signed, err := SignTaintRecoveryAuthorization(auth, privateKey)
	if err != nil {
		t.Fatalf("sign boot A recovery authorization: %v", err)
	}
	if err := VerifySignedTaintRecoveryAuthorizationForBoot(signed, publicKey, now, host.BootIDHash); err != nil {
		t.Fatalf("boot A authorization did not verify on boot A: %v", err)
	}

	commitment, err := TaintRecoveryCommitmentDigest(signed)
	if err != nil {
		t.Fatalf("digest boot A recovery commitment: %v", err)
	}
	pinned, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "aegis_reboot_proof",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  32,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create reboot proof kernel map: %v", err)
	}
	defer pinned.Close()
	var key uint32
	if err := pinned.Update(&key, &commitment, ebpf.UpdateAny); err != nil {
		t.Fatalf("write reboot proof commitment: %v", err)
	}
	pinPath := filepath.Join(proofRoot, "maps", "aegis_trecover")
	if err := pinned.Pin(pinPath); err != nil {
		t.Fatalf("pin reboot proof commitment: %v", err)
	}
	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("boot A pin is not observable before reboot boundary: %v", err)
	}

	state := taintRebootProofState{
		BootIDHash:        host.BootIDHash,
		PublicKey:         base64.StdEncoding.EncodeToString(publicKey),
		PrivateKey:        base64.StdEncoding.EncodeToString(privateKey),
		Signed:            signed,
		HistoryPublicKey:  base64.StdEncoding.EncodeToString(historyPublicKey),
		HistoryPrivateKey: base64.StdEncoding.EncodeToString(historyPrivateKey),
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("encode reboot proof state: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatalf("create reboot proof state directory: %v", err)
	}
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("persist reboot proof handoff state: %v", err)
	}

	t.Logf("boot A established: boot=%s pinned=%s", host.BootIDHash, pinPath)
}

func runTaintRebootAfter(t *testing.T, proofRoot, statePath string) {
	t.Helper()
	payload, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read boot A handoff state: %v", err)
	}
	var state taintRebootProofState
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatalf("decode boot A handoff state: %v", err)
	}

	host, err := (LinuxBootstrapHostProvider{}).Snapshot(proofRoot)
	if err != nil {
		t.Fatalf("capture boot B identity: %v", err)
	}
	if host.BootIDHash == state.BootIDHash {
		t.Fatalf("second VM boot reused boot identity: %s", host.BootIDHash)
	}

	// The map was pinned in boot A's bpffs. A new kernel must not inherit it.
	pinPath := filepath.Join(proofRoot, "maps", "aegis_trecover")
	if _, err := os.Stat(pinPath); err == nil {
		t.Fatalf("boot B resurrected boot A kernel pin at %s", pinPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect boot B recovery pin: %v", err)
	}

	publicBytes, err := base64.StdEncoding.DecodeString(state.PublicKey)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		t.Fatalf("decode recovery public key: %v", err)
	}
	publicKey := ed25519.PublicKey(publicBytes)
	now := time.Now().UTC()
	err = VerifySignedTaintRecoveryAuthorizationForBoot(state.Signed, publicKey, now, host.BootIDHash)
	if err == nil {
		t.Fatal("boot A recovery authorization was accepted on boot B")
	}
	if !strings.Contains(err.Error(), "boot identity mismatch") {
		t.Fatalf("stale boot authorization failed for unexpected reason: %v", err)
	}

	privateBytes, err := base64.StdEncoding.DecodeString(state.PrivateKey)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		t.Fatalf("decode recovery private key: %v", err)
	}
	freshAuth := state.Signed.Authorization
	freshAuth.AuthorizationID = "host-reboot-proof-boot-b"
	freshAuth.BootIDHash = host.BootIDHash
	freshAuth.NotBefore = now.Add(-time.Minute)
	freshAuth.ExpiresAt = now.Add(time.Hour)
	freshSigned, err := SignTaintRecoveryAuthorization(freshAuth, ed25519.PrivateKey(privateBytes))
	if err != nil {
		t.Fatalf("sign boot B recovery authorization: %v", err)
	}
	if err := VerifySignedTaintRecoveryAuthorizationForBoot(freshSigned, publicKey, now, host.BootIDHash); err != nil {
		t.Fatalf("fresh boot B authorization did not verify: %v", err)
	}

	proof := proveFreshBootBEnrollmentAndEffect(t, host.BootIDHash)

	historyPublicBytes, err := base64.StdEncoding.DecodeString(state.HistoryPublicKey)
	if err != nil || len(historyPublicBytes) != ed25519.PublicKeySize {
		t.Fatalf("decode recovery history public key: %v", err)
	}
	historyPrivateBytes, err := base64.StdEncoding.DecodeString(state.HistoryPrivateKey)
	if err != nil || len(historyPrivateBytes) != ed25519.PrivateKeySize {
		t.Fatalf("decode recovery history private key: %v", err)
	}
	historyReceipt := TaintRecoveryHistoryReceipt{
		Version:             TaintRecoveryHistoryReceiptVersion,
		ReceiptID:           "host-reboot-proof-boot-b",
		Event:               TaintRecoveryHistoryEventReenrolled,
		BootIDHash:          host.BootIDHash,
		PlanDigest:          proof.PlanDigest,
		CgroupID:            proof.CgroupID,
		EnrollmentEpoch:     proof.EnrollmentEpoch,
		DirtyGeneration:     proof.DirtyGeneration,
		CleanGeneration:     proof.CleanGeneration,
		CleanEffectAllowed:  true,
		TaintedEffectDenied: true,
		RecordedAt:          time.Now().UTC(),
	}
	signedHistory, err := SignTaintRecoveryHistoryReceipt(
		historyReceipt,
		ed25519.PrivateKey(historyPrivateBytes),
	)
	if err != nil {
		t.Fatalf("sign durable recovery history: %v", err)
	}
	historyStore := TaintRecoveryHistoryStore{Dir: statePath + ".history"}
	historyDigest, err := historyStore.Append(
		signedHistory,
		ed25519.PublicKey(historyPublicBytes),
	)
	if err != nil {
		t.Fatalf("persist durable recovery history: %v", err)
	}

	state.BootBIDHash = host.BootIDHash
	state.BootBSigned = freshSigned
	state.HistoryDigest = historyDigest
	payload, err = json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("encode boot B handoff state: %v", err)
	}
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("persist boot B handoff state: %v", err)
	}

	t.Logf(
		"reboot trust reset proved: bootA=%s bootB=%s stale_authority=DENY old_kernel_pin=ABSENT fresh_boot_authority=ACCEPT",
		state.BootIDHash,
		host.BootIDHash,
	)
}

func runTaintRebootHistory(t *testing.T, proofRoot, statePath string) {
	t.Helper()
	payload, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read boot history handoff state: %v", err)
	}
	var state taintRebootProofState
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatalf("decode boot history handoff state: %v", err)
	}
	if state.BootBIDHash == "" || state.HistoryDigest == "" {
		t.Fatal("boot B did not persist durable history metadata")
	}

	host, err := (LinuxBootstrapHostProvider{}).Snapshot(proofRoot)
	if err != nil {
		t.Fatalf("capture boot C identity: %v", err)
	}
	if host.BootIDHash == state.BootIDHash || host.BootIDHash == state.BootBIDHash {
		t.Fatalf("boot C reused prior boot identity: %s", host.BootIDHash)
	}

	historyPublicBytes, err := base64.StdEncoding.DecodeString(state.HistoryPublicKey)
	if err != nil || len(historyPublicBytes) != ed25519.PublicKeySize {
		t.Fatalf("decode recovery history public key: %v", err)
	}
	historyStore := TaintRecoveryHistoryStore{Dir: statePath + ".history"}
	historical, digest, exists, err := historyStore.Current(ed25519.PublicKey(historyPublicBytes))
	if err != nil {
		t.Fatalf("verify durable recovery history on boot C: %v", err)
	}
	if !exists || digest != state.HistoryDigest {
		t.Fatalf("durable history head mismatch: exists=%v got=%s want=%s", exists, digest, state.HistoryDigest)
	}
	if historical.Receipt.BootIDHash != state.BootBIDHash ||
		historical.Receipt.Event != TaintRecoveryHistoryEventReenrolled {
		t.Fatalf("unexpected durable history receipt: %+v", historical.Receipt)
	}

	publicBytes, err := base64.StdEncoding.DecodeString(state.PublicKey)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		t.Fatalf("decode recovery public key: %v", err)
	}
	err = VerifySignedTaintRecoveryAuthorizationForBoot(
		state.BootBSigned,
		ed25519.PublicKey(publicBytes),
		time.Now().UTC(),
		host.BootIDHash,
	)
	if err == nil {
		t.Fatal("boot B effect authority was accepted on boot C")
	}
	if !strings.Contains(err.Error(), "boot identity mismatch") {
		t.Fatalf("boot B authority failed on boot C for unexpected reason: %v", err)
	}

	t.Logf(
		"durable recovery truth survived reboot: bootB=%s bootC=%s history=%s historical_truth=VERIFIED boot_b_authority=DENY",
		state.BootBIDHash,
		host.BootIDHash,
		digest,
	)
}

func proveFreshBootBEnrollmentAndEffect(t *testing.T, bootBIDHash string) freshBootBProofResult {
	t.Helper()
	if len(nativeTaintBPFObject) == 0 {
		t.Fatal("embedded native taint BPF object is empty")
	}
	if err := prepareNativeTaintKernel(); err != nil {
		t.Fatalf("prepare boot B native taint kernel: %v", err)
	}

	originalCgroup, err := currentUnifiedCgroupPath()
	if err != nil {
		t.Fatal(err)
	}
	testID := fmt.Sprintf("aegis-taint-reboot-b-%d", os.Getpid())
	cgroupPath := filepath.Join("/sys/fs/cgroup", testID)
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create boot B cgroup: %v", err)
	}
	defer func() {
		_ = movePIDToCgroup(originalCgroup, os.Getpid())
		_ = os.Remove(cgroupPath)
	}()

	bpffsRoot := filepath.Join("/sys/fs/bpf", testID)
	if err := os.MkdirAll(bpffsRoot, 0o755); err != nil {
		t.Fatalf("create boot B bpffs root: %v", err)
	}
	defer removeNativeTaintPins(bpffsRoot)

	sourceRoot := filepath.Join(t.TempDir(), "boot-b-source")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatalf("create boot B source mountpoint: %v", err)
	}
	if err := unix.Mount("aegis-reboot-b-source", sourceRoot, "tmpfs", 0, "mode=0700,size=4m"); err != nil {
		t.Fatalf("mount boot B source tmpfs: %v", err)
	}
	defer func() {
		if err := unix.Unmount(sourceRoot, unix.MNT_DETACH); err != nil {
			t.Logf("unmount boot B source tmpfs: %v", err)
		}
	}()

	sourcePath := filepath.Join(sourceRoot, "secret.txt")
	if err := os.WriteFile(sourcePath, []byte("fresh-boot-b-source"), 0o600); err != nil {
		t.Fatalf("write boot B source: %v", err)
	}

	artifact := filepath.Join(t.TempDir(), "aegis_taint.bpf.o")
	if err := os.WriteFile(artifact, nativeTaintBPFObject, 0o600); err != nil {
		t.Fatalf("materialize boot B taint artifact: %v", err)
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

	loaded, err := (TaintBootstrapLoader{}).LoadAndAttach(
		context.Background(),
		TaintBootstrapLoadRequest{
			ArtifactPath:          artifact,
			CgroupPath:            cgroupPath,
			BPFFSRoot:             bpffsRoot,
			SignedManifest:        signedManifest,
			Trust:                 BootstrapTrustStore{releaseKeyID: releasePublic},
			AttestationPrivateKey: attestationPrivate,
			Now:                   now,
		},
	)
	if err != nil {
		t.Fatalf("load fresh boot B taint substrate: %v", err)
	}
	if loaded.SignedReceipt.Receipt.Host.BootIDHash != bootBIDHash {
		t.Fatalf(
			"fresh boot B bootstrap receipt bound to wrong boot: got=%s want=%s",
			loaded.SignedReceipt.Receipt.Host.BootIDHash,
			bootBIDHash,
		)
	}

	sourceKeys, err := ResolveTaintFileKeysObserved(bpffsRoot, sourcePath)
	if err != nil {
		t.Fatalf("kernel-observe fresh boot B source: %v", err)
	}
	if len(sourceKeys) == 0 {
		t.Fatal("fresh boot B source probe returned no kernel identities")
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

	planDigest, err := TaintActivationPlanDigest(plan)
	if err != nil {
		t.Fatalf("digest fresh boot B plan: %v", err)
	}

	activated, err := ActivateTaintCgroup(TaintActivationRequest{
		BPFFSRoot:                     bpffsRoot,
		Plan:                          plan,
		SignedBootstrapReceipt:        loaded.SignedReceipt,
		BootstrapAttestationPublicKey: attestationPublic,
	})
	if err != nil {
		t.Fatalf("activate fresh boot B taint cgroup: %v", err)
	}
	if activated.EnrollmentEpoch != 1 {
		t.Fatalf("fresh boot B did not start a new enrollment epoch: %d", activated.EnrollmentEpoch)
	}
	active, err := TaintCgroupActivationState(bpffsRoot, activated.CgroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("fresh boot B cgroup is not protected after activation")
	}
	dirty, err := TaintSourceIdentityDirtyState(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := TaintSourceContinuityWatermark(bpffsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if dirty != 0 || clean != 0 {
		t.Fatalf("fresh boot B continuity is not clean: dirty=%d clean=%d", dirty, clean)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go acceptNativeConnections(listener)

	if err := movePIDToCgroup(cgroupPath, os.Getpid()); err != nil {
		t.Fatalf("move fresh boot B workload into protected cgroup: %v", err)
	}
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("fresh boot B clean effect unexpectedly denied: %v", err)
	}
	_ = conn.Close()

	if _, err := os.ReadFile(sourcePath); err != nil {
		t.Fatalf("read fresh boot B enrolled source: %v", err)
	}
	if err := expectNativeDialDenied(listener.Addr().String()); err != nil {
		t.Fatalf("fresh boot B tainted effect unexpectedly allowed: %v", err)
	}

	t.Logf(
		"fresh boot B authority restored from new evidence: boot=%s sources=%v epoch=%d clean_effect=ALLOW tainted_effect=DENY",
		bootBIDHash,
		sourceKeys,
		activated.EnrollmentEpoch,
	)
	return freshBootBProofResult{
		PlanDigest:      planDigest,
		CgroupID:        activated.CgroupID,
		EnrollmentEpoch: activated.EnrollmentEpoch,
		DirtyGeneration: dirty,
		CleanGeneration: clean,
	}
}

func ensureNativeBPFFSMounted() error {
	const root = "/sys/fs/bpf"
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err == nil && uint64(fs.Type) == uint64(bpfFSMagic) {
		return nil
	}
	if err := unix.Mount("bpf", root, "bpf", 0, ""); err != nil {
		return err
	}
	if err := unix.Statfs(root, &fs); err != nil {
		return err
	}
	if uint64(fs.Type) != uint64(bpfFSMagic) {
		return fmt.Errorf("%s is not bpffs after mount", root)
	}
	return nil
}
