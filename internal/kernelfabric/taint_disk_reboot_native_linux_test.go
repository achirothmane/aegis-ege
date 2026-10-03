//go:build linux && taintnative

package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const (
	taintDiskRebootPhaseEnv = "AEGIS_TAINT_DISK_REBOOT_PHASE"
	taintDiskRebootStateEnv = "AEGIS_TAINT_DISK_REBOOT_STATE"
	taintDiskRebootKeyEnv   = "AEGIS_TAINT_DISK_REBOOT_KEY"
)

func TestNativeTaintDiskBackedRebootBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disk-backed reboot boundary proof requires root in disposable VM")
	}
	recordPath := strings.TrimSpace(os.Getenv(taintDiskRebootStateEnv))
	keyPath := strings.TrimSpace(os.Getenv(taintDiskRebootKeyEnv))
	if recordPath == "" || keyPath == "" {
		t.Fatal("disk reboot record and key paths are required")
	}
	if err := ensureNativeBPFFSMounted(); err != nil {
		t.Fatalf("prepare bpffs: %v", err)
	}

	const proofRoot = "/sys/fs/bpf/aegis-ege-disk-reboot-proof"
	switch os.Getenv(taintDiskRebootPhaseEnv) {
	case "before":
		runTaintDiskRebootBefore(t, proofRoot, recordPath, keyPath)
	case "after":
		runTaintDiskRebootAfter(t, proofRoot, recordPath, keyPath)
	default:
		t.Fatalf("unknown disk reboot phase %q", os.Getenv(taintDiskRebootPhaseEnv))
	}
}

func runTaintDiskRebootBefore(t *testing.T, proofRoot, recordPath, keyPath string) {
	t.Helper()
	if err := os.RemoveAll(proofRoot); err != nil {
		t.Fatalf("clear disk reboot proof root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(proofRoot, "maps"), 0o755); err != nil {
		t.Fatalf("create disk reboot bpffs root: %v", err)
	}
	host, err := (LinuxBootstrapHostProvider{}).Snapshot(proofRoot)
	if err != nil {
		t.Fatalf("capture boot A identity: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	planHash := sha256.Sum256([]byte("aegis-ege/disk-reboot-plan/v1"))
	now := time.Now().UTC()
	auth := TaintRecoveryAuthorization{
		Version:         TaintRecoveryAuthorizationVersion,
		AuthorizationID: "disk-reboot-boot-a",
		PlanDigest:      fmt.Sprintf("sha256:%x", planHash[:]),
		CgroupID:        11,
		BPFFSRoot:       proofRoot,
		BootIDHash:      host.BootIDHash,
		FromEpoch:       7,
		ToEpoch:         8,
		ExpectedDirty:   3,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
	signedAuth, err := SignTaintRecoveryAuthorization(auth, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := TaintRecoveryCommitmentDigest(signedAuth)
	if err != nil {
		t.Fatal(err)
	}

	record := TaintRecoveryPersistenceRecord{
		Version:                 TaintRecoveryPersistenceVersion,
		RecordID:                "disk-reboot-recovery-committed-a",
		BootIDHash:              host.BootIDHash,
		PlanDigest:              auth.PlanDigest,
		CgroupID:                auth.CgroupID,
		EnrollmentEpoch:         auth.ToEpoch,
		DirtyGeneration:         auth.ExpectedDirty,
		CleanWatermark:          auth.ExpectedDirty,
		AuthorizationCommitment: TaintRecoveryCommitmentHex(commitment),
		Outcome:                 TaintRecoveryPersistenceOutcomeCommitted,
		RecordedAt:              now,
	}
	signedRecord, err := SignTaintRecoveryPersistenceRecord(record, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedTaintRecoveryPersistenceRecordForBoot(
		signedRecord,
		publicKey,
		host.BootIDHash,
	); err != nil {
		t.Fatalf("boot A durable record rejected on boot A: %v", err)
	}
	if err := WriteSignedTaintRecoveryPersistenceRecordDurable(recordPath, signedRecord); err != nil {
		t.Fatalf("persist signed recovery record: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o600); err != nil {
		t.Fatalf("persist test recovery public key: %v", err)
	}

	pinned, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "aegis_disk_reboot",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  32,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create disk reboot kernel map: %v", err)
	}
	defer pinned.Close()
	var zero uint32
	if err := pinned.Update(&zero, &commitment, ebpf.UpdateAny); err != nil {
		t.Fatalf("write disk reboot kernel commitment: %v", err)
	}
	pinPath := filepath.Join(proofRoot, "maps", "aegis_trecover")
	if err := pinned.Pin(pinPath); err != nil {
		t.Fatalf("pin disk reboot kernel commitment: %v", err)
	}

	t.Logf(
		"boot A durable recovery committed: boot=%s epoch=%d dirty=%d clean=%d record=%s pin=%s",
		host.BootIDHash,
		record.EnrollmentEpoch,
		record.DirtyGeneration,
		record.CleanWatermark,
		recordPath,
		pinPath,
	)
}

func runTaintDiskRebootAfter(t *testing.T, proofRoot, recordPath, keyPath string) {
	t.Helper()
	signedRecord, err := LoadSignedTaintRecoveryPersistenceRecord(recordPath)
	if err != nil {
		t.Fatalf("load durable boot A recovery record: %v", err)
	}
	keyPayload, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read test recovery public key: %v", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyPayload)))
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		t.Fatalf("decode test recovery public key: %v", err)
	}
	publicKey := ed25519.PublicKey(keyBytes)

	if err := VerifySignedTaintRecoveryPersistenceRecord(signedRecord, publicKey); err != nil {
		t.Fatalf("boot A durable record lost historical integrity: %v", err)
	}

	host, err := (LinuxBootstrapHostProvider{}).Snapshot(proofRoot)
	if err != nil {
		t.Fatalf("capture boot B identity: %v", err)
	}
	if host.BootIDHash == signedRecord.Record.BootIDHash {
		t.Fatalf("second VM boot reused boot identity: %s", host.BootIDHash)
	}

	err = VerifySignedTaintRecoveryPersistenceRecordForBoot(
		signedRecord,
		publicKey,
		host.BootIDHash,
	)
	if err == nil {
		t.Fatal("disk-backed Boot-A recovery record became authority on Boot B")
	}
	if !strings.Contains(err.Error(), "historical only") {
		t.Fatalf("stale durable record failed for unexpected reason: %v", err)
	}

	pinPath := filepath.Join(proofRoot, "maps", "aegis_trecover")
	if _, err := os.Stat(pinPath); err == nil {
		t.Fatalf("Boot B resurrected Boot-A kernel state at %s", pinPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect Boot-B kernel recovery pin: %v", err)
	}

	proveFreshBootBEnrollmentAndEffect(t, host.BootIDHash)

	t.Logf(
		"disk-backed reboot boundary proved: old_record=HISTORICAL_ONLY bootA=%s bootB=%s old_kernel_state=ABSENT fresh_boot_enrollment=REQUIRED",
		signedRecord.Record.BootIDHash,
		host.BootIDHash,
	)
}
