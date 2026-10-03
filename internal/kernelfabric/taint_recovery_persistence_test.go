package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistentRecoveryRecordIsEvidenceNotCrossBootAuthority(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootA := sha256.Sum256([]byte("persistent-boot-a"))
	bootB := sha256.Sum256([]byte("persistent-boot-b"))
	plan := sha256.Sum256([]byte("persistent-plan"))
	auth := sha256.Sum256([]byte("persistent-authorization"))
	now := time.Now().UTC()

	record := TaintRecoveryPersistenceRecord{
		Version:                 TaintRecoveryPersistenceVersion,
		RecordID:                "disk-record-a",
		BootIDHash:              fmt.Sprintf("sha256:%x", bootA[:]),
		PlanDigest:              fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:                7,
		EnrollmentEpoch:         8,
		DirtyGeneration:         3,
		CleanWatermark:          3,
		AuthorizationCommitment: fmt.Sprintf("sha256:%x", auth[:]),
		Outcome:                 TaintRecoveryPersistenceOutcomeCommitted,
		RecordedAt:              now,
	}
	signed, err := SignTaintRecoveryPersistenceRecord(record, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedTaintRecoveryPersistenceRecord(signed, publicKey); err != nil {
		t.Fatalf("signed persistent record rejected as historical evidence: %v", err)
	}
	if err := VerifySignedTaintRecoveryPersistenceRecordForBoot(signed, publicKey, record.BootIDHash); err != nil {
		t.Fatalf("same-boot persistent record rejected: %v", err)
	}

	err = VerifySignedTaintRecoveryPersistenceRecordForBoot(
		signed,
		publicKey,
		fmt.Sprintf("sha256:%x", bootB[:]),
	)
	if err == nil || !strings.Contains(err.Error(), "historical only") {
		t.Fatalf("boot-A disk record became Boot-B authority: %v", err)
	}

	path := filepath.Join(t.TempDir(), "recovery-record.json")
	if err := WriteSignedTaintRecoveryPersistenceRecordDurable(path, signed); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSignedTaintRecoveryPersistenceRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != signed {
		t.Fatalf("durable recovery record changed across write/load: got=%+v want=%+v", loaded, signed)
	}
}
