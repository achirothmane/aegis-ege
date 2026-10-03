package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRecoveryAuthorizationIsBoundToExactBoot(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootA := sha256.Sum256([]byte("boot-a"))
	bootB := sha256.Sum256([]byte("boot-b"))
	plan := sha256.Sum256([]byte("plan"))
	now := time.Now().UTC()

	auth := TaintRecoveryAuthorization{
		Version:         TaintRecoveryAuthorizationVersion,
		AuthorizationID: "boot-fence-unit",
		PlanDigest:      fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:        1,
		BPFFSRoot:       "/sys/fs/bpf/aegis-ege",
		BootIDHash:      fmt.Sprintf("sha256:%x", bootA[:]),
		FromEpoch:       1,
		ToEpoch:         2,
		ExpectedDirty:   1,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
	signed, err := SignTaintRecoveryAuthorization(auth, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifySignedTaintRecoveryAuthorizationForBoot(
		signed,
		publicKey,
		now,
		fmt.Sprintf("sha256:%x", bootA[:]),
	); err != nil {
		t.Fatalf("boot A authorization rejected on boot A: %v", err)
	}

	err = VerifySignedTaintRecoveryAuthorizationForBoot(
		signed,
		publicKey,
		now,
		fmt.Sprintf("sha256:%x", bootB[:]),
	)
	if err == nil {
		t.Fatal("boot A authorization was accepted on boot B")
	}
	if !strings.Contains(err.Error(), "boot identity mismatch") {
		t.Fatalf("unexpected boot mismatch error: %v", err)
	}
}
