package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func testTaintRecoveryAuthorization(t *testing.T) (TaintRecoveryAuthorization, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	plan := TaintActivationPlan{
		CgroupPath:    "/sys/fs/cgroup/aegis",
		AllowedLabels: 0,
		Sources: []TaintSourceBinding{
			{
				Path:   "/var/lib/aegis/source",
				File:   TaintFileKey{Device: 8, Inode: 42},
				Labels: 1,
			},
		},
	}
	digest, err := TaintActivationPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 19, 0, 0, 0, time.UTC)
	return TaintRecoveryAuthorization{
		Version:         TaintRecoveryAuthorizationVersion,
		AuthorizationID: "recovery-epoch-1-to-2",
		PlanDigest:      digest,
		CgroupID:        42,
		BPFFSRoot:       "/sys/fs/bpf/aegis-ege/taint",
		BootIDHash:      "sha256:" + strings.Repeat("a", 64),
		FromEpoch:       1,
		ToEpoch:         2,
		ExpectedDirty:   1,
		NotBefore:       now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Minute),
	}, publicKey, privateKey
}

func TestTaintRecoveryAuthorizationRequiresMonotonicEpoch(t *testing.T) {
	auth, _, _ := testTaintRecoveryAuthorization(t)
	if err := ValidateTaintRecoveryAuthorization(auth); err != nil {
		t.Fatal(err)
	}

	bad := auth
	bad.ToEpoch = auth.FromEpoch
	if err := ValidateTaintRecoveryAuthorization(bad); err == nil {
		t.Fatal("non-advancing recovery epoch accepted")
	}

	bad = auth
	bad.ToEpoch = auth.FromEpoch + 2
	if err := ValidateTaintRecoveryAuthorization(bad); err == nil {
		t.Fatal("skipped recovery epoch accepted")
	}

	bad = auth
	bad.ExpectedDirty = 0
	if err := ValidateTaintRecoveryAuthorization(bad); err == nil {
		t.Fatal("clean-state recovery authorization accepted")
	}
}

func TestSignedTaintRecoveryAuthorizationBindsPlanDirtyAndEpoch(t *testing.T) {
	auth, publicKey, privateKey := testTaintRecoveryAuthorization(t)
	signed, err := SignTaintRecoveryAuthorization(auth, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	now := auth.NotBefore.Add(30 * time.Second)
	if err := VerifySignedTaintRecoveryAuthorization(signed, publicKey, now); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*SignedTaintRecoveryAuthorization){
		"plan": func(s *SignedTaintRecoveryAuthorization) {
			s.Authorization.PlanDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"dirty": func(s *SignedTaintRecoveryAuthorization) {
			s.Authorization.ExpectedDirty++
		},
		"epoch": func(s *SignedTaintRecoveryAuthorization) {
			s.Authorization.FromEpoch++
			s.Authorization.ToEpoch++
		},
		"cgroup": func(s *SignedTaintRecoveryAuthorization) {
			s.Authorization.CgroupID++
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			mutate(&tampered)
			if err := VerifySignedTaintRecoveryAuthorization(tampered, publicKey, now); err == nil {
				t.Fatal("tampered recovery authorization verified")
			}
		})
	}
}

func TestSignedTaintRecoveryAuthorizationExpires(t *testing.T) {
	auth, publicKey, privateKey := testTaintRecoveryAuthorization(t)
	signed, err := SignTaintRecoveryAuthorization(auth, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedTaintRecoveryAuthorization(
		signed,
		publicKey,
		auth.ExpiresAt,
	); err == nil {
		t.Fatal("expired recovery authorization verified")
	}
}
