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

func TestJointTaintRecoveryAuthorizationRequiresBothDistinctPrincipals(t *testing.T) {
	auth, authorityPublic, authorityPrivate := testTaintRecoveryAuthorization(t)
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignJointTaintRecoveryAuthorization(auth, authorityPrivate, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := auth.NotBefore.Add(30 * time.Second)
	if err := VerifyJointTaintRecoveryAuthorization(signed, authorityPublic, witnessPublic, now); err != nil {
		t.Fatalf("joint recovery authorization rejected: %v", err)
	}

	missingWitness := signed
	missingWitness.WitnessSignature = ""
	if err := VerifyJointTaintRecoveryAuthorization(missingWitness, authorityPublic, witnessPublic, now); err == nil {
		t.Fatal("authority-only recovery authorization verified")
	}

	if _, err := SignJointTaintRecoveryAuthorization(auth, authorityPrivate, authorityPrivate); err == nil {
		t.Fatal("same key accepted as both recovery principals")
	}
	if err := VerifyJointTaintRecoveryAuthorization(signed, authorityPublic, authorityPublic, now); err == nil {
		t.Fatal("same public key accepted for both recovery principals")
	}
}

func TestJointTaintRecoveryAuthorizationRejectsCrossPayloadWitnessAndKeySwap(t *testing.T) {
	auth, authorityPublic, authorityPrivate := testTaintRecoveryAuthorization(t)
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignJointTaintRecoveryAuthorization(auth, authorityPrivate, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}

	other := auth
	other.AuthorizationID = "different-recovery-authorization"
	other.ExpectedDirty++
	otherSigned, err := SignJointTaintRecoveryAuthorization(other, authorityPrivate, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	crossPayload := signed
	crossPayload.WitnessSignature = otherSigned.WitnessSignature
	if err := VerifyJointTaintRecoveryAuthorization(
		crossPayload,
		authorityPublic,
		witnessPublic,
		auth.NotBefore.Add(30*time.Second),
	); err == nil {
		t.Fatal("witness signature over a different recovery payload verified")
	}

	if err := VerifyJointTaintRecoveryAuthorization(
		signed,
		witnessPublic,
		authorityPublic,
		auth.NotBefore.Add(30*time.Second),
	); err == nil {
		t.Fatal("swapped recovery principals verified")
	}
}

func TestJointTaintRecoveryCommitmentBindsBothPrincipals(t *testing.T) {
	auth, _, authorityPrivate := testTaintRecoveryAuthorization(t)
	_, witnessPrivateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, witnessPrivateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := SignJointTaintRecoveryAuthorization(auth, authorityPrivate, witnessPrivateA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignJointTaintRecoveryAuthorization(auth, authorityPrivate, witnessPrivateB)
	if err != nil {
		t.Fatal(err)
	}
	digestA, err := JointTaintRecoveryCommitmentDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := JointTaintRecoveryCommitmentDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == digestB {
		t.Fatal("joint recovery commitment ignored witness identity/signature")
	}
}
