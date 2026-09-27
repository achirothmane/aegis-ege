package kernelfabric

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func remoteTestReceipt(t *testing.T, artifactDigest string, attestor ed25519.PrivateKey) SignedBootstrapReceipt {
	t.Helper()
	receipt := BootstrapReceipt{
		Version:             BootstrapReceiptVersion,
		ManifestDigest:      "sha256:" + strings.Repeat("a", 64),
		ManifestSignerKeyID: "ed25519:release",
		ArtifactSHA256:      artifactDigest,
		ArtifactSize:        123,
		Host: BootstrapHostSnapshot{
			BootIDHash:    "sha256:" + strings.Repeat("b", 64),
			KernelRelease: "6.18-test",
			LockdownMode:  "integrity",
			BPFFSRoot:     "/sys/fs/bpf/aegis-ege",
		},
		CgroupPath: "/sys/fs/cgroup/workload",
		Programs: []PinnedProgramAttestation{{
			PinName:    "aegis_connect4",
			ID:         11,
			Name:       "aegis_connect4",
			Type:       "cgroup_sock_addr",
			Tag:        "0123456789abcdef",
			AttachType: "connect4",
		}},
		Maps: []PinnedMapAttestation{{
			Name:       "aegis_capsules",
			ID:         22,
			Type:       "hash",
			KeySize:    40,
			ValueSize:  240,
			MaxEntries: 16384,
		}},
		CompletedAt: time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC),
	}
	signed, err := SignBootstrapReceipt(receipt, attestor)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestReplayIMASHA256PCR10(t *testing.T) {
	d1 := strings.Repeat("11", 32)
	d2 := strings.Repeat("22", 32)
	log := []byte(
		"10 " + d1 + " ima-ng sha256:" + strings.Repeat("aa", 32) + " /usr/bin/one\n" +
			"10 " + d2 + " ima-ng sha256:" + strings.Repeat("bb", 32) + " /usr/bin/two\n",
	)
	got, err := ReplayIMASHA256PCR10(log)
	if err != nil {
		t.Fatal(err)
	}

	pcr := make([]byte, sha256.Size)
	for _, raw := range []string{d1, d2} {
		digest, _ := hex.DecodeString(raw)
		h := sha256.New()
		h.Write(pcr)
		h.Write(digest)
		pcr = h.Sum(nil)
	}
	if string(got) != string(pcr) {
		t.Fatalf("PCR replay mismatch: got=%x want=%x", got, pcr)
	}
}

func TestIMAMeasurementContainsDigest(t *testing.T) {
	want := "sha256:" + strings.Repeat("ab", 32)
	log := []byte("10 " + strings.Repeat("11", 32) + " ima-ng " + want + " /tmp/aegis_connect.bpf.o\n")
	if !IMAMeasurementContainsDigest(log, want) {
		t.Fatal("expected BPF artifact digest to be found")
	}
	if IMAMeasurementContainsDigest(log, "sha256:"+strings.Repeat("cd", 32)) {
		t.Fatal("unexpected digest match")
	}
}

func TestRemoteQuoteNonceBindsReceiptAndLogs(t *testing.T) {
	_, attestor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewRemoteAttestationChallenge(
		"device-1",
		time.Minute,
		time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt := remoteTestReceipt(t, "sha256:"+strings.Repeat("c", 64), attestor)
	ima := []byte("ima")
	events := []byte("events")

	base, err := RemoteQuoteNonce(challenge, receipt, ima, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != RemoteQuoteNonceSize {
		t.Fatalf("nonce length=%d want=%d", len(base), RemoteQuoteNonceSize)
	}

	changedIMA, _ := RemoteQuoteNonce(challenge, receipt, []byte("ima2"), events)
	if string(base) == string(changedIMA) {
		t.Fatal("nonce did not bind IMA log")
	}
	changedEvents, _ := RemoteQuoteNonce(challenge, receipt, ima, []byte("events2"))
	if string(base) == string(changedEvents) {
		t.Fatal("nonce did not bind platform event log")
	}

	receipt2 := receipt
	receipt2.Receipt.CgroupPath = "/sys/fs/cgroup/other"
	changedReceipt, err := RemoteQuoteNonce(challenge, receipt2, ima, events)
	if err != nil {
		t.Fatal(err)
	}
	if string(base) == string(changedReceipt) {
		t.Fatal("nonce did not bind bootstrap receipt")
	}
}

func TestRemoteChallengeExpires(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	challenge, err := NewRemoteAttestationChallenge("device-1", time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRemoteChallenge(challenge, now.Add(2*time.Second)); !errors.Is(err, ErrRemoteChallengeExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestEKTrustAllowlist(t *testing.T) {
	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ek.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fp := "sha256:" + hex.EncodeToString(sum[:])
	req := TPMEnrollmentRequest{EKPublicDER: der}
	if err := verifyEKTrust(
		req,
		&ek.PublicKey,
		fp,
		TPMEnrollmentTrustPolicy{AllowedEKSPKI: map[string]struct{}{fp: {}}},
	); err != nil {
		t.Fatalf("allowlisted EK rejected: %v", err)
	}
}

func TestCompleteEnrollmentRejectsWrongSecret(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	pending := PendingTPMEnrollment{
		Request: TPMEnrollmentRequest{
			DeviceID: "device-1",
			BootstrapAttestorPublicKey: make([]byte, ed25519.PublicKeySize),
		},
		Challenge: TPMEnrollmentChallenge{
			EnrollmentID: "enroll-1",
			DeviceID:     "device-1",
			ExpiresAt:    now.Add(time.Minute),
		},
		ExpectedSecret: []byte("correct"),
		EKSPKISHA256:  "sha256:" + strings.Repeat("a", 64),
	}
	_, err := CompleteTPMEnrollment(pending, TPMEnrollmentProof{
		Version:      TPMEnrollmentProofVersion,
		EnrollmentID: "enroll-1",
		DeviceID:     "device-1",
		Secret:       []byte("wrong"),
	}, now)
	if !errors.Is(err, ErrEnrollmentActivationFailed) {
		t.Fatalf("expected activation failure, got %v", err)
	}
}

func TestSignedRemoteAttestationDecision(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decision := RemoteAttestationDecision{
		Version:         RemoteAttestationDecisionVersion,
		DecisionID:      "decision-1",
		ChallengeID:     "challenge-1",
		DeviceID:        "device-1",
		Decision:        "ALLOW",
		BootstrapDigest: "sha256:" + strings.Repeat("a", 64),
		AKPublicSHA256:  "sha256:" + strings.Repeat("b", 64),
		VerifiedAt:      time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC),
	}
	signed, err := signRemoteDecision(decision, RemoteAttestationPolicy{
		VerifierKey: priv,
		VerifierID:  "verifier-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedRemoteAttestationDecision(signed, pub); err != nil {
		t.Fatalf("signed decision rejected: %v", err)
	}
	signed.Decision.Decision = "BLOCK"
	if err := VerifySignedRemoteAttestationDecision(signed, pub); !errors.Is(err, ErrBootstrapSignatureInvalid) {
		t.Fatalf("tampered decision was not rejected: %v", err)
	}
}

func TestWirePCRsRequiresCompleteSelection(t *testing.T) {
	challenge := RemoteAttestationChallenge{
		PCRBank: "sha256",
		PCRs:    []int{0, 10},
	}
	in := []AttestedPCR{{
		Index:  0,
		Bank:   "sha256",
		Digest: make([]byte, sha256.Size),
	}}
	if _, err := wirePCRsToAttest(in, challenge); err == nil {
		t.Fatal("expected incomplete PCR selection to fail")
	}
}

var _ = crypto.SHA256


func TestTPMEnrollmentRequestDigestBindsBootstrapAttestor(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	req := TPMEnrollmentRequest{
		Version:                    TPMEnrollmentRequestVersion,
		DeviceID:                   "device-1",
		EKPublicDER:                []byte("ek"),
		BootstrapAttestorPublicKey: bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize),
		CreatedAt:                  now,
	}
	first, err := TPMEnrollmentRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	req.BootstrapAttestorPublicKey = bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize)
	second, err := TPMEnrollmentRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("enrollment request digest did not bind bootstrap attestor key")
	}
}

func TestRemoteChallengeConsumptionAllowsExactlyOneWinner(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	challenge, err := NewRemoteAttestationChallenge("device-1", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- ConsumeRemoteAttestationChallenge(dir, challenge, now.Add(time.Second))
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRemoteChallengeReplay):
			replays++
		default:
			t.Fatalf("unexpected consumption error: %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("expected one consumer and one replay rejection, got success=%d replay=%d", successes, replays)
	}
}

func TestRemoteChallengeConsumptionRejectsExpiredChallenge(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	challenge, err := NewRemoteAttestationChallenge("device-1", time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	err = ConsumeRemoteAttestationChallenge(t.TempDir(), challenge, now.Add(2*time.Second))
	if !errors.Is(err, ErrRemoteChallengeExpired) {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}


func TestEnrollmentChallengeRejectsTamperedBootstrapAttestorRequest(t *testing.T) {
	now := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)
	req := TPMEnrollmentRequest{
		Version:                    TPMEnrollmentRequestVersion,
		DeviceID:                   "device-1",
		BootstrapAttestorPublicKey: bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize),
		CreatedAt:                  now,
	}
	digest, err := TPMEnrollmentRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	challenge := TPMEnrollmentChallenge{
		Version:                 TPMEnrollmentChallengeVersion,
		EnrollmentID:            "enroll-1",
		DeviceID:                "device-1",
		EKSPKISHA256:            "sha256:" + strings.Repeat("a", 64),
		EnrollmentRequestDigest: digest,
		IssuedAt:                now,
		ExpiresAt:               now.Add(time.Minute),
	}
	if err := ValidateTPMEnrollmentChallengeForRequest(req, challenge, now); err != nil {
		t.Fatalf("matching enrollment request rejected: %v", err)
	}

	tampered := req
	tampered.BootstrapAttestorPublicKey = bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize)
	if err := ValidateTPMEnrollmentChallengeForRequest(tampered, challenge, now); !errors.Is(err, ErrEnrollmentActivationFailed) {
		t.Fatalf("tampered bootstrap attestor request was not rejected: %v", err)
	}
}
