//go:build linux && cgo

package kernelfabric

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/go-attestation/attest"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMSimulatorEnrollmentAndRemoteAllow(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	tpm := attest.InjectSimulatedTPMForTest(sim)
	defer tpm.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close(tpm)

	eks, err := tpm.EKs()
	if err != nil || len(eks) == 0 {
		t.Fatalf("simulator EK unavailable: %v", err)
	}
	ekDER, err := x509.MarshalPKIXPublicKey(eks[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	ekHash := sha256.Sum256(ekDER)
	ekFP := "sha256:" + hex.EncodeToString(ekHash[:])

	attestorPub, attestorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 23, 30, 0, 0, time.UTC)
	enrollReq := TPMEnrollmentRequest{
		Version:                    TPMEnrollmentRequestVersion,
		DeviceID:                   "sim-device",
		AK:                         attestationParametersToWire(ak.AttestationParameters()),
		EKPublicDER:                ekDER,
		BootstrapAttestorPublicKey: append([]byte(nil), attestorPub...),
		CreatedAt:                  now,
	}
	enrollChallenge, pending, err := BeginTPMEnrollment(
		enrollReq,
		TPMEnrollmentTrustPolicy{
			AllowedEKSPKI: map[string]struct{}{ekFP: {}},
			Now:           func() time.Time { return now },
		},
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ak.ActivateCredentialWithEK(tpm, attest.EncryptedCredential{
		Credential: enrollChallenge.EncryptedCredential,
		Secret:     enrollChallenge.EncryptedSecret,
	}, eks[0])
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := enrollmentTranscriptPayload(enrollChallenge)
	if err != nil {
		t.Fatal(err)
	}
	transcriptSignature, err := ak.SignMsg(tpm, transcript, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := CompleteTPMEnrollment(pending, TPMEnrollmentProof{
		Version:             TPMEnrollmentProofVersion,
		EnrollmentID:        enrollChallenge.EnrollmentID,
		DeviceID:            enrollChallenge.DeviceID,
		Secret:              secret,
		TranscriptSignature: transcriptSignature,
		CompletedAt:         now,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	artifactHex := strings.Repeat("ab", 32)
	artifactDigest := "sha256:" + artifactHex
	templateHex := strings.Repeat("21", 32)
	templateDigest, _ := hex.DecodeString(templateHex)
	if err := legacytpm2.PCRExtend(
		sim,
		tpmutil.Handle(DefaultIMAPCRIndex),
		legacytpm2.AlgSHA256,
		templateDigest,
		"",
	); err != nil {
		t.Fatal(err)
	}
	imaLog := []byte(
		"10 " + templateHex + " ima-ng sha256:" + artifactHex + " /tmp/aegis_connect.bpf.o\n",
	)

	receipt := remoteTestReceipt(t, artifactDigest, attestorPriv)
	challenge, err := NewRemoteAttestationChallenge("sim-device", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	platformLog, err := tpm.MeasurementLog()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := RemoteQuoteNonce(challenge, receipt, imaLog, platformLog)
	if err != nil {
		t.Fatal(err)
	}
	allPCRs, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		t.Fatal(err)
	}
	selected, wirePCRs, err := selectChallengePCRs(allPCRs, challenge.PCRs)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := ak.QuotePCRs(tpm, nonce, attest.HashSHA256, challenge.PCRs)
	if err != nil {
		t.Fatal(err)
	}
	akPublic, err := attest.ParseAKPublic(identity.AK.Public)
	if err != nil {
		t.Fatal(err)
	}
	if err := akPublic.Verify(*quote, selected, nonce); err != nil {
		t.Fatalf("simulator quote failed local verification: %v", err)
	}

	_, verifierPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidence := RemoteAttestationEvidence{
		Version:               RemoteAttestationEvidenceVersion,
		DeviceID:              challenge.DeviceID,
		ChallengeID:           challenge.ChallengeID,
		BootstrapReceipt:      receipt,
		Quote:                 TPMQuoteEvidence{Quote: quote.Quote, Signature: quote.Signature},
		PCRs:                  wirePCRs,
		PlatformEventLog:      platformLog,
		IMASHA256Measurements: imaLog,
		CollectedAt:           now,
	}
	decision, err := VerifyRemoteAttestation(
		challenge,
		identity,
		evidence,
		RemoteAttestationPolicy{
			RequirePlatformEventLog:             false,
			RequireIMAReplay:                    true,
			RequireBootstrapArtifactMeasurement: true,
			VerifierKey:                         verifierPriv,
			VerifierID:                          "sim-verifier",
			Now:                                 func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW, got %+v", decision.Decision)
	}
	replayed, err := ReplayIMASHA256PCR10(imaLog)
	if err != nil {
		t.Fatal(err)
	}
	pcr10, err := findPCRDigest(selected, 10, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed) != string(pcr10) {
		t.Fatalf("simulated IMA PCR mismatch replay=%x quote=%x", replayed, pcr10)
	}
}
