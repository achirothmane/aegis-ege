//go:build linux && cgo

package kernelfabric

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
)

type vcs11CeremonyHeadAnchor struct {
	mu    sync.Mutex
	state DurableHeadAnchorState
}

func (a *vcs11CeremonyHeadAnchor) Current(context.Context) (DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *vcs11CeremonyHeadAnchor) CompareAndAdvance(
	_ context.Context,
	expected,
	next DurableHeadAnchorState,
) (DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != expected {
		return a.state, ErrEnrollmentIdentityRollback
	}
	if next.Sequence != expected.Sequence+1 || next.HeadDigest == "" {
		return a.state, ErrEnrollmentIdentityReceiptInvalid
	}
	a.state = next
	return a.state, nil
}

func TestVCS11TPMCeremonyIsRequiredBeforeDurableEnrollmentCommit(t *testing.T) {
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

	attestorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)
	request := TPMEnrollmentRequest{
		Version:                    TPMEnrollmentRequestVersion,
		DeviceID:                   "device:vcs11-ceremony",
		AK:                         attestationParametersToWire(ak.AttestationParameters()),
		EKPublicDER:                ekDER,
		BootstrapAttestorPublicKey: append([]byte(nil), attestorPub...),
		CreatedAt:                  now,
	}
	challenge, pending, err := BeginTPMEnrollment(
		request,
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
		Credential: challenge.EncryptedCredential,
		Secret:     challenge.EncryptedSecret,
	}, eks[0])
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := enrollmentTranscriptPayload(challenge)
	if err != nil {
		t.Fatal(err)
	}
	transcriptSignature, err := ak.SignMsg(tpm, transcript, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	authorityPub, authorityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchor := &vcs11CeremonyHeadAnchor{}
	store := AnchoredEnrollmentIdentityStore{
		Store: EnrollmentIdentityReceiptStore{
			Path: filepath.Join(t.TempDir(), "enrollment-current.json"),
		},
		Anchor: anchor,
	}
	ctx := context.Background()

	badProof := TPMEnrollmentProof{
		Version:             TPMEnrollmentProofVersion,
		EnrollmentID:        challenge.EnrollmentID,
		DeviceID:            challenge.DeviceID,
		Secret:              []byte("not-the-activated-secret"),
		TranscriptSignature: transcriptSignature,
		CompletedAt:         now.Add(time.Second),
	}
	if _, _, _, err := CompleteAndCommitTPMEnrollmentReceipt(
		ctx,
		pending,
		badProof,
		now.Add(time.Second),
		store,
		authorityPriv,
	); !errors.Is(err, ErrEnrollmentActivationFailed) {
		t.Fatalf("wrong activation secret should fail enrollment ceremony, got %v", err)
	}
	head, err := anchor.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != (DurableHeadAnchorState{}) {
		t.Fatalf("failed enrollment ceremony advanced durable head: %+v", head)
	}
	if _, _, exists, err := store.Current(ctx, authorityPub); err != nil || exists {
		t.Fatalf("failed enrollment ceremony created durable receipt: exists=%t err=%v", exists, err)
	}

	goodProof := TPMEnrollmentProof{
		Version:             TPMEnrollmentProofVersion,
		EnrollmentID:        challenge.EnrollmentID,
		DeviceID:            challenge.DeviceID,
		Secret:              secret,
		TranscriptSignature: transcriptSignature,
		CompletedAt:         now.Add(2 * time.Second),
	}
	identity, signed, digest, err := CompleteAndCommitTPMEnrollmentReceipt(
		ctx,
		pending,
		goodProof,
		now.Add(2 * time.Second),
		store,
		authorityPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Receipt.ReceiptID != challenge.EnrollmentID {
		t.Fatalf("receipt id=%q want ceremony enrollment id=%q", signed.Receipt.ReceiptID, challenge.EnrollmentID)
	}
	if signed.Receipt.Sequence != 1 || signed.Receipt.PreviousReceiptDigest != "" {
		t.Fatalf("unexpected first durable receipt lineage: %+v", signed.Receipt)
	}
	if signed.Receipt.DeviceID != request.DeviceID || signed.Receipt.EKSPKISHA256 != ekFP {
		t.Fatalf("durable receipt lost ceremony identity: %+v", signed.Receipt)
	}
	if err := VerifyEnrollmentIdentityReceiptForIdentity(signed, authorityPub, identity); err != nil {
		t.Fatalf("committed ceremony receipt does not bind completed identity: %v", err)
	}

	current, currentDigest, exists, err := store.Current(ctx, authorityPub)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || currentDigest != digest || current.Receipt.ReceiptID != challenge.EnrollmentID {
		t.Fatalf("durable store did not recover ceremony receipt: exists=%t digest=%s receipt=%+v", exists, currentDigest, current.Receipt)
	}

	// Retrying the same verified ceremony must return the already committed R1,
	// not advance the durable head to a second receipt.
	_, replayed, replayDigest, err := CompleteAndCommitTPMEnrollmentReceipt(
		ctx,
		pending,
		goodProof,
		now.Add(3*time.Second),
		store,
		authorityPriv,
	)
	if err != nil {
		t.Fatalf("idempotent ceremony retry failed: %v", err)
	}
	if replayDigest != digest || replayed.Receipt.Sequence != 1 || replayed.Receipt.ReceiptID != challenge.EnrollmentID {
		t.Fatalf("ceremony retry advanced or changed durable receipt: digest=%s receipt=%+v", replayDigest, replayed.Receipt)
	}
	head, err = anchor.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != 1 || head.HeadDigest != digest {
		t.Fatalf("ceremony retry advanced durable head: %+v", head)
	}
}
