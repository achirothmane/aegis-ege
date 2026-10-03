package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testDurableHeadAnchor struct {
	mu    sync.Mutex
	state DurableHeadAnchorState
}

func (a *testDurableHeadAnchor) Current(context.Context) (DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *testDurableHeadAnchor) CompareAndAdvance(
	_ context.Context,
	expected,
	next DurableHeadAnchorState,
) (DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != expected {
		return a.state, errors.New("anchor compare failed")
	}
	if next.Sequence != expected.Sequence+1 {
		return a.state, errors.New("non-successor")
	}
	a.state = next
	return a.state, nil
}

func TestEnrollmentIdentityReceiptBindsExactIdentity(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := enrollmentReceiptTestIdentity()
	receipt, err := NewEnrollmentIdentityReceipt(
		"enrollment-receipt-1",
		1,
		"",
		identity,
		identity.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEnrollmentIdentityReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnrollmentIdentityReceiptForIdentity(signed, pub, identity); err != nil {
		t.Fatal(err)
	}

	substituted := identity
	substituted.EKSPKISHA256 = "sha256:" + strings.Repeat("c", 64)
	if err := VerifyEnrollmentIdentityReceiptForIdentity(signed, pub, substituted); err == nil {
		t.Fatal("receipt must not validate against substituted TPM identity")
	}
}

func TestAnchoredEnrollmentIdentityStoreRejectsWholeVolumeRollback(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enrollment-current.json")
	anchor := &testDurableHeadAnchor{}
	store := AnchoredEnrollmentIdentityStore{
		Store:  EnrollmentIdentityReceiptStore{Path: path},
		Anchor: anchor,
	}
	identity1 := enrollmentReceiptTestIdentity()
	r1 := signEnrollmentReceiptTest(t, priv, "r1", 1, "", identity1)
	d1, err := store.Append(context.Background(), r1, pub)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	identity2 := identity1
	identity2.EKSPKISHA256 = "sha256:" + strings.Repeat("b", 64)
	identity2.EnrolledAt = identity1.EnrolledAt.Add(time.Minute)
	r2 := signEnrollmentReceiptTest(t, priv, "r2", 2, d1, identity2)
	if _, err := store.Append(context.Background(), r2, pub); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = store.Current(context.Background(), pub)
	if !errors.Is(err, ErrEnrollmentIdentityRollback) {
		t.Fatalf("expected rollback detection, got %v", err)
	}
}

func TestAnchoredEnrollmentIdentityStoreRecoversCommittedPendingAfterCrash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enrollment-current.json")
	anchor := &testDurableHeadAnchor{}
	store := AnchoredEnrollmentIdentityStore{
		Store:  EnrollmentIdentityReceiptStore{Path: path},
		Anchor: anchor,
	}
	identity := enrollmentReceiptTestIdentity()
	r1 := signEnrollmentReceiptTest(t, priv, "r1", 1, "", identity)
	d1, err := EnrollmentIdentityReceiptDigest(r1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store.writePending(r1, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.CompareAndAdvance(
		context.Background(),
		DurableHeadAnchorState{},
		DurableHeadAnchorState{Sequence: 1, HeadDigest: d1},
	); err != nil {
		t.Fatal(err)
	}

	current, digest, exists, err := store.Current(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || digest != d1 || current.Receipt.ReceiptID != "r1" {
		t.Fatalf("committed pending receipt was not recovered: exists=%t digest=%s receipt=%+v", exists, digest, current.Receipt)
	}
	if _, err := os.Stat(path + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("pending receipt should be promoted, stat err=%v", err)
	}
}

func TestAnchoredEnrollmentIdentityStoreDiscardsUncommittedPendingAfterCrash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enrollment-current.json")
	anchor := &testDurableHeadAnchor{}
	store := AnchoredEnrollmentIdentityStore{
		Store:  EnrollmentIdentityReceiptStore{Path: path},
		Anchor: anchor,
	}
	r1 := signEnrollmentReceiptTest(t, priv, "r1", 1, "", enrollmentReceiptTestIdentity())
	if _, err := store.Store.writePending(r1, pub); err != nil {
		t.Fatal(err)
	}

	_, _, exists, err := store.Current(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("uncommitted pending enrollment receipt must not become current")
	}
	if _, err := os.Stat(path + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("uncommitted pending receipt should be removed, stat err=%v", err)
	}
}

func TestAnchoredEnrollmentIdentityStoreRejectsSameSequenceReplacement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "enrollment-current.json")
	anchor := &testDurableHeadAnchor{}
	store := AnchoredEnrollmentIdentityStore{
		Store:  EnrollmentIdentityReceiptStore{Path: path},
		Anchor: anchor,
	}
	identity := enrollmentReceiptTestIdentity()
	r1 := signEnrollmentReceiptTest(t, priv, "r1", 1, "", identity)
	if _, err := store.Append(context.Background(), r1, pub); err != nil {
		t.Fatal(err)
	}

	replacement := identity
	replacement.EKSPKISHA256 = "sha256:" + strings.Repeat("d", 64)
	fork := signEnrollmentReceiptTest(t, priv, "r1-fork", 1, "", replacement)
	payload, err := jsonMarshalEnrollmentReceipt(fork)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err = store.Current(context.Background(), pub)
	if !errors.Is(err, ErrEnrollmentIdentityRollback) {
		t.Fatalf("expected same-sequence replacement rejection, got %v", err)
	}
}

func enrollmentReceiptTestIdentity() EnrolledTPMIdentity {
	return EnrolledTPMIdentity{
		DeviceID:                   "device:vcs11",
		AK:                         TPMAttestationParameters{Public: []byte("ak-public-vcs11")},
		EKSPKISHA256:               "sha256:" + strings.Repeat("a", 64),
		BootstrapAttestorPublicKey: make([]byte, ed25519.PublicKeySize),
		TPMManufacturer:            "SIM",
		TPMVendorInfo:              "VCS11",
		TPMFirmwareMajor:           1,
		TPMFirmwareMinor:           2,
		EnrolledAt:                 time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC),
	}
}

func signEnrollmentReceiptTest(
	t *testing.T,
	priv ed25519.PrivateKey,
	id string,
	sequence uint64,
	previous string,
	identity EnrolledTPMIdentity,
) SignedEnrollmentIdentityReceipt {
	t.Helper()
	receipt, err := NewEnrollmentIdentityReceipt(
		id,
		sequence,
		previous,
		identity,
		identity.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEnrollmentIdentityReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func jsonMarshalEnrollmentReceipt(signed SignedEnrollmentIdentityReceipt) ([]byte, error) {
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, byte(10)), nil
}
