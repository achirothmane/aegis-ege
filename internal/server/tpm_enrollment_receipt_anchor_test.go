//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMAnchoredEnrollmentReceiptRejectsRollbackAfterRestart(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(1111)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A180),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A181),
		StatePath:     filepath.Join(dir, "enrollment-anchor.json"),
		IndexAuth:     []byte("vcs11-counter"),
		HeadIndexAuth: []byte("vcs11-head"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "enrollment-current.json")
	store := kernelfabric.AnchoredEnrollmentIdentityStore{
		Store:  kernelfabric.EnrollmentIdentityReceiptStore{Path: receiptPath},
		Anchor: anchor,
	}

	id1 := serverEnrollmentIdentity(
		"sha256:"+strings.Repeat("a", 64),
		time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC),
	)
	r1 := serverSignedEnrollmentReceipt(t, priv, "r1", 1, "", id1)
	d1, err := store.Append(context.Background(), r1, pub)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}

	id2 := serverEnrollmentIdentity(
		"sha256:"+strings.Repeat("b", 64),
		id1.EnrolledAt.Add(time.Minute),
	)
	r2 := serverSignedEnrollmentReceipt(t, priv, "r2", 2, d1, id2)
	d2, err := store.Append(context.Background(), r2, pub)
	if err != nil {
		t.Fatal(err)
	}

	restartedAnchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	restartedStore := kernelfabric.AnchoredEnrollmentIdentityStore{
		Store:  kernelfabric.EnrollmentIdentityReceiptStore{Path: receiptPath},
		Anchor: restartedAnchor,
	}
	current, currentDigest, exists, err := restartedStore.Current(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || currentDigest != d2 || current.Receipt.ReceiptID != "r2" {
		t.Fatalf("restart did not recover current enrollment receipt: exists=%t digest=%s receipt=%+v", exists, currentDigest, current.Receipt)
	}

	// Roll the writable receipt volume back to the exact valid R1 snapshot while
	// the TPM exact-head anchor remains at R2.
	if err := os.WriteFile(receiptPath, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(receiptPath + ".pending")

	restartedAgain, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rolledBackStore := kernelfabric.AnchoredEnrollmentIdentityStore{
		Store:  kernelfabric.EnrollmentIdentityReceiptStore{Path: receiptPath},
		Anchor: restartedAgain,
	}
	_, _, _, err = rolledBackStore.Current(context.Background(), pub)
	if !errors.Is(err, kernelfabric.ErrEnrollmentIdentityRollback) {
		t.Fatalf("expected TPM-anchored enrollment rollback rejection, got %v", err)
	}
}

func serverEnrollmentIdentity(
	ekDigest string,
	enrolledAt time.Time,
) kernelfabric.EnrolledTPMIdentity {
	return kernelfabric.EnrolledTPMIdentity{
		DeviceID:                   "device:vcs11",
		AK:                         kernelfabric.TPMAttestationParameters{Public: []byte("ak-public-vcs11-server")},
		EKSPKISHA256:               ekDigest,
		BootstrapAttestorPublicKey: make([]byte, ed25519.PublicKeySize),
		TPMManufacturer:            "SIM",
		TPMVendorInfo:              "VCS11",
		TPMFirmwareMajor:           1,
		TPMFirmwareMinor:           2,
		EnrolledAt:                 enrolledAt,
	}
}

func serverSignedEnrollmentReceipt(
	t *testing.T,
	priv ed25519.PrivateKey,
	id string,
	sequence uint64,
	previous string,
	identity kernelfabric.EnrolledTPMIdentity,
) kernelfabric.SignedEnrollmentIdentityReceipt {
	t.Helper()
	receipt, err := kernelfabric.NewEnrollmentIdentityReceipt(
		id,
		sequence,
		previous,
		identity,
		identity.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := kernelfabric.SignEnrollmentIdentityReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
