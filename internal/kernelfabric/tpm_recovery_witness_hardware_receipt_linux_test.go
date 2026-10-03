//go:build linux && cgo

package kernelfabric

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMRecoveryWitnessHardwareReceiptBindsDeviceAndLivePublicArea(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(24001)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewTPMRecoveryWitnessSigner(sim, "")
	if err != nil {
		_ = sim.Close()
		t.Fatal(err)
	}
	defer signer.Close()

	hardware := TPMHardwareIdentityEvidence{
		Version:          TPMHardwareIdentityEvidenceVersion,
		DevicePath:       "/dev/tpmrm0",
		DeviceMode:       "Dcrw-------",
		TPMManufacturer:  "TEST",
		TPMVendorInfo:    "simulator-fixture-only",
		TPMFirmwareMajor: 1,
		TPMFirmwareMinor: 2,
		EKSPKISHA256:     "sha256:" + strings.Repeat("a", 64),
	}
	receipt, err := CreateTPMRecoveryWitnessHardwareReceipt(
		context.Background(),
		signer,
		hardware,
		"challenge-24001",
		time.Date(2026, 10, 3, 5, 20, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTPMRecoveryWitnessHardwareReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Statement.WitnessPublic.PublicAreaSHA256 == "" ||
		receipt.Statement.WitnessPublic.NameHex == "" {
		t.Fatal("hardware receipt omitted live TPM public-area identity")
	}

	substitutedEK := receipt
	substitutedEK.Statement.Hardware.EKSPKISHA256 = "sha256:" + strings.Repeat("b", 64)
	if err := VerifyTPMRecoveryWitnessHardwareReceipt(substitutedEK); err == nil {
		t.Fatal("hardware receipt accepted substituted EK identity")
	}

	forgedAttributes := receipt
	forgedAttributes.Statement.WitnessPublic.Attributes = 0
	if err := VerifyTPMRecoveryWitnessHardwareReceipt(forgedAttributes); err == nil {
		t.Fatal("hardware receipt accepted public attributes not derivable from pinned B key")
	}

	badSignature := receipt
	rawSignature, err := base64.StdEncoding.DecodeString(badSignature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	rawSignature[len(rawSignature)-1] ^= 0x01
	badSignature.Signature = base64.StdEncoding.EncodeToString(rawSignature)
	if err := VerifyTPMRecoveryWitnessHardwareReceipt(badSignature); err == nil {
		t.Fatal("hardware receipt accepted modified TPM signature")
	}
}

func TestTPMHardwareIdentityEvidenceRejectsNonCharacterDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-tpm")
	if err := os.WriteFile(path, []byte("simulator fallback"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureTPMHardwareIdentityEvidence(path); err == nil {
		t.Fatal("hardware evidence accepted regular file instead of kernel TPM character device")
	}
}
