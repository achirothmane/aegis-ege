//go:build linux

package kernelfabric

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-attestation/attest"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const TPMHardwareIdentityEvidenceVersion = "aegis.ege/tpm-hardware-identity/v1"

type TPMHardwareIdentityEvidence struct {
	Version             string `json:"version"`
	DevicePath          string `json:"device_path"`
	DeviceMode          string `json:"device_mode"`
	TPMManufacturer     string `json:"tpm_manufacturer"`
	TPMVendorInfo       string `json:"tpm_vendor_info"`
	TPMFirmwareMajor    uint16 `json:"tpm_firmware_major"`
	TPMFirmwareMinor    uint16 `json:"tpm_firmware_minor"`
	EKSPKISHA256        string `json:"ek_spki_sha256"`
	EKCertificateSHA256 string `json:"ek_certificate_sha256,omitempty"`
}

type tpmHardwareCommandChannel struct {
	io.ReadWriteCloser
}

func (c *tpmHardwareCommandChannel) MeasurementLog() ([]byte, error) {
	for _, path := range []string{
		"/sys/kernel/security/tpm0/binary_bios_measurements",
		"/sys/kernel/security/tpm1/binary_bios_measurements",
	} {
		payload, err := os.ReadFile(path)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("TPM platform measurement log is unavailable")
}

func CaptureTPMHardwareIdentityEvidence(devicePath string) (TPMHardwareIdentityEvidence, error) {
	devicePath = filepath.Clean(strings.TrimSpace(devicePath))
	if devicePath == "." || devicePath == "" {
		return TPMHardwareIdentityEvidence{}, errors.New("TPM device path is required")
	}
	info, err := os.Stat(devicePath)
	if err != nil {
		return TPMHardwareIdentityEvidence{}, fmt.Errorf("stat TPM device: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return TPMHardwareIdentityEvidence{}, fmt.Errorf(
			"TPM hardware proof requires a kernel character device, got mode %s",
			info.Mode(),
		)
	}

	rw, err := legacytpm2.OpenTPM(devicePath)
	if err != nil {
		return TPMHardwareIdentityEvidence{}, fmt.Errorf("open TPM hardware device: %w", err)
	}
	channel := &tpmHardwareCommandChannel{ReadWriteCloser: rw}
	tpm, err := attest.OpenTPM(&attest.OpenConfig{CommandChannel: channel})
	if err != nil {
		_ = rw.Close()
		return TPMHardwareIdentityEvidence{}, fmt.Errorf("open TPM hardware attester: %w", err)
	}
	defer tpm.Close()

	tpmInfo, err := tpm.Info()
	if err != nil {
		return TPMHardwareIdentityEvidence{}, fmt.Errorf("read TPM hardware info: %w", err)
	}
	ek, certDER, err := selectEnrollmentEK(tpm)
	if err != nil {
		return TPMHardwareIdentityEvidence{}, err
	}
	ekDER, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return TPMHardwareIdentityEvidence{}, fmt.Errorf("marshal TPM EK public key: %w", err)
	}
	ekSum := sha256.Sum256(ekDER)
	evidence := TPMHardwareIdentityEvidence{
		Version:          TPMHardwareIdentityEvidenceVersion,
		DevicePath:       devicePath,
		DeviceMode:       info.Mode().String(),
		TPMManufacturer:  tpmInfo.Manufacturer.String(),
		TPMVendorInfo:    tpmInfo.VendorInfo,
		TPMFirmwareMajor: tpmInfo.FirmwareVersionMajor,
		TPMFirmwareMinor: tpmInfo.FirmwareVersionMinor,
		EKSPKISHA256:     "sha256:" + hex.EncodeToString(ekSum[:]),
	}
	if len(certDER) > 0 {
		certSum := sha256.Sum256(certDER)
		evidence.EKCertificateSHA256 = "sha256:" + hex.EncodeToString(certSum[:])
	}
	if err := ValidateTPMHardwareIdentityEvidence(evidence); err != nil {
		return TPMHardwareIdentityEvidence{}, err
	}
	return evidence, nil
}

func ValidateTPMHardwareIdentityEvidence(evidence TPMHardwareIdentityEvidence) error {
	if evidence.Version != TPMHardwareIdentityEvidenceVersion {
		return errors.New("unsupported TPM hardware identity evidence version")
	}
	if filepath.Clean(strings.TrimSpace(evidence.DevicePath)) == "." ||
		strings.TrimSpace(evidence.DeviceMode) == "" {
		return errors.New("TPM hardware device identity is incomplete")
	}
	if strings.TrimSpace(evidence.TPMManufacturer) == "" {
		return errors.New("TPM hardware manufacturer is missing")
	}
	if _, err := ParseSHA256Digest(evidence.EKSPKISHA256); err != nil {
		return fmt.Errorf("TPM hardware EK identity: %w", err)
	}
	if evidence.EKCertificateSHA256 != "" {
		if _, err := ParseSHA256Digest(evidence.EKCertificateSHA256); err != nil {
			return fmt.Errorf("TPM hardware EK certificate identity: %w", err)
		}
	}
	return nil
}
