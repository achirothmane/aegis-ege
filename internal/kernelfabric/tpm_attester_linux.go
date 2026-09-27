//go:build linux

package kernelfabric

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
)

const (
	DefaultIMASHA256MeasurementsPath = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha256"
	DefaultTPMCollectAttempts        = 3
)

func ProvisionTPMEnrollmentRequest(
	deviceID string,
	akBlobPath string,
	bootstrapAttestorPublicKeyPath string,
	now time.Time,
) (TPMEnrollmentRequest, error) {
	if strings.TrimSpace(deviceID) == "" {
		return TPMEnrollmentRequest{}, errors.New("device id is required")
	}
	bootstrapAttestorKey, err := LoadEd25519PublicKey(bootstrapAttestorPublicKeyPath)
	if err != nil {
		return TPMEnrollmentRequest{}, fmt.Errorf("load bootstrap attestor public key: %w", err)
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		return TPMEnrollmentRequest{}, fmt.Errorf("open TPM: %w", err)
	}
	defer tpm.Close()

	ak, err := loadOrCreateAK(tpm, akBlobPath)
	if err != nil {
		return TPMEnrollmentRequest{}, err
	}
	defer ak.Close(tpm)

	ek, certDER, err := selectEnrollmentEK(tpm)
	if err != nil {
		return TPMEnrollmentRequest{}, err
	}
	ekDER, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return TPMEnrollmentRequest{}, fmt.Errorf("marshal EK public key: %w", err)
	}
	info, err := tpm.Info()
	if err != nil {
		return TPMEnrollmentRequest{}, fmt.Errorf("read TPM info: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return TPMEnrollmentRequest{
		Version:          TPMEnrollmentRequestVersion,
		DeviceID:         deviceID,
		AK:               attestationParametersToWire(ak.AttestationParameters()),
		EKPublicDER:      ekDER,
		EKCertificateDER:           certDER,
		BootstrapAttestorPublicKey: append([]byte(nil), bootstrapAttestorKey...),
		TPMManufacturer:            info.Manufacturer.String(),
		TPMVendorInfo:    info.VendorInfo,
		TPMFirmwareMajor: info.FirmwareVersionMajor,
		TPMFirmwareMinor: info.FirmwareVersionMinor,
		CreatedAt:        now.UTC(),
	}, nil
}

func ActivateTPMEnrollmentChallenge(
	akBlobPath string,
	challenge TPMEnrollmentChallenge,
	now time.Time,
) (TPMEnrollmentProof, error) {
	if challenge.Version != TPMEnrollmentChallengeVersion ||
		strings.TrimSpace(challenge.EnrollmentID) == "" ||
		strings.TrimSpace(challenge.DeviceID) == "" ||
		strings.TrimSpace(challenge.EKSPKISHA256) == "" {
		return TPMEnrollmentProof{}, ErrEnrollmentActivationFailed
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !now.Before(challenge.ExpiresAt) {
		return TPMEnrollmentProof{}, ErrRemoteChallengeExpired
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		return TPMEnrollmentProof{}, fmt.Errorf("open TPM: %w", err)
	}
	defer tpm.Close()
	blob, err := os.ReadFile(akBlobPath)
	if err != nil {
		return TPMEnrollmentProof{}, fmt.Errorf("read AK blob: %w", err)
	}
	ak, err := tpm.LoadAK(blob)
	if err != nil {
		return TPMEnrollmentProof{}, fmt.Errorf("load AK: %w", err)
	}
	defer ak.Close(tpm)

	eks, err := allTPMEKs(tpm)
	if err != nil {
		return TPMEnrollmentProof{}, err
	}
	var selected *attest.EK
	for i := range eks {
		der, err := x509.MarshalPKIXPublicKey(eks[i].Public)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		if "sha256:"+hex.EncodeToString(sum[:]) == challenge.EKSPKISHA256 {
			selected = &eks[i]
			break
		}
	}
	if selected == nil {
		return TPMEnrollmentProof{}, fmt.Errorf("%w: enrolled EK not present on local TPM", ErrEnrollmentActivationFailed)
	}
	secret, err := ak.ActivateCredentialWithEK(tpm, attest.EncryptedCredential{
		Credential: challenge.EncryptedCredential,
		Secret:     challenge.EncryptedSecret,
	}, *selected)
	if err != nil {
		return TPMEnrollmentProof{}, fmt.Errorf("%w: %v", ErrEnrollmentActivationFailed, err)
	}
	return TPMEnrollmentProof{
		Version:      TPMEnrollmentProofVersion,
		EnrollmentID: challenge.EnrollmentID,
		DeviceID:     challenge.DeviceID,
		Secret:       secret,
		CompletedAt:  now.UTC(),
	}, nil
}

func CollectRemoteAttestationEvidence(
	akBlobPath string,
	challenge RemoteAttestationChallenge,
	receipt SignedBootstrapReceipt,
	imaPath string,
	now time.Time,
) (RemoteAttestationEvidence, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateRemoteChallenge(challenge, now); err != nil {
		return RemoteAttestationEvidence{}, err
	}
	if imaPath == "" {
		imaPath = DefaultIMASHA256MeasurementsPath
	}
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		return RemoteAttestationEvidence{}, fmt.Errorf("open TPM: %w", err)
	}
	defer tpm.Close()
	blob, err := os.ReadFile(akBlobPath)
	if err != nil {
		return RemoteAttestationEvidence{}, fmt.Errorf("read AK blob: %w", err)
	}
	ak, err := tpm.LoadAK(blob)
	if err != nil {
		return RemoteAttestationEvidence{}, fmt.Errorf("load AK: %w", err)
	}
	defer ak.Close(tpm)

	akPublic, err := attest.ParseAKPublic(ak.AttestationParameters().Public)
	if err != nil {
		return RemoteAttestationEvidence{}, fmt.Errorf("parse local AK public: %w", err)
	}

	for attempt := 1; attempt <= DefaultTPMCollectAttempts; attempt++ {
		imaMeasurements, err := os.ReadFile(imaPath)
		if err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("read IMA SHA-256 measurements: %w", err)
		}
		imaReplay, err := ReplayIMASHA256PCR10(imaMeasurements)
		if err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("replay local IMA measurements: %w", err)
		}

		platformEventLog, err := tpm.MeasurementLog()
		if err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("read TPM platform event log: %w", err)
		}
		nonce, err := RemoteQuoteNonce(challenge, receipt, imaMeasurements, platformEventLog)
		if err != nil {
			return RemoteAttestationEvidence{}, err
		}

		allPCRs, err := tpm.PCRs(attest.HashSHA256)
		if err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("read SHA-256 PCR bank: %w", err)
		}
		selected, wirePCRs, err := selectChallengePCRs(allPCRs, challenge.PCRs)
		if err != nil {
			return RemoteAttestationEvidence{}, err
		}
		quotedPCR10, err := findPCRDigest(selected, DefaultIMAPCRIndex, cryptoSHA256)
		if err != nil {
			return RemoteAttestationEvidence{}, err
		}
		if !bytes.Equal(quotedPCR10, imaReplay) {
			if attempt < DefaultTPMCollectAttempts {
				continue
			}
			return RemoteAttestationEvidence{}, fmt.Errorf(
				"%w: IMA log changed while collecting TPM snapshot",
				ErrRemoteIMAReplayMismatch,
			)
		}

		quote, err := ak.QuotePCRs(tpm, nonce, attest.HashSHA256, challenge.PCRs)
		if err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("quote TPM PCRs: %w", err)
		}
		if err := akPublic.Verify(*quote, selected, nonce); err != nil {
			return RemoteAttestationEvidence{}, fmt.Errorf("local TPM quote verification failed: %w", err)
		}

		return RemoteAttestationEvidence{
			Version:               RemoteAttestationEvidenceVersion,
			DeviceID:              challenge.DeviceID,
			ChallengeID:           challenge.ChallengeID,
			BootstrapReceipt:      receipt,
			Quote:                 TPMQuoteEvidence{Quote: quote.Quote, Signature: quote.Signature},
			PCRs:                  wirePCRs,
			PlatformEventLog:      platformEventLog,
			IMASHA256Measurements: imaMeasurements,
			CollectedAt:           now.UTC(),
		}, nil
	}
	return RemoteAttestationEvidence{}, ErrRemoteAttestationInvalid
}

var cryptoSHA256 = crypto.SHA256

func selectChallengePCRs(
	all []attest.PCR,
	requested []int,
) ([]attest.PCR, []AttestedPCR, error) {
	want := map[int]struct{}{}
	for _, idx := range requested {
		if idx < 0 || idx > 23 {
			return nil, nil, fmt.Errorf("invalid requested PCR index %d", idx)
		}
		want[idx] = struct{}{}
	}
	selected := make([]attest.PCR, 0, len(want))
	wire := make([]AttestedPCR, 0, len(want))
	for _, p := range all {
		if p.DigestAlg != crypto.SHA256 {
			continue
		}
		if _, ok := want[p.Index]; !ok {
			continue
		}
		selected = append(selected, p)
		wire = append(wire, AttestedPCR{
			Index:  p.Index,
			Bank:   "sha256",
			Digest: append([]byte(nil), p.Digest...),
		})
	}
	if len(selected) != len(want) {
		return nil, nil, fmt.Errorf(
			"%w: local TPM returned %d/%d requested SHA-256 PCRs",
			ErrRemoteAttestationInvalid,
			len(selected),
			len(want),
		)
	}
	return selected, wire, nil
}

func loadOrCreateAK(tpm *attest.TPM, path string) (*attest.AK, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return nil, errors.New("AK blob path is required")
	}
	if payload, err := os.ReadFile(path); err == nil {
		ak, err := tpm.LoadAK(payload)
		if err != nil {
			return nil, fmt.Errorf("load persisted AK: %w", err)
		}
		return ak, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read persisted AK: %w", err)
	}

	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, fmt.Errorf("create TPM AK: %w", err)
	}
	blob, err := ak.Marshal()
	if err != nil {
		ak.Close(tpm)
		return nil, fmt.Errorf("marshal TPM AK: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		ak.Close(tpm)
		return nil, fmt.Errorf("create AK directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		ak.Close(tpm)
		return nil, fmt.Errorf("persist TPM AK: %w", err)
	}
	if _, err := file.Write(blob); err != nil {
		file.Close()
		os.Remove(path)
		ak.Close(tpm)
		return nil, fmt.Errorf("write TPM AK: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		ak.Close(tpm)
		return nil, fmt.Errorf("sync TPM AK: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		ak.Close(tpm)
		return nil, fmt.Errorf("close TPM AK: %w", err)
	}
	return ak, nil
}

func selectEnrollmentEK(tpm *attest.TPM) (attest.EK, []byte, error) {
	if certs, err := tpm.EKCertificates(); err == nil && len(certs) > 0 {
		for _, ek := range certs {
			if ek.Certificate != nil {
				return ek, append([]byte(nil), ek.Certificate.Raw...), nil
			}
		}
	}
	eks, err := tpm.EKs()
	if err != nil {
		return attest.EK{}, nil, fmt.Errorf("read TPM endorsement keys: %w", err)
	}
	if len(eks) == 0 {
		return attest.EK{}, nil, errors.New("TPM exposes no endorsement key")
	}
	return eks[0], nil, nil
}

func allTPMEKs(tpm *attest.TPM) ([]attest.EK, error) {
	seen := map[string]struct{}{}
	var out []attest.EK
	for _, source := range []func() ([]attest.EK, error){tpm.EKCertificates, tpm.EKs} {
		eks, err := source()
		if err != nil {
			continue
		}
		for _, ek := range eks {
			der, err := x509.MarshalPKIXPublicKey(ek.Public)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(der)
			key := hex.EncodeToString(sum[:])
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ek)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("TPM exposes no usable endorsement key")
	}
	return out, nil
}
