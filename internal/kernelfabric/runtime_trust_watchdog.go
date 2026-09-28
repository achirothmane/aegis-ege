
package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	RuntimeTrustExpiryEvidenceVersion = "aegis.ege/runtime-trust-expiry-evidence/v1"

	RuntimeExpiryProcessRunning       = "MATCH_RUNNING"
	RuntimeExpiryProcessAbsent        = "ABSENT"
	RuntimeExpiryProcessPIDReused     = "PID_REUSED"
	RuntimeExpiryProcessCgroupMismatch = "CGROUP_MISMATCH"
)

var (
	ErrRuntimeTrustDeadlineNotReached = errors.New("runtime trust monotonic deadline has not been reached")
	ErrRuntimeTrustBootChanged        = errors.New("runtime trust boot identity changed")
)

type RuntimeTrustExpiryEvidence struct {
	Version                    string                `json:"version"`
	EvidenceID                 string                `json:"evidence_id"`
	DeviceID                   string                `json:"device_id"`
	WorkloadID                 string                `json:"workload_id"`
	Generation                 uint64                `json:"generation"`
	LifecycleEpoch             uint64                `json:"lifecycle_epoch"`
	ActivationDigest           string                `json:"activation_digest"`
	RuntimeTrustLeaseDigest    string                `json:"runtime_trust_lease_digest"`
	RuntimeTrustLeaseEpoch     uint64                `json:"runtime_trust_lease_epoch"`
	RuntimeTrustExpiresAt      time.Time             `json:"runtime_trust_expires_at"`
	RuntimeTrustBootIDHash     string                `json:"runtime_trust_boot_id_hash"`
	RuntimeTrustInstalledBootNS uint64               `json:"runtime_trust_installed_boot_ns"`
	RuntimeTrustDeadlineBootNS uint64                `json:"runtime_trust_deadline_boot_ns"`
	ObservedBootIDHash         string                `json:"observed_boot_id_hash"`
	ObservedBootNS             uint64                `json:"observed_boot_ns"`
	TargetCgroup               string                `json:"target_cgroup"`
	TargetCgroupID             uint64                `json:"target_cgroup_id"`
	KernelFenceBootIDHash      string                `json:"kernel_fence_boot_id_hash"`
	KernelAuthorityTerm        uint64                `json:"kernel_authority_term"`
	KernelDecisionEpoch        uint64                `json:"kernel_decision_epoch"`
	KernelRevocationEpoch      uint64                `json:"kernel_revocation_epoch"`
	ProcessID                  int                   `json:"process_id"`
	ExpectedProcessIdentity    *LinuxProcessIdentity `json:"expected_process_identity"`
	ObservedProcessIdentity    *LinuxProcessIdentity `json:"observed_process_identity,omitempty"`
	ObservedCgroup             string                `json:"observed_cgroup,omitempty"`
	ObservedCgroupID           uint64                `json:"observed_cgroup_id,omitempty"`
	ProcessState               string                `json:"process_state"`
	ObservedAt                 time.Time             `json:"observed_at"`
}

type SignedRuntimeTrustExpiryEvidence struct {
	Evidence  RuntimeTrustExpiryEvidence `json:"evidence"`
	KeyID     string                     `json:"key_id"`
	Signature string                     `json:"signature"`
}

func ValidateRuntimeTrustExpiryEvidence(e RuntimeTrustExpiryEvidence) error {
	if e.Version != RuntimeTrustExpiryEvidenceVersion ||
		strings.TrimSpace(e.EvidenceID) == "" ||
		strings.TrimSpace(e.DeviceID) == "" ||
		strings.TrimSpace(e.WorkloadID) == "" ||
		e.Generation == 0 ||
		e.LifecycleEpoch == 0 ||
		e.RuntimeTrustLeaseEpoch == 0 ||
		e.RuntimeTrustExpiresAt.IsZero() ||
		e.RuntimeTrustInstalledBootNS == 0 ||
		e.RuntimeTrustDeadlineBootNS == 0 ||
		e.RuntimeTrustDeadlineBootNS <= e.RuntimeTrustInstalledBootNS ||
		e.ObservedBootNS < e.RuntimeTrustDeadlineBootNS ||
		e.TargetCgroupID == 0 ||
		e.KernelAuthorityTerm == 0 ||
		e.KernelDecisionEpoch == 0 ||
		e.KernelRevocationEpoch == 0 ||
		e.ProcessID <= 0 ||
		e.ExpectedProcessIdentity == nil ||
		e.ObservedAt.IsZero() {
		return errors.New("runtime trust expiry evidence is incomplete")
	}
	for field, digest := range map[string]string{
		"activation_digest":          e.ActivationDigest,
		"runtime_trust_lease_digest": e.RuntimeTrustLeaseDigest,
		"runtime_trust_boot_id_hash": e.RuntimeTrustBootIDHash,
		"observed_boot_id_hash":      e.ObservedBootIDHash,
		"kernel_fence_boot_id_hash":  e.KernelFenceBootIDHash,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if e.RuntimeTrustBootIDHash != e.ObservedBootIDHash ||
		e.KernelFenceBootIDHash != e.ObservedBootIDHash {
		return ErrRuntimeTrustBootChanged
	}
	if filepath.Clean(e.TargetCgroup) != e.TargetCgroup ||
		!filepath.IsAbs(e.TargetCgroup) {
		return errors.New("runtime trust expiry target cgroup must be a clean absolute path")
	}
	if err := ValidateLinuxProcessIdentity(*e.ExpectedProcessIdentity); err != nil {
		return err
	}
	if e.ExpectedProcessIdentity.BootIDHash != e.ObservedBootIDHash {
		return ErrRuntimeTrustBootChanged
	}
	if e.ObservedProcessIdentity != nil {
		if err := ValidateLinuxProcessIdentity(*e.ObservedProcessIdentity); err != nil {
			return err
		}
		if e.ObservedProcessIdentity.BootIDHash != e.ObservedBootIDHash {
			return ErrRuntimeTrustBootChanged
		}
	}
	switch e.ProcessState {
	case RuntimeExpiryProcessRunning:
		if e.ObservedProcessIdentity == nil ||
			*e.ObservedProcessIdentity != *e.ExpectedProcessIdentity ||
			e.ObservedCgroupID != e.TargetCgroupID ||
			filepath.Clean(e.ObservedCgroup) != e.TargetCgroup {
			return errors.New("MATCH_RUNNING expiry evidence is inconsistent")
		}
	case RuntimeExpiryProcessAbsent:
		if e.ObservedProcessIdentity != nil ||
			e.ObservedCgroupID != 0 ||
			e.ObservedCgroup != "" {
			return errors.New("ABSENT expiry evidence is inconsistent")
		}
	case RuntimeExpiryProcessPIDReused:
		if e.ObservedProcessIdentity == nil ||
			*e.ObservedProcessIdentity == *e.ExpectedProcessIdentity {
			return errors.New("PID_REUSED expiry evidence is inconsistent")
		}
	case RuntimeExpiryProcessCgroupMismatch:
		if e.ObservedProcessIdentity == nil ||
			*e.ObservedProcessIdentity != *e.ExpectedProcessIdentity ||
			(e.ObservedCgroupID == e.TargetCgroupID &&
				filepath.Clean(e.ObservedCgroup) == e.TargetCgroup) {
			return errors.New("CGROUP_MISMATCH expiry evidence is inconsistent")
		}
	default:
		return fmt.Errorf("unsupported runtime trust expiry process state %q", e.ProcessState)
	}
	return nil
}

func SignRuntimeTrustExpiryEvidence(
	e RuntimeTrustExpiryEvidence,
	privateKey ed25519.PrivateKey,
) (SignedRuntimeTrustExpiryEvidence, error) {
	if err := ValidateRuntimeTrustExpiryEvidence(e); err != nil {
		return SignedRuntimeTrustExpiryEvidence{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedRuntimeTrustExpiryEvidence{}, errors.New("host runtime watchdog private key is invalid")
	}
	payload, err := canonicalRuntimeTrustExpiryEvidencePayload(e)
	if err != nil {
		return SignedRuntimeTrustExpiryEvidence{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRuntimeTrustExpiryEvidence{}, err
	}
	return SignedRuntimeTrustExpiryEvidence{
		Evidence:  e,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedRuntimeTrustExpiryEvidence(
	signed SignedRuntimeTrustExpiryEvidence,
	publicKey ed25519.PublicKey,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("host runtime watchdog public key is invalid")
	}
	if err := ValidateRuntimeTrustExpiryEvidence(signed.Evidence); err != nil {
		return err
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return ErrBootstrapSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalRuntimeTrustExpiryEvidencePayload(signed.Evidence)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedRuntimeTrustExpiryEvidenceDigest(
	signed SignedRuntimeTrustExpiryEvidence,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed runtime trust expiry evidence is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-runtime-trust-expiry-evidence/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalRuntimeTrustExpiryEvidencePayload(
	e RuntimeTrustExpiryEvidence,
) ([]byte, error) {
	normalized := e
	normalized.TargetCgroup = filepath.Clean(normalized.TargetCgroup)
	if normalized.ObservedCgroup != "" {
		normalized.ObservedCgroup = filepath.Clean(normalized.ObservedCgroup)
	}
	normalized.RuntimeTrustExpiresAt = normalized.RuntimeTrustExpiresAt.UTC()
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/runtime-trust-expiry-evidence/v1\x00"), body...), nil
}
