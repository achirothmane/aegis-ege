package computesettlement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const liveAegisAttestationLineageVersion = "aegis.compute/live-aegis-attestation-lineage/v0"

type AegisExecutionRootTrust struct {
	HostAttestorPublicKey       ed25519.PublicKey
	LifecycleAuthorityPublicKey ed25519.PublicKey
}

// AegisRuntimeObservation is the live runtime observation consumed by the
// portable producer. Linux callers should obtain it through
// CaptureLiveAegisExecutionRoot rather than constructing it themselves.
type AegisRuntimeObservation struct {
	ProcessIdentity          kernelfabric.LinuxProcessIdentity
	CgroupID                 uint64
	ExecutableArtifactDigest string
}

type LiveAegisExecutionRoot struct {
	Root                     TrustedExecutionRoot
	DeviceID                 string
	WorkloadID               string
	WorkloadSpecDigest       string
	ExecutableArtifactDigest string
	RuntimeTrustLeaseDigest  string
	AttestationLineageDigest string
	RuntimeTrustLeaseEpoch   uint64
}

// ProduceLiveAegisExecutionRoot converts current Aegis workload/runtime trust
// artifacts plus a live process observation into the VCS-07 TrustedExecutionRoot.
//
// It intentionally does not understand GPU, model, benchmark, or billing
// semantics. The only compute-domain bridge is that the VCS workload profile
// must name the same Aegis WorkloadID, bind WorkloadDigest to the signed Aegis
// WorkloadSpecDigest, and bind ArtifactDigest to the live executable digest.
func ProduceLiveAegisExecutionRoot(
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	observation AegisRuntimeObservation,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	now time.Time,
) (LiveAegisExecutionRoot, error) {
	if len(trust.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return LiveAegisExecutionRoot{}, errors.New("host activation attestor public key is required")
	}
	if len(trust.LifecycleAuthorityPublicKey) != ed25519.PublicKeySize {
		return LiveAegisExecutionRoot{}, errors.New("runtime trust lifecycle authority public key is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	if err := kernelfabric.VerifySignedWorkloadActivationReceipt(
		activation,
		trust.HostAttestorPublicKey,
	); err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("verify workload activation receipt: %w", err)
	}
	if activation.Receipt.Version != kernelfabric.WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil {
		return LiveAegisExecutionRoot{}, errors.New("live execution root requires activation receipt v2 process identity")
	}

	if err := kernelfabric.VerifySignedRuntimeTrustLease(
		runtimeLease,
		trust.LifecycleAuthorityPublicKey,
		now,
	); err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("verify runtime trust lease: %w", err)
	}

	state = kernelfabric.NormalizeWorkloadLifecycleState(state)
	if err := kernelfabric.ValidateWorkloadLifecycleState(state); err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("validate workload lifecycle state: %w", err)
	}
	if state.State != kernelfabric.LifecycleStateRunning {
		return LiveAegisExecutionRoot{}, errors.New("live execution root requires RUNNING lifecycle state")
	}

	if err := kernelfabric.ValidateLinuxProcessIdentity(observation.ProcessIdentity); err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("validate observed process identity: %w", err)
	}
	if observation.CgroupID == 0 {
		return LiveAegisExecutionRoot{}, errors.New("observed cgroup identity is required")
	}
	if _, err := kernelfabric.ParseSHA256Digest(observation.ExecutableArtifactDigest); err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("observed executable artifact digest: %w", err)
	}
	if err := validateWorkloadPerformanceProfile(expectedProfile); err != nil {
		return LiveAegisExecutionRoot{}, err
	}

	activationDigest, err := kernelfabric.SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("digest workload activation receipt: %w", err)
	}
	runtimeLeaseDigest, err := kernelfabric.SignedRuntimeTrustLeaseDigest(runtimeLease)
	if err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("digest runtime trust lease: %w", err)
	}

	a := activation.Receipt
	l := runtimeLease.Lease

	if state.DeviceID != a.DeviceID ||
		state.DeviceID != l.DeviceID ||
		state.WorkloadID != a.WorkloadID ||
		state.WorkloadID != l.WorkloadID {
		return LiveAegisExecutionRoot{}, errors.New("device/workload identity differs across lifecycle, activation, and runtime trust")
	}
	if state.Generation != l.Generation ||
		state.LifecycleEpoch != l.LifecycleEpoch {
		return LiveAegisExecutionRoot{}, errors.New("runtime trust lease generation/lifecycle epoch differs from current lifecycle state")
	}
	if state.ActivationDigest != activationDigest ||
		l.ActivationDigest != activationDigest {
		return LiveAegisExecutionRoot{}, errors.New("activation digest differs across lifecycle and runtime trust")
	}
	if state.RuntimeTrustEpoch != l.LeaseEpoch ||
		state.RuntimeTrustLeaseDigest != runtimeLeaseDigest {
		return LiveAegisExecutionRoot{}, errors.New("current lifecycle state is not bound to the presented runtime trust lease")
	}
	if !state.RuntimeTrustExpiresAt.UTC().Equal(l.ExpiresAt.UTC()) {
		return LiveAegisExecutionRoot{}, errors.New("runtime trust expiry differs from current lifecycle state")
	}
	if a.WorkloadSpecDigest != l.WorkloadSpecDigest {
		return LiveAegisExecutionRoot{}, errors.New("activation and runtime trust disagree on workload spec")
	}
	if a.TargetCgroupID != l.TargetCgroupID ||
		a.TargetCgroupID != observation.CgroupID {
		return LiveAegisExecutionRoot{}, errors.New("observed cgroup identity differs from admitted runtime cgroup")
	}

	if *a.ProcessIdentity != observation.ProcessIdentity {
		return LiveAegisExecutionRoot{}, errors.New("live process identity differs from activation receipt")
	}
	if state.RuntimeTrustBootIDHash != observation.ProcessIdentity.BootIDHash {
		return LiveAegisExecutionRoot{}, errors.New("live process boot identity differs from runtime trust boot binding")
	}

	if expectedProfile.WorkloadID != a.WorkloadID {
		return LiveAegisExecutionRoot{}, errors.New("compute workload id differs from live Aegis workload id")
	}
	if expectedProfile.WorkloadDigest != a.WorkloadSpecDigest {
		return LiveAegisExecutionRoot{}, errors.New("compute workload digest differs from signed Aegis workload spec digest")
	}
	if expectedProfile.ArtifactDigest != observation.ExecutableArtifactDigest {
		return LiveAegisExecutionRoot{}, errors.New("compute artifact digest differs from live executable artifact")
	}

	processDigest, err := kernelfabric.LinuxProcessIdentityDigest(observation.ProcessIdentity)
	if err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("digest live process identity: %w", err)
	}
	cgroupDigest, err := liveCgroupIdentityDigest(
		observation.ProcessIdentity.BootIDHash,
		observation.CgroupID,
	)
	if err != nil {
		return LiveAegisExecutionRoot{}, err
	}
	attestationDigest, err := liveAegisAttestationLineageDigest(
		state,
		runtimeLease,
		runtimeLeaseDigest,
	)
	if err != nil {
		return LiveAegisExecutionRoot{}, err
	}

	return LiveAegisExecutionRoot{
		Root: TrustedExecutionRoot{
			ActivationReceiptDigest: activationDigest,
			ProcessIdentityDigest:    processDigest,
			CgroupIdentityDigest:     cgroupDigest,
			BootMeasurementDigest:    attestationDigest,
		},
		DeviceID:                 a.DeviceID,
		WorkloadID:               a.WorkloadID,
		WorkloadSpecDigest:       a.WorkloadSpecDigest,
		ExecutableArtifactDigest: observation.ExecutableArtifactDigest,
		RuntimeTrustLeaseDigest:  runtimeLeaseDigest,
		AttestationLineageDigest: attestationDigest,
		RuntimeTrustLeaseEpoch:   l.LeaseEpoch,
	}, nil
}

func liveCgroupIdentityDigest(bootIDHash string, cgroupID uint64) (string, error) {
	if _, err := kernelfabric.ParseSHA256Digest(bootIDHash); err != nil {
		return "", fmt.Errorf("cgroup boot identity: %w", err)
	}
	if cgroupID == 0 {
		return "", errors.New("cgroup id must be non-zero")
	}
	raw := fmt.Sprintf("%s\x00%d", bootIDHash, cgroupID)
	sum := sha256.Sum256(append([]byte("aegis.compute/live-cgroup-identity/v0\x00"), []byte(raw)...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type liveAegisAttestationLineage struct {
	Version                     string    `json:"version"`
	DeviceID                    string    `json:"device_id"`
	WorkloadID                  string    `json:"workload_id"`
	ActivationDigest            string    `json:"activation_digest"`
	RuntimeTrustLeaseDigest     string    `json:"runtime_trust_lease_digest"`
	RuntimeTrustLeaseEpoch      uint64    `json:"runtime_trust_lease_epoch"`
	RemoteDecisionDigest        string    `json:"remote_decision_digest"`
	BootstrapDigest             string    `json:"bootstrap_digest"`
	PolicyDigest                string    `json:"policy_digest"`
	RuntimeTrustBootIDHash      string    `json:"runtime_trust_boot_id_hash"`
	RuntimeTrustInstalledBootNS uint64    `json:"runtime_trust_installed_boot_ns"`
	RuntimeTrustDeadlineBootNS  uint64    `json:"runtime_trust_deadline_boot_ns"`
	RemoteVerifiedAt            time.Time `json:"remote_verified_at"`
	RuntimeTrustExpiresAt       time.Time `json:"runtime_trust_expires_at"`
}

func liveAegisAttestationLineageDigest(
	state kernelfabric.WorkloadLifecycleState,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	runtimeLeaseDigest string,
) (string, error) {
	if strings.TrimSpace(runtimeLeaseDigest) == "" {
		return "", errors.New("runtime trust lease digest is required")
	}
	l := runtimeLease.Lease
	lineage := liveAegisAttestationLineage{
		Version:                     liveAegisAttestationLineageVersion,
		DeviceID:                    l.DeviceID,
		WorkloadID:                  l.WorkloadID,
		ActivationDigest:            l.ActivationDigest,
		RuntimeTrustLeaseDigest:     runtimeLeaseDigest,
		RuntimeTrustLeaseEpoch:      l.LeaseEpoch,
		RemoteDecisionDigest:        l.RemoteDecisionDigest,
		BootstrapDigest:             l.BootstrapDigest,
		PolicyDigest:                l.PolicyDigest,
		RuntimeTrustBootIDHash:      state.RuntimeTrustBootIDHash,
		RuntimeTrustInstalledBootNS: state.RuntimeTrustInstalledBootNS,
		RuntimeTrustDeadlineBootNS:  state.RuntimeTrustDeadlineBootNS,
		RemoteVerifiedAt:            l.RemoteVerifiedAt.UTC(),
		RuntimeTrustExpiresAt:       l.ExpiresAt.UTC(),
	}
	body, err := json.Marshal(lineage)
	if err != nil {
		return "", fmt.Errorf("marshal live Aegis attestation lineage: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis.compute/live-aegis-attestation-lineage/v0\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
