
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
	"sort"
	"strings"
	"time"
)

const (
	RuntimeTrustLeaseVersion    = "aegis.ege/runtime-trust-lease/v1"
	RuntimeTrustDecisionVersion = "aegis.ege/runtime-trust-decision/v1"

	RuntimeTrustKeepRunning  = "KEEP_RUNNING"
	RuntimeTrustRenewRequired = "RENEW_REQUIRED"
	RuntimeTrustRevoke       = "REVOKE"

	DefaultRuntimeTrustLeaseTTL = 90 * time.Second
	DefaultRuntimeTrustMaxAge   = 2 * time.Minute
	DefaultRuntimeClockSkew     = 5 * time.Second
)

var (
	ErrRuntimeTrustInvalid       = errors.New("runtime trust evidence is invalid")
	ErrRuntimeTrustLeaseExpired  = errors.New("runtime trust lease expired")
	ErrRuntimeTrustRollback      = errors.New("runtime trust lease rollback detected")
	ErrRuntimeTrustRevokeRequired = errors.New("runtime trust requires revocation")
)

type RuntimeTrustLease struct {
	Version                string    `json:"version"`
	LeaseID                string    `json:"lease_id"`
	LeaseEpoch             uint64    `json:"lease_epoch"`
	DeviceID               string    `json:"device_id"`
	WorkloadID             string    `json:"workload_id"`
	Generation             uint64    `json:"generation"`
	LifecycleEpoch         uint64    `json:"lifecycle_epoch"`
	ActivationDigest       string    `json:"activation_digest"`
	WorkloadSpecDigest     string    `json:"workload_spec_digest"`
	TargetCgroup           string    `json:"target_cgroup"`
	TargetCgroupID         uint64    `json:"target_cgroup_id"`
	BootstrapDigest        string    `json:"bootstrap_digest"`
	PolicyDigest           string    `json:"policy_digest"`
	RemoteDecisionID       string    `json:"remote_decision_id"`
	RemoteDecisionDigest   string    `json:"remote_decision_digest"`
	RemoteVerifiedAt       time.Time `json:"remote_verified_at"`
	AuthorityID            string    `json:"authority_id"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}

type SignedRuntimeTrustLease struct {
	Lease     RuntimeTrustLease `json:"lease"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
}

type RuntimeTrustPolicy struct {
	LifecycleAuthorityKey    ed25519.PrivateKey
	LifecycleAuthorityID     string
	RemoteVerifierPublicKey  ed25519.PublicKey
	AdmissionIssuerPublicKey ed25519.PublicKey
	HostAttestorPublicKey    ed25519.PublicKey
	PolicyDigest             string
	MaxAttestationAge        time.Duration
	LeaseTTL                 time.Duration
	MaxClockSkew             time.Duration
	Now                      func() time.Time
}

func IssueRuntimeTrustLease(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	remote SignedRemoteAttestationDecision,
	previous *SignedRuntimeTrustLease,
	policy RuntimeTrustPolicy,
) (SignedRuntimeTrustLease, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if state.State != LifecycleStateRunning {
		return SignedRuntimeTrustLease{}, ErrRuntimeTrustInvalid
	}
	if len(policy.LifecycleAuthorityKey) != ed25519.PrivateKeySize ||
		len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize ||
		len(policy.AdmissionIssuerPublicKey) != ed25519.PublicKeySize ||
		len(policy.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedRuntimeTrustLease{}, errors.New("runtime trust policy trust roots are incomplete")
	}
	authorityID := strings.TrimSpace(policy.LifecycleAuthorityID)
	if authorityID == "" {
		return SignedRuntimeTrustLease{}, errors.New("runtime trust lifecycle authority id is required")
	}
	if _, err := ParseSHA256Digest(policy.PolicyDigest); err != nil {
		return SignedRuntimeTrustLease{}, fmt.Errorf("runtime trust policy digest: %w", err)
	}
	if err := VerifySignedWorkloadAdmissionGrant(
		priorGrant,
		policy.AdmissionIssuerPublicKey,
		activation.Receipt.StartedAt,
	); err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if err := VerifySignedWorkloadActivationReceipt(
		activation,
		policy.HostAttestorPublicKey,
	); err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if err := VerifySignedRemoteAttestationDecision(
		remote,
		policy.RemoteVerifierPublicKey,
	); err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if remote.Decision.Decision != "ALLOW" {
		return SignedRuntimeTrustLease{}, ErrRuntimeTrustRevokeRequired
	}

	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	grantDigest, err := SignedWorkloadAdmissionGrantDigest(priorGrant)
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	remoteDigest, err := SignedRemoteAttestationDecisionDigest(remote)
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.Generation == 0 ||
		state.ActivationDigest != activationDigest ||
		activation.Receipt.GrantID != priorGrant.Grant.GrantID ||
		activation.Receipt.GrantDigest != grantDigest ||
		activation.Receipt.DeviceID != priorGrant.Grant.DeviceID ||
		activation.Receipt.WorkloadID != priorGrant.Grant.WorkloadID ||
		activation.Receipt.WorkloadSpecDigest != priorGrant.Grant.WorkloadSpecDigest ||
		activation.Receipt.TargetCgroupID != priorGrant.Grant.TargetCgroupID ||
		remote.Decision.DeviceID != state.DeviceID ||
		remote.Decision.BootstrapDigest != priorGrant.Grant.BootstrapDigest {
		return SignedRuntimeTrustLease{}, ErrLifecycleInvalidLineage
	}
	if filepath.Clean(activation.Receipt.TargetCgroup) != filepath.Clean(priorGrant.Grant.TargetCgroup) {
		return SignedRuntimeTrustLease{}, ErrLifecycleInvalidLineage
	}

	skew := policy.MaxClockSkew
	if skew <= 0 {
		skew = DefaultRuntimeClockSkew
	}
	verifiedAt := remote.Decision.VerifiedAt.UTC()
	if verifiedAt.IsZero() || verifiedAt.After(now.Add(skew)) {
		return SignedRuntimeTrustLease{}, ErrRuntimeTrustInvalid
	}
	maxAge := policy.MaxAttestationAge
	if maxAge <= 0 {
		maxAge = DefaultRuntimeTrustMaxAge
	}
	attestationDeadline := verifiedAt.Add(maxAge)
	if !now.Before(attestationDeadline) {
		return SignedRuntimeTrustLease{}, ErrAdmissionRemoteDecisionStale
	}
	ttl := policy.LeaseTTL
	if ttl <= 0 {
		ttl = DefaultRuntimeTrustLeaseTTL
	}
	expiresAt := now.Add(ttl)
	if expiresAt.After(attestationDeadline) {
		expiresAt = attestationDeadline
	}
	if !expiresAt.After(now) {
		return SignedRuntimeTrustLease{}, ErrRuntimeTrustLeaseExpired
	}

	leaseEpoch := uint64(1)
	if previous != nil {
		lifecyclePub := policy.LifecycleAuthorityKey.Public().(ed25519.PublicKey)
		if err := VerifySignedRuntimeTrustLease(*previous, lifecyclePub, now); err != nil {
			return SignedRuntimeTrustLease{}, err
		}
		prev := previous.Lease
		prevDigest, err := SignedRuntimeTrustLeaseDigest(*previous)
		if err != nil {
			return SignedRuntimeTrustLease{}, err
		}
		if state.RuntimeTrustEpoch == 0 ||
			state.RuntimeTrustEpoch != prev.LeaseEpoch ||
			state.RuntimeTrustLeaseDigest != prevDigest ||
			prev.DeviceID != state.DeviceID ||
			prev.WorkloadID != state.WorkloadID ||
			prev.Generation != state.Generation ||
			prev.LifecycleEpoch != EffectiveLifecycleEpoch(state) ||
			prev.ActivationDigest != activationDigest ||
			prev.PolicyDigest != policy.PolicyDigest ||
			prev.BootstrapDigest != priorGrant.Grant.BootstrapDigest {
			return SignedRuntimeTrustLease{}, ErrRuntimeTrustRollback
		}
		if prev.LeaseEpoch == ^uint64(0) {
			return SignedRuntimeTrustLease{}, errors.New("runtime trust lease epoch exhausted")
		}
		if !verifiedAt.After(prev.RemoteVerifiedAt.UTC()) ||
			remoteDigest == prev.RemoteDecisionDigest {
			return SignedRuntimeTrustLease{}, errors.New("runtime trust renewal requires newer remote attestation evidence")
		}
		leaseEpoch = prev.LeaseEpoch + 1
	} else if state.RuntimeTrustEpoch != 0 || state.RuntimeTrustLeaseDigest != "" {
		return SignedRuntimeTrustLease{}, ErrRuntimeTrustRollback
	}

	leaseID, err := randomToken(24)
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	lease := RuntimeTrustLease{
		Version:              RuntimeTrustLeaseVersion,
		LeaseID:              leaseID,
		LeaseEpoch:           leaseEpoch,
		DeviceID:             state.DeviceID,
		WorkloadID:           state.WorkloadID,
		Generation:           state.Generation,
		LifecycleEpoch:       EffectiveLifecycleEpoch(state),
		ActivationDigest:     activationDigest,
		WorkloadSpecDigest:   activation.Receipt.WorkloadSpecDigest,
		TargetCgroup:         filepath.Clean(activation.Receipt.TargetCgroup),
		TargetCgroupID:       activation.Receipt.TargetCgroupID,
		BootstrapDigest:      priorGrant.Grant.BootstrapDigest,
		PolicyDigest:         policy.PolicyDigest,
		RemoteDecisionID:     remote.Decision.DecisionID,
		RemoteDecisionDigest: remoteDigest,
		RemoteVerifiedAt:     verifiedAt,
		AuthorityID:          authorityID,
		IssuedAt:             now,
		ExpiresAt:            expiresAt,
	}
	return SignRuntimeTrustLease(lease, policy.LifecycleAuthorityKey)
}

func ValidateRuntimeTrustLease(lease RuntimeTrustLease, now time.Time) error {
	if lease.Version != RuntimeTrustLeaseVersion ||
		strings.TrimSpace(lease.LeaseID) == "" ||
		lease.LeaseEpoch == 0 ||
		strings.TrimSpace(lease.DeviceID) == "" ||
		strings.TrimSpace(lease.WorkloadID) == "" ||
		lease.Generation == 0 ||
		lease.LifecycleEpoch == 0 ||
		lease.TargetCgroupID == 0 ||
		strings.TrimSpace(lease.RemoteDecisionID) == "" ||
		strings.TrimSpace(lease.AuthorityID) == "" ||
		lease.RemoteVerifiedAt.IsZero() ||
		lease.IssuedAt.IsZero() ||
		lease.ExpiresAt.IsZero() ||
		!lease.ExpiresAt.After(lease.IssuedAt) {
		return ErrRuntimeTrustInvalid
	}
	for field, digest := range map[string]string{
		"activation_digest":      lease.ActivationDigest,
		"workload_spec_digest":   lease.WorkloadSpecDigest,
		"bootstrap_digest":       lease.BootstrapDigest,
		"policy_digest":          lease.PolicyDigest,
		"remote_decision_digest": lease.RemoteDecisionDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if filepath.Clean(lease.TargetCgroup) != lease.TargetCgroup ||
		!filepath.IsAbs(lease.TargetCgroup) {
		return errors.New("runtime trust target cgroup must be a clean absolute path")
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(lease.IssuedAt.UTC()) {
			return errors.New("runtime trust lease is not yet valid")
		}
		if !now.Before(lease.ExpiresAt.UTC()) {
			return ErrRuntimeTrustLeaseExpired
		}
	}
	return nil
}

func SignRuntimeTrustLease(
	lease RuntimeTrustLease,
	privateKey ed25519.PrivateKey,
) (SignedRuntimeTrustLease, error) {
	if err := ValidateRuntimeTrustLease(lease, time.Time{}); err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedRuntimeTrustLease{}, errors.New("runtime trust authority private key is invalid")
	}
	payload, err := canonicalRuntimeTrustLeasePayload(lease)
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRuntimeTrustLease{}, err
	}
	return SignedRuntimeTrustLease{
		Lease:     lease,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedRuntimeTrustLease(
	signed SignedRuntimeTrustLease,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("runtime trust authority public key is invalid")
	}
	if err := ValidateRuntimeTrustLease(signed.Lease, now); err != nil {
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
	payload, err := canonicalRuntimeTrustLeasePayload(signed.Lease)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedRuntimeTrustLeaseDigest(signed SignedRuntimeTrustLease) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed runtime trust lease is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-runtime-trust-lease/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalRuntimeTrustLeasePayload(lease RuntimeTrustLease) ([]byte, error) {
	normalized := lease
	normalized.TargetCgroup = filepath.Clean(lease.TargetCgroup)
	normalized.RemoteVerifiedAt = normalized.RemoteVerifiedAt.UTC()
	normalized.IssuedAt = normalized.IssuedAt.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/runtime-trust-lease/v1\x00"), body...), nil
}

type RuntimeTrustDecision struct {
	Version               string    `json:"version"`
	DecisionID            string    `json:"decision_id"`
	DeviceID              string    `json:"device_id"`
	WorkloadID            string    `json:"workload_id"`
	Generation            uint64    `json:"generation"`
	LifecycleEpoch        uint64    `json:"lifecycle_epoch"`
	ActivationDigest      string    `json:"activation_digest"`
	RuntimeLeaseDigest    string    `json:"runtime_lease_digest"`
	RuntimeLeaseEpoch     uint64    `json:"runtime_lease_epoch"`
	PolicyDigest          string    `json:"policy_digest"`
	RemoteDecisionDigest  string    `json:"remote_decision_digest,omitempty"`
	TargetCgroup          string    `json:"target_cgroup"`
	TargetCgroupID        uint64    `json:"target_cgroup_id"`
	Outcome               string    `json:"outcome"`
	ReasonCodes           []string  `json:"reason_codes,omitempty"`
	DecidedAt             time.Time `json:"decided_at"`
	AuthorityID           string    `json:"authority_id"`
}

type SignedRuntimeTrustDecision struct {
	Decision  RuntimeTrustDecision `json:"decision"`
	KeyID     string               `json:"key_id"`
	Signature string               `json:"signature"`
}

type RuntimeTrustEvaluationPolicy struct {
	LifecycleAuthorityKey   ed25519.PrivateKey
	LifecycleAuthorityID    string
	RemoteVerifierPublicKey ed25519.PublicKey
	HostAttestorPublicKey   ed25519.PublicKey
	PolicyDigest            string
	Now                     func() time.Time
}

func EvaluateRuntimeTrust(
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	lease SignedRuntimeTrustLease,
	currentRemote *SignedRemoteAttestationDecision,
	policy RuntimeTrustEvaluationPolicy,
) (SignedRuntimeTrustDecision, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	if state.State != LifecycleStateRunning ||
		state.RuntimeTrustEpoch == 0 ||
		state.RuntimeTrustLeaseDigest == "" {
		return SignedRuntimeTrustDecision{}, ErrRuntimeTrustInvalid
	}
	if len(policy.LifecycleAuthorityKey) != ed25519.PrivateKeySize ||
		len(policy.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedRuntimeTrustDecision{}, errors.New("runtime trust evaluation keys are incomplete")
	}
	if _, err := ParseSHA256Digest(policy.PolicyDigest); err != nil {
		return SignedRuntimeTrustDecision{}, fmt.Errorf("runtime trust evaluation policy digest: %w", err)
	}
	lifecyclePub := policy.LifecycleAuthorityKey.Public().(ed25519.PublicKey)
	if err := VerifySignedWorkloadActivationReceipt(
		activation,
		policy.HostAttestorPublicKey,
	); err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	if err := VerifySignedRuntimeTrustLease(lease, lifecyclePub, time.Time{}); err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	leaseValidationErr := ValidateRuntimeTrustLease(lease.Lease, now)
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	leaseDigest, err := SignedRuntimeTrustLeaseDigest(lease)
	if err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	if lease.Lease.DeviceID != state.DeviceID ||
		lease.Lease.WorkloadID != state.WorkloadID ||
		lease.Lease.Generation != state.Generation ||
		lease.Lease.LifecycleEpoch != EffectiveLifecycleEpoch(state) ||
		lease.Lease.ActivationDigest != activationDigest ||
		lease.Lease.WorkloadSpecDigest != activation.Receipt.WorkloadSpecDigest ||
		lease.Lease.TargetCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(lease.Lease.TargetCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) ||
		state.ActivationDigest != activationDigest ||
		state.RuntimeTrustEpoch != lease.Lease.LeaseEpoch ||
		state.RuntimeTrustLeaseDigest != leaseDigest {
		return SignedRuntimeTrustDecision{}, ErrRuntimeTrustRollback
	}

	outcome := RuntimeTrustKeepRunning
	reasons := []string{"RUNTIME_TRUST_LEASE_VALID"}
	if leaseValidationErr != nil {
		if errors.Is(leaseValidationErr, ErrRuntimeTrustLeaseExpired) {
			outcome = RuntimeTrustRevoke
			reasons = []string{"RUNTIME_TRUST_LEASE_EXPIRED"}
		} else {
			return SignedRuntimeTrustDecision{}, leaseValidationErr
		}
	}
	if lease.Lease.PolicyDigest != policy.PolicyDigest {
		outcome = RuntimeTrustRevoke
		reasons = []string{"RUNTIME_POLICY_SUPERSEDED"}
	}

	remoteDigest := ""
	if currentRemote != nil {
		if len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize {
			return SignedRuntimeTrustDecision{}, errors.New("remote verifier public key is required when runtime remote evidence is supplied")
		}
		if err := VerifySignedRemoteAttestationDecision(*currentRemote, policy.RemoteVerifierPublicKey); err != nil {
			return SignedRuntimeTrustDecision{}, err
		}
		remoteDigest, err = SignedRemoteAttestationDecisionDigest(*currentRemote)
		if err != nil {
			return SignedRuntimeTrustDecision{}, err
		}
		if currentRemote.Decision.DeviceID != state.DeviceID ||
			currentRemote.Decision.BootstrapDigest != lease.Lease.BootstrapDigest {
			outcome = RuntimeTrustRevoke
			reasons = []string{"RUNTIME_REMOTE_IDENTITY_CHANGED"}
		} else if currentRemote.Decision.Decision != "ALLOW" {
			outcome = RuntimeTrustRevoke
			reasons = append([]string{"RUNTIME_REMOTE_BLOCK"}, currentRemote.Decision.ReasonCodes...)
		} else if outcome == RuntimeTrustKeepRunning &&
			currentRemote.Decision.VerifiedAt.UTC().After(lease.Lease.RemoteVerifiedAt.UTC()) &&
			remoteDigest != lease.Lease.RemoteDecisionDigest {
			outcome = RuntimeTrustRenewRequired
			reasons = []string{"NEWER_REMOTE_EVIDENCE_AVAILABLE"}
		}
	}

	decisionID, err := randomToken(24)
	if err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	authorityID := strings.TrimSpace(policy.LifecycleAuthorityID)
	if authorityID == "" {
		return SignedRuntimeTrustDecision{}, errors.New("runtime trust lifecycle authority id is required")
	}
	decision := RuntimeTrustDecision{
		Version:              RuntimeTrustDecisionVersion,
		DecisionID:           decisionID,
		DeviceID:             state.DeviceID,
		WorkloadID:           state.WorkloadID,
		Generation:           state.Generation,
		LifecycleEpoch:       EffectiveLifecycleEpoch(state),
		ActivationDigest:     activationDigest,
		RuntimeLeaseDigest:   leaseDigest,
		RuntimeLeaseEpoch:    lease.Lease.LeaseEpoch,
		PolicyDigest:         policy.PolicyDigest,
		RemoteDecisionDigest: remoteDigest,
		TargetCgroup:         filepath.Clean(activation.Receipt.TargetCgroup),
		TargetCgroupID:       activation.Receipt.TargetCgroupID,
		Outcome:              outcome,
		ReasonCodes:          reasons,
		DecidedAt:            now,
		AuthorityID:          authorityID,
	}
	return SignRuntimeTrustDecision(decision, policy.LifecycleAuthorityKey)
}

func ValidateRuntimeTrustDecision(decision RuntimeTrustDecision) error {
	if decision.Version != RuntimeTrustDecisionVersion ||
		strings.TrimSpace(decision.DecisionID) == "" ||
		strings.TrimSpace(decision.DeviceID) == "" ||
		strings.TrimSpace(decision.WorkloadID) == "" ||
		decision.Generation == 0 ||
		decision.LifecycleEpoch == 0 ||
		decision.RuntimeLeaseEpoch == 0 ||
		decision.TargetCgroupID == 0 ||
		decision.DecidedAt.IsZero() ||
		strings.TrimSpace(decision.AuthorityID) == "" {
		return errors.New("runtime trust decision is incomplete")
	}
	for field, digest := range map[string]string{
		"activation_digest":    decision.ActivationDigest,
		"runtime_lease_digest": decision.RuntimeLeaseDigest,
		"policy_digest":        decision.PolicyDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if decision.RemoteDecisionDigest != "" {
		if _, err := ParseSHA256Digest(decision.RemoteDecisionDigest); err != nil {
			return fmt.Errorf("remote_decision_digest: %w", err)
		}
	}
	if filepath.Clean(decision.TargetCgroup) != decision.TargetCgroup ||
		!filepath.IsAbs(decision.TargetCgroup) {
		return errors.New("runtime trust decision target cgroup must be a clean absolute path")
	}
	switch decision.Outcome {
	case RuntimeTrustKeepRunning, RuntimeTrustRenewRequired, RuntimeTrustRevoke:
	default:
		return fmt.Errorf("unsupported runtime trust outcome %q", decision.Outcome)
	}
	return nil
}

func SignRuntimeTrustDecision(
	decision RuntimeTrustDecision,
	privateKey ed25519.PrivateKey,
) (SignedRuntimeTrustDecision, error) {
	if err := ValidateRuntimeTrustDecision(decision); err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedRuntimeTrustDecision{}, errors.New("runtime trust authority private key is invalid")
	}
	payload, err := canonicalRuntimeTrustDecisionPayload(decision)
	if err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRuntimeTrustDecision{}, err
	}
	return SignedRuntimeTrustDecision{
		Decision:  decision,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedRuntimeTrustDecision(
	signed SignedRuntimeTrustDecision,
	publicKey ed25519.PublicKey,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("runtime trust authority public key is invalid")
	}
	if err := ValidateRuntimeTrustDecision(signed.Decision); err != nil {
		return err
	}
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return ErrBootstrapSignatureInvalid
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalRuntimeTrustDecisionPayload(signed.Decision)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedRuntimeTrustDecisionDigest(
	signed SignedRuntimeTrustDecision,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed runtime trust decision is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-runtime-trust-decision/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalRuntimeTrustDecisionPayload(
	decision RuntimeTrustDecision,
) ([]byte, error) {
	normalized := decision
	normalized.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	normalized.TargetCgroup = filepath.Clean(normalized.TargetCgroup)
	normalized.DecidedAt = normalized.DecidedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/runtime-trust-decision/v1\x00"), body...), nil
}


func EvaluateRuntimeTrustReconciliation(
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	observation SignedWorkloadRecoveryObservation,
	runtimeDecision SignedRuntimeTrustDecision,
	hostAttestorPublicKey ed25519.PublicKey,
	lifecycleAuthorityKey ed25519.PrivateKey,
	lifecycleAuthorityID string,
	now time.Time,
) (SignedWorkloadReconciliationDecision, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if state.State != LifecycleStateRunning {
		return SignedWorkloadReconciliationDecision{}, ErrReconciliationRejected
	}
	if len(lifecycleAuthorityKey) != ed25519.PrivateKeySize ||
		len(hostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedWorkloadReconciliationDecision{}, errors.New("runtime trust reconciliation keys are incomplete")
	}
	lifecycleAuthorityID = strings.TrimSpace(lifecycleAuthorityID)
	if lifecycleAuthorityID == "" {
		return SignedWorkloadReconciliationDecision{}, errors.New("lifecycle authority id is required")
	}
	lifecyclePub := lifecycleAuthorityKey.Public().(ed25519.PublicKey)
	if err := VerifySignedRuntimeTrustDecision(runtimeDecision, lifecyclePub); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if runtimeDecision.Decision.Outcome != RuntimeTrustRevoke {
		return SignedWorkloadReconciliationDecision{}, ErrRuntimeTrustRevokeRequired
	}
	if err := VerifySignedWorkloadActivationReceipt(
		activation,
		hostAttestorPublicKey,
	); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if err := VerifySignedWorkloadRecoveryObservation(
		observation,
		hostAttestorPublicKey,
	); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}

	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	runtimeDigest, err := SignedRuntimeTrustDecisionDigest(runtimeDecision)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	observationDigest, err := SignedWorkloadRecoveryObservationDigest(observation)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}

	d := runtimeDecision.Decision
	obs := observation.Observation
	if d.DeviceID != state.DeviceID ||
		d.WorkloadID != state.WorkloadID ||
		d.Generation != state.Generation ||
		d.LifecycleEpoch != EffectiveLifecycleEpoch(state) ||
		d.ActivationDigest != activationDigest ||
		d.RuntimeLeaseEpoch != state.RuntimeTrustEpoch ||
		d.RuntimeLeaseDigest != state.RuntimeTrustLeaseDigest ||
		d.TargetCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(d.TargetCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) ||
		state.ActivationDigest != activationDigest ||
		obs.State != RecoveryObservationRuntimeTrustRevoked ||
		obs.RuntimeTrustDecisionDigest != runtimeDigest ||
		obs.DeviceID != state.DeviceID ||
		obs.WorkloadID != state.WorkloadID ||
		obs.Generation != state.Generation ||
		obs.ActivationID != activation.Receipt.ActivationID ||
		obs.ActivationDigest != activationDigest ||
		obs.ProcessID != activation.Receipt.ProcessID ||
		obs.ExpectedCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(obs.ExpectedCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) ||
		obs.ObservedCgroupID != activation.Receipt.TargetCgroupID ||
		filepath.Clean(obs.ObservedCgroup) != filepath.Clean(activation.Receipt.TargetCgroup) ||
		obs.ObservedAt.UTC().Before(d.DecidedAt.UTC()) {
		return SignedWorkloadReconciliationDecision{}, ErrLifecycleInvalidLineage
	}
	if activation.Receipt.Version != WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil ||
		obs.ExpectedProcessIdentity == nil ||
		obs.ObservedProcessIdentity == nil ||
		*obs.ExpectedProcessIdentity != *activation.Receipt.ProcessIdentity ||
		*obs.ObservedProcessIdentity != *activation.Receipt.ProcessIdentity {
		return SignedWorkloadReconciliationDecision{}, ErrLifecycleInvalidLineage
	}

	decisionID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	decision := WorkloadReconciliationDecision{
		Version:           WorkloadReconciliationDecisionVersion,
		DecisionID:        decisionID,
		DeviceID:          state.DeviceID,
		WorkloadID:        state.WorkloadID,
		Generation:        state.Generation,
		ActivationDigest:  activationDigest,
		ObservationDigest: observationDigest,
		Outcome:           ReconciliationQuarantine,
		ReasonCodes: []string{
			"RUNTIME_TRUST_REVOKED",
			"KERNEL_NETWORK_SCOPE_REVOKED",
		},
		ObservedAt:  obs.ObservedAt.UTC(),
		DecidedAt:   now.UTC(),
		AuthorityID: lifecycleAuthorityID,
	}
	return SignWorkloadReconciliationDecision(decision, lifecycleAuthorityKey)
}
