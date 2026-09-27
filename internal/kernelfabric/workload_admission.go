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
	WorkloadAdmissionRequestVersion = "aegis.ege/workload-admission-request/v1"
	WorkloadAdmissionGrantVersion   = "aegis.ege/workload-admission-grant/v1"
	WorkloadActivationReceiptVersion = "aegis.ege/workload-activation-receipt/v1"

	DefaultAdmissionAttestationMaxAge = 2 * time.Minute
	DefaultAdmissionGrantTTL          = 30 * time.Second
	DefaultAdmissionClockSkew         = 5 * time.Second
)

var (
	ErrAdmissionRemoteDecisionRejected = errors.New("remote attestation decision does not authorize workload admission")
	ErrAdmissionRemoteDecisionStale    = errors.New("remote attestation decision is stale")
	ErrAdmissionBindingMismatch        = errors.New("workload admission binding mismatch")
	ErrAdmissionGrantExpired           = errors.New("workload admission grant expired")
	ErrAdmissionGrantReplay            = errors.New("workload admission grant already consumed")
)

type WorkloadEnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WorkloadLaunchSpec struct {
	Executable  string                        `json:"executable"`
	Args        []string                      `json:"args,omitempty"`
	WorkingDir  string                        `json:"working_dir,omitempty"`
	Environment []WorkloadEnvironmentVariable `json:"environment,omitempty"`
}

func (s WorkloadLaunchSpec) Validate() error {
	executable := filepath.Clean(strings.TrimSpace(s.Executable))
	if executable == "." || !filepath.IsAbs(executable) {
		return errors.New("workload executable must be an absolute path")
	}
	if s.WorkingDir != "" {
		workingDir := filepath.Clean(strings.TrimSpace(s.WorkingDir))
		if workingDir == "." || !filepath.IsAbs(workingDir) {
			return errors.New("workload working_dir must be absolute when set")
		}
	}
	seen := map[string]struct{}{}
	for _, env := range s.Environment {
		name := strings.TrimSpace(env.Name)
		if name == "" || strings.Contains(name, "=") {
			return fmt.Errorf("invalid workload environment variable name %q", env.Name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate workload environment variable %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func WorkloadLaunchSpecDigest(spec WorkloadLaunchSpec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	normalized := spec
	normalized.Executable = filepath.Clean(spec.Executable)
	if normalized.WorkingDir != "" {
		normalized.WorkingDir = filepath.Clean(normalized.WorkingDir)
	}
	normalized.Args = append([]string(nil), spec.Args...)
	normalized.Environment = append([]WorkloadEnvironmentVariable(nil), spec.Environment...)
	sort.Slice(normalized.Environment, func(i, j int) bool {
		if normalized.Environment[i].Name != normalized.Environment[j].Name {
			return normalized.Environment[i].Name < normalized.Environment[j].Name
		}
		return normalized.Environment[i].Value < normalized.Environment[j].Value
	})
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal workload launch spec: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/workload-launch-spec/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type WorkloadAdmissionRequest struct {
	Version            string    `json:"version"`
	RequestID          string    `json:"request_id"`
	DeviceID           string    `json:"device_id"`
	WorkloadID         string    `json:"workload_id"`
	WorkloadSpecDigest string    `json:"workload_spec_digest"`
	TargetCgroup       string    `json:"target_cgroup"`
	TargetCgroupID     uint64    `json:"target_cgroup_id"`
	BootstrapDigest    string    `json:"bootstrap_digest"`
	RequestedAt        time.Time `json:"requested_at"`
}

func NewWorkloadAdmissionRequest(
	deviceID string,
	workloadID string,
	spec WorkloadLaunchSpec,
	targetCgroup string,
	targetCgroupID uint64,
	bootstrapDigest string,
	now time.Time,
) (WorkloadAdmissionRequest, error) {
	deviceID = strings.TrimSpace(deviceID)
	workloadID = strings.TrimSpace(workloadID)
	targetCgroup = filepath.Clean(strings.TrimSpace(targetCgroup))
	if deviceID == "" || workloadID == "" {
		return WorkloadAdmissionRequest{}, errors.New("device_id and workload_id are required")
	}
	if targetCgroup == "." || !filepath.IsAbs(targetCgroup) {
		return WorkloadAdmissionRequest{}, errors.New("target_cgroup must be an absolute path")
	}
	if targetCgroupID == 0 {
		return WorkloadAdmissionRequest{}, errors.New("target_cgroup_id must be non-zero")
	}
	if _, err := ParseSHA256Digest(bootstrapDigest); err != nil {
		return WorkloadAdmissionRequest{}, fmt.Errorf("bootstrap digest: %w", err)
	}
	specDigest, err := WorkloadLaunchSpecDigest(spec)
	if err != nil {
		return WorkloadAdmissionRequest{}, err
	}
	requestID, err := randomToken(24)
	if err != nil {
		return WorkloadAdmissionRequest{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return WorkloadAdmissionRequest{
		Version:            WorkloadAdmissionRequestVersion,
		RequestID:          requestID,
		DeviceID:           deviceID,
		WorkloadID:         workloadID,
		WorkloadSpecDigest: specDigest,
		TargetCgroup:       targetCgroup,
		TargetCgroupID:     targetCgroupID,
		BootstrapDigest:    bootstrapDigest,
		RequestedAt:        now.UTC(),
	}, nil
}

func ValidateWorkloadAdmissionRequest(req WorkloadAdmissionRequest) error {
	if req.Version != WorkloadAdmissionRequestVersion {
		return fmt.Errorf("unsupported workload admission request version %q", req.Version)
	}
	if strings.TrimSpace(req.RequestID) == "" ||
		strings.TrimSpace(req.DeviceID) == "" ||
		strings.TrimSpace(req.WorkloadID) == "" {
		return errors.New("workload admission request identity fields are required")
	}
	if _, err := ParseSHA256Digest(req.WorkloadSpecDigest); err != nil {
		return fmt.Errorf("workload spec digest: %w", err)
	}
	if _, err := ParseSHA256Digest(req.BootstrapDigest); err != nil {
		return fmt.Errorf("bootstrap digest: %w", err)
	}
	cgroup := filepath.Clean(strings.TrimSpace(req.TargetCgroup))
	if cgroup == "." || !filepath.IsAbs(cgroup) {
		return errors.New("workload admission target_cgroup must be absolute")
	}
	if req.TargetCgroupID == 0 {
		return errors.New("workload admission target_cgroup_id must be non-zero")
	}
	if req.RequestedAt.IsZero() {
		return errors.New("workload admission requested_at is required")
	}
	return nil
}

type WorkloadAdmissionPolicy struct {
	RemoteVerifierPublicKey ed25519.PublicKey
	AdmissionIssuerKey      ed25519.PrivateKey
	AdmissionIssuerID       string
	MaxAttestationAge       time.Duration
	GrantTTL                time.Duration
	MaxClockSkew            time.Duration
	Now                     func() time.Time
}

type WorkloadAdmissionGrant struct {
	Version              string    `json:"version"`
	GrantID              string    `json:"grant_id"`
	RequestID            string    `json:"request_id"`
	DeviceID             string    `json:"device_id"`
	WorkloadID           string    `json:"workload_id"`
	WorkloadSpecDigest   string    `json:"workload_spec_digest"`
	TargetCgroup         string    `json:"target_cgroup"`
	TargetCgroupID       uint64    `json:"target_cgroup_id"`
	BootstrapDigest      string    `json:"bootstrap_digest"`
	RemoteDecisionID     string    `json:"remote_decision_id"`
	RemoteDecisionDigest string    `json:"remote_decision_digest"`
	IssuerID             string    `json:"issuer_id"`
	NotBefore            time.Time `json:"not_before"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type SignedWorkloadAdmissionGrant struct {
	Grant     WorkloadAdmissionGrant `json:"grant"`
	KeyID     string                 `json:"key_id"`
	Signature string                 `json:"signature"`
}

func IssueWorkloadAdmissionGrant(
	req WorkloadAdmissionRequest,
	decision SignedRemoteAttestationDecision,
	policy WorkloadAdmissionPolicy,
) (SignedWorkloadAdmissionGrant, error) {
	if err := ValidateWorkloadAdmissionRequest(req); err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	if len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize {
		return SignedWorkloadAdmissionGrant{}, errors.New("trusted remote verifier public key is required")
	}
	if len(policy.AdmissionIssuerKey) != ed25519.PrivateKeySize {
		return SignedWorkloadAdmissionGrant{}, errors.New("admission issuer private key is required")
	}
	issuerID := strings.TrimSpace(policy.AdmissionIssuerID)
	if issuerID == "" {
		return SignedWorkloadAdmissionGrant{}, errors.New("admission issuer id is required")
	}
	if err := VerifySignedRemoteAttestationDecision(decision, policy.RemoteVerifierPublicKey); err != nil {
		return SignedWorkloadAdmissionGrant{}, fmt.Errorf("%w: %v", ErrAdmissionRemoteDecisionRejected, err)
	}
	if decision.Decision.Decision != "ALLOW" {
		return SignedWorkloadAdmissionGrant{}, ErrAdmissionRemoteDecisionRejected
	}
	if decision.Decision.DeviceID != req.DeviceID ||
		decision.Decision.BootstrapDigest != req.BootstrapDigest {
		return SignedWorkloadAdmissionGrant{}, ErrAdmissionBindingMismatch
	}

	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	maxAge := policy.MaxAttestationAge
	if maxAge <= 0 {
		maxAge = DefaultAdmissionAttestationMaxAge
	}
	grantTTL := policy.GrantTTL
	if grantTTL <= 0 {
		grantTTL = DefaultAdmissionGrantTTL
	}
	skew := policy.MaxClockSkew
	if skew <= 0 {
		skew = DefaultAdmissionClockSkew
	}
	verifiedAt := decision.Decision.VerifiedAt.UTC()
	if verifiedAt.IsZero() {
		return SignedWorkloadAdmissionGrant{}, ErrAdmissionRemoteDecisionRejected
	}
	if verifiedAt.After(now.Add(skew)) {
		return SignedWorkloadAdmissionGrant{}, fmt.Errorf("%w: verifier timestamp is in the future", ErrAdmissionRemoteDecisionStale)
	}
	attestationDeadline := verifiedAt.Add(maxAge)
	if !now.Before(attestationDeadline) {
		return SignedWorkloadAdmissionGrant{}, ErrAdmissionRemoteDecisionStale
	}
	expiresAt := now.Add(grantTTL)
	if expiresAt.After(attestationDeadline) {
		expiresAt = attestationDeadline
	}
	if !expiresAt.After(now) {
		return SignedWorkloadAdmissionGrant{}, ErrAdmissionRemoteDecisionStale
	}

	decisionDigest, err := SignedRemoteAttestationDecisionDigest(decision)
	if err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	grantID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	grant := WorkloadAdmissionGrant{
		Version:              WorkloadAdmissionGrantVersion,
		GrantID:              grantID,
		RequestID:            req.RequestID,
		DeviceID:             req.DeviceID,
		WorkloadID:           req.WorkloadID,
		WorkloadSpecDigest:   req.WorkloadSpecDigest,
		TargetCgroup:         filepath.Clean(req.TargetCgroup),
		TargetCgroupID:       req.TargetCgroupID,
		BootstrapDigest:      req.BootstrapDigest,
		RemoteDecisionID:     decision.Decision.DecisionID,
		RemoteDecisionDigest: decisionDigest,
		IssuerID:             issuerID,
		NotBefore:            now,
		ExpiresAt:            expiresAt,
	}
	return SignWorkloadAdmissionGrant(grant, policy.AdmissionIssuerKey)
}

func SignedRemoteAttestationDecisionDigest(decision SignedRemoteAttestationDecision) (string, error) {
	if strings.TrimSpace(decision.Signature) == "" || strings.TrimSpace(decision.KeyID) == "" {
		return "", errors.New("signed remote attestation decision is incomplete")
	}
	body, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("marshal signed remote decision: %w", err)
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-remote-attestation-decision/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignWorkloadAdmissionGrant(
	grant WorkloadAdmissionGrant,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadAdmissionGrant, error) {
	if err := ValidateWorkloadAdmissionGrant(grant, time.Time{}); err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadAdmissionGrant{}, errors.New("invalid admission issuer private key")
	}
	payload, err := canonicalWorkloadAdmissionGrantPayload(grant)
	if err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	return SignedWorkloadAdmissionGrant{
		Grant:     grant,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedWorkloadAdmissionGrant(
	signed SignedWorkloadAdmissionGrant,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("admission issuer public key is invalid")
	}
	if err := ValidateWorkloadAdmissionGrant(signed.Grant, now); err != nil {
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
	payload, err := canonicalWorkloadAdmissionGrantPayload(signed.Grant)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func ValidateWorkloadAdmissionGrant(grant WorkloadAdmissionGrant, now time.Time) error {
	if grant.Version != WorkloadAdmissionGrantVersion {
		return fmt.Errorf("unsupported workload admission grant version %q", grant.Version)
	}
	if strings.TrimSpace(grant.GrantID) == "" ||
		strings.TrimSpace(grant.RequestID) == "" ||
		strings.TrimSpace(grant.DeviceID) == "" ||
		strings.TrimSpace(grant.WorkloadID) == "" ||
		strings.TrimSpace(grant.RemoteDecisionID) == "" ||
		strings.TrimSpace(grant.IssuerID) == "" {
		return errors.New("workload admission grant identity fields are required")
	}
	for field, digest := range map[string]string{
		"workload_spec_digest":    grant.WorkloadSpecDigest,
		"bootstrap_digest":        grant.BootstrapDigest,
		"remote_decision_digest":  grant.RemoteDecisionDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	cgroup := filepath.Clean(strings.TrimSpace(grant.TargetCgroup))
	if cgroup == "." || !filepath.IsAbs(cgroup) {
		return errors.New("workload admission grant target_cgroup must be absolute")
	}
	if grant.TargetCgroupID == 0 {
		return errors.New("workload admission grant target_cgroup_id must be non-zero")
	}
	if grant.NotBefore.IsZero() || grant.ExpiresAt.IsZero() ||
		!grant.ExpiresAt.After(grant.NotBefore) {
		return errors.New("workload admission grant validity window is invalid")
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(grant.NotBefore.UTC()) {
			return errors.New("workload admission grant is not yet valid")
		}
		if !now.Before(grant.ExpiresAt.UTC()) {
			return ErrAdmissionGrantExpired
		}
	}
	return nil
}

func canonicalWorkloadAdmissionGrantPayload(grant WorkloadAdmissionGrant) ([]byte, error) {
	normalized := grant
	normalized.TargetCgroup = filepath.Clean(grant.TargetCgroup)
	normalized.NotBefore = grant.NotBefore.UTC()
	normalized.ExpiresAt = grant.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal workload admission grant: %w", err)
	}
	return append([]byte("aegis-ege/workload-admission-grant/v1\x00"), body...), nil
}

func SignedWorkloadAdmissionGrantDigest(grant SignedWorkloadAdmissionGrant) (string, error) {
	if strings.TrimSpace(grant.KeyID) == "" || strings.TrimSpace(grant.Signature) == "" {
		return "", errors.New("signed workload admission grant is incomplete")
	}
	body, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-workload-admission-grant/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type WorkloadActivationReceipt struct {
	Version          string    `json:"version"`
	ActivationID     string    `json:"activation_id"`
	GrantID          string    `json:"grant_id"`
	GrantDigest      string    `json:"grant_digest"`
	DeviceID         string    `json:"device_id"`
	WorkloadID       string    `json:"workload_id"`
	WorkloadSpecDigest string  `json:"workload_spec_digest"`
	TargetCgroup     string    `json:"target_cgroup"`
	TargetCgroupID   uint64    `json:"target_cgroup_id"`
	ProcessID        int       `json:"process_id"`
	StartedAt        time.Time `json:"started_at"`
}

type SignedWorkloadActivationReceipt struct {
	Receipt   WorkloadActivationReceipt `json:"receipt"`
	KeyID     string                    `json:"key_id"`
	Signature string                    `json:"signature"`
}

func SignWorkloadActivationReceipt(
	receipt WorkloadActivationReceipt,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadActivationReceipt, error) {
	if receipt.Version != WorkloadActivationReceiptVersion ||
		strings.TrimSpace(receipt.ActivationID) == "" ||
		strings.TrimSpace(receipt.GrantID) == "" ||
		receipt.TargetCgroupID == 0 ||
		receipt.ProcessID <= 0 ||
		receipt.StartedAt.IsZero() {
		return SignedWorkloadActivationReceipt{}, errors.New("workload activation receipt is incomplete")
	}
	if _, err := ParseSHA256Digest(receipt.GrantDigest); err != nil {
		return SignedWorkloadActivationReceipt{}, fmt.Errorf("grant digest: %w", err)
	}
	if _, err := ParseSHA256Digest(receipt.WorkloadSpecDigest); err != nil {
		return SignedWorkloadActivationReceipt{}, fmt.Errorf("workload spec digest: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadActivationReceipt{}, errors.New("host activation attestor private key is invalid")
	}
	normalized := receipt
	normalized.StartedAt = normalized.StartedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return SignedWorkloadActivationReceipt{}, err
	}
	payload := append([]byte("aegis-ege/workload-activation-receipt/v1\x00"), body...)
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadActivationReceipt{}, err
	}
	return SignedWorkloadActivationReceipt{
		Receipt:   normalized,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}
