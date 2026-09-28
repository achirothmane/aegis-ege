package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	WorkloadRecoveryObservationVersion    = "aegis.ege/workload-recovery-observation/v1"
	WorkloadReconciliationDecisionVersion = "aegis.ege/workload-reconciliation-decision/v1"

	RecoveryObservationMatchRunning  = "MATCH_RUNNING"
	RecoveryObservationAbsent        = "ABSENT"
	RecoveryObservationBootChanged   = "BOOT_CHANGED"
	RecoveryObservationPIDReused     = "PID_REUSED"
	RecoveryObservationCgroupMismatch = "CGROUP_MISMATCH"
	RecoveryObservationLegacy        = "LEGACY_UNVERIFIABLE"
	RecoveryObservationUnverifiable  = "UNVERIFIABLE"

	ReconciliationKeepRunning       = "KEEP_RUNNING"
	ReconciliationMarkExitedUnknown = "MARK_EXITED_UNKNOWN"
	ReconciliationQuarantine        = "QUARANTINE"
)

var (
	ErrRecoveryObservationInvalid = errors.New("workload recovery observation is invalid")
	ErrReconciliationRejected     = errors.New("workload reconciliation decision is rejected")
)

type WorkloadRecoveryObservation struct {
	Version                 string                `json:"version"`
	ObservationID           string                `json:"observation_id"`
	DeviceID                string                `json:"device_id"`
	WorkloadID              string                `json:"workload_id"`
	Generation              uint64                `json:"generation"`
	ActivationID            string                `json:"activation_id"`
	ActivationDigest        string                `json:"activation_digest"`
	ProcessID               int                   `json:"process_id"`
	ExpectedProcessIdentity *LinuxProcessIdentity `json:"expected_process_identity,omitempty"`
	ObservedProcessIdentity *LinuxProcessIdentity `json:"observed_process_identity,omitempty"`
	ExpectedCgroupID        uint64                `json:"expected_cgroup_id"`
	ObservedCgroupID        uint64                `json:"observed_cgroup_id,omitempty"`
	ObservedCgroup          string                `json:"observed_cgroup,omitempty"`
	State                   string                `json:"state"`
	Detail                  string                `json:"detail,omitempty"`
	ObservedAt              time.Time             `json:"observed_at"`
}

type SignedWorkloadRecoveryObservation struct {
	Observation WorkloadRecoveryObservation `json:"observation"`
	KeyID       string                      `json:"key_id"`
	Signature   string                      `json:"signature"`
}

func ValidateWorkloadRecoveryObservation(obs WorkloadRecoveryObservation) error {
	if obs.Version != WorkloadRecoveryObservationVersion ||
		strings.TrimSpace(obs.ObservationID) == "" ||
		strings.TrimSpace(obs.DeviceID) == "" ||
		strings.TrimSpace(obs.WorkloadID) == "" ||
		obs.Generation == 0 ||
		strings.TrimSpace(obs.ActivationID) == "" ||
		obs.ProcessID <= 0 ||
		obs.ExpectedCgroupID == 0 ||
		obs.ObservedAt.IsZero() {
		return ErrRecoveryObservationInvalid
	}
	if _, err := ParseSHA256Digest(obs.ActivationDigest); err != nil {
		return fmt.Errorf("%w: activation digest: %v", ErrRecoveryObservationInvalid, err)
	}
	if obs.ExpectedProcessIdentity != nil {
		if err := ValidateLinuxProcessIdentity(*obs.ExpectedProcessIdentity); err != nil {
			return fmt.Errorf("%w: expected process identity: %v", ErrRecoveryObservationInvalid, err)
		}
	}
	if obs.ObservedProcessIdentity != nil {
		if err := ValidateLinuxProcessIdentity(*obs.ObservedProcessIdentity); err != nil {
			return fmt.Errorf("%w: observed process identity: %v", ErrRecoveryObservationInvalid, err)
		}
	}
	switch obs.State {
	case RecoveryObservationMatchRunning:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity == nil ||
			obs.ObservedCgroupID == 0 {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationAbsent, RecoveryObservationBootChanged:
	case RecoveryObservationPIDReused:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity == nil {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationCgroupMismatch:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity == nil ||
			obs.ObservedCgroupID == 0 {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationLegacy, RecoveryObservationUnverifiable:
	default:
		return fmt.Errorf("%w: unsupported observation state %q", ErrRecoveryObservationInvalid, obs.State)
	}
	return nil
}

func SignWorkloadRecoveryObservation(
	obs WorkloadRecoveryObservation,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadRecoveryObservation, error) {
	if err := ValidateWorkloadRecoveryObservation(obs); err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadRecoveryObservation{}, errors.New("host recovery attestor private key is invalid")
	}
	payload, err := canonicalWorkloadRecoveryObservationPayload(obs)
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadRecoveryObservation{}, err
	}
	return SignedWorkloadRecoveryObservation{
		Observation: obs,
		KeyID: keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedWorkloadRecoveryObservation(
	signed SignedWorkloadRecoveryObservation,
	publicKey ed25519.PublicKey,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("host recovery attestor public key is invalid")
	}
	if err := ValidateWorkloadRecoveryObservation(signed.Observation); err != nil {
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
	payload, err := canonicalWorkloadRecoveryObservationPayload(signed.Observation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedWorkloadRecoveryObservationDigest(
	signed SignedWorkloadRecoveryObservation,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed workload recovery observation is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-workload-recovery-observation/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalWorkloadRecoveryObservationPayload(
	obs WorkloadRecoveryObservation,
) ([]byte, error) {
	normalized := obs
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/workload-recovery-observation/v1\x00"), body...), nil
}

type WorkloadReconciliationDecision struct {
	Version            string    `json:"version"`
	DecisionID         string    `json:"decision_id"`
	DeviceID           string    `json:"device_id"`
	WorkloadID         string    `json:"workload_id"`
	Generation         uint64    `json:"generation"`
	ActivationDigest   string    `json:"activation_digest"`
	ObservationDigest  string    `json:"observation_digest"`
	Outcome            string    `json:"outcome"`
	ReasonCodes        []string  `json:"reason_codes,omitempty"`
	ObservedAt         time.Time `json:"observed_at"`
	DecidedAt          time.Time `json:"decided_at"`
	AuthorityID        string    `json:"authority_id"`
}

type SignedWorkloadReconciliationDecision struct {
	Decision  WorkloadReconciliationDecision `json:"decision"`
	KeyID     string                         `json:"key_id"`
	Signature string                         `json:"signature"`
}

func EvaluateWorkloadReconciliation(
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	observation SignedWorkloadRecoveryObservation,
	hostAttestorPublicKey ed25519.PublicKey,
	lifecycleAuthorityKey ed25519.PrivateKey,
	lifecycleAuthorityID string,
	now time.Time,
) (SignedWorkloadReconciliationDecision, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if len(lifecycleAuthorityKey) != ed25519.PrivateKeySize {
		return SignedWorkloadReconciliationDecision{}, errors.New("lifecycle authority private key is required")
	}
	lifecycleAuthorityID = strings.TrimSpace(lifecycleAuthorityID)
	if lifecycleAuthorityID == "" {
		return SignedWorkloadReconciliationDecision{}, errors.New("lifecycle authority id is required")
	}
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if state.State != LifecycleStateRunning {
		return SignedWorkloadReconciliationDecision{}, ErrReconciliationRejected
	}
	if err := VerifySignedWorkloadActivationReceipt(activation, hostAttestorPublicKey); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if err := VerifySignedWorkloadRecoveryObservation(observation, hostAttestorPublicKey); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	obsDigest, err := SignedWorkloadRecoveryObservationDigest(observation)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	obs := observation.Observation
	if state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.ActivationDigest != activationDigest ||
		obs.DeviceID != state.DeviceID ||
		obs.WorkloadID != state.WorkloadID ||
		obs.Generation != state.Generation ||
		obs.ActivationID != activation.Receipt.ActivationID ||
		obs.ActivationDigest != activationDigest ||
		obs.ProcessID != activation.Receipt.ProcessID ||
		obs.ExpectedCgroupID != activation.Receipt.TargetCgroupID {
		return SignedWorkloadReconciliationDecision{}, ErrLifecycleInvalidLineage
	}

	outcome := ReconciliationQuarantine
	reasons := []string{}
	switch obs.State {
	case RecoveryObservationMatchRunning:
		outcome = ReconciliationKeepRunning
		reasons = append(reasons, "PROCESS_IDENTITY_AND_CGROUP_MATCH")
	case RecoveryObservationAbsent:
		outcome = ReconciliationMarkExitedUnknown
		reasons = append(reasons, "PROCESS_ABSENT_EXIT_STATUS_UNKNOWN")
	case RecoveryObservationBootChanged:
		outcome = ReconciliationMarkExitedUnknown
		reasons = append(reasons, "BOOT_CHANGED_PROCESS_CANNOT_SURVIVE")
	case RecoveryObservationPIDReused:
		outcome = ReconciliationMarkExitedUnknown
		reasons = append(reasons, "PID_REUSED_ORIGINAL_PROCESS_GONE")
	case RecoveryObservationCgroupMismatch:
		outcome = ReconciliationQuarantine
		reasons = append(reasons, "LIVE_PROCESS_OUTSIDE_EXPECTED_CGROUP")
	case RecoveryObservationLegacy:
		outcome = ReconciliationQuarantine
		reasons = append(reasons, "LEGACY_ACTIVATION_RECEIPT_HAS_NO_PROCESS_IDENTITY")
	case RecoveryObservationUnverifiable:
		outcome = ReconciliationQuarantine
		reasons = append(reasons, "PROCESS_STATE_UNVERIFIABLE")
	default:
		return SignedWorkloadReconciliationDecision{}, ErrRecoveryObservationInvalid
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
		ObservationDigest: obsDigest,
		Outcome:           outcome,
		ReasonCodes:       reasons,
		ObservedAt:        obs.ObservedAt.UTC(),
		DecidedAt:         now.UTC(),
		AuthorityID:       lifecycleAuthorityID,
	}
	return SignWorkloadReconciliationDecision(decision, lifecycleAuthorityKey)
}

func ValidateWorkloadReconciliationDecision(d WorkloadReconciliationDecision) error {
	if d.Version != WorkloadReconciliationDecisionVersion ||
		strings.TrimSpace(d.DecisionID) == "" ||
		strings.TrimSpace(d.DeviceID) == "" ||
		strings.TrimSpace(d.WorkloadID) == "" ||
		d.Generation == 0 ||
		d.ObservedAt.IsZero() ||
		d.DecidedAt.IsZero() ||
		strings.TrimSpace(d.AuthorityID) == "" {
		return errors.New("workload reconciliation decision is incomplete")
	}
	if d.DecidedAt.Before(d.ObservedAt) {
		return errors.New("reconciliation decision predates observation")
	}
	for field, digest := range map[string]string{
		"activation_digest": d.ActivationDigest,
		"observation_digest": d.ObservationDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	switch d.Outcome {
	case ReconciliationKeepRunning, ReconciliationMarkExitedUnknown, ReconciliationQuarantine:
	default:
		return fmt.Errorf("unsupported reconciliation outcome %q", d.Outcome)
	}
	return nil
}

func SignWorkloadReconciliationDecision(
	d WorkloadReconciliationDecision,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadReconciliationDecision, error) {
	if err := ValidateWorkloadReconciliationDecision(d); err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadReconciliationDecision{}, errors.New("lifecycle authority private key is invalid")
	}
	payload, err := canonicalWorkloadReconciliationDecisionPayload(d)
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadReconciliationDecision{}, err
	}
	return SignedWorkloadReconciliationDecision{
		Decision: d,
		KeyID: keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedWorkloadReconciliationDecision(
	signed SignedWorkloadReconciliationDecision,
	publicKey ed25519.PublicKey,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("lifecycle authority public key is invalid")
	}
	if err := ValidateWorkloadReconciliationDecision(signed.Decision); err != nil {
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
	payload, err := canonicalWorkloadReconciliationDecisionPayload(signed.Decision)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedWorkloadReconciliationDecisionDigest(
	signed SignedWorkloadReconciliationDecision,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed reconciliation decision is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-workload-reconciliation-decision/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalWorkloadReconciliationDecisionPayload(
	d WorkloadReconciliationDecision,
) ([]byte, error) {
	normalized := d
	normalized.ReasonCodes = append([]string(nil), d.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	normalized.DecidedAt = normalized.DecidedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/workload-reconciliation-decision/v1\x00"), body...), nil
}
