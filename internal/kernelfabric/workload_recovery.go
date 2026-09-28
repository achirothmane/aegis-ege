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
	CurrentBootIDHash       string                `json:"current_boot_id_hash,omitempty"`
	ExpectedCgroup          string                `json:"expected_cgroup"`
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
		strings.TrimSpace(obs.ExpectedCgroup) == "" ||
		obs.ExpectedCgroupID == 0 ||
		obs.ObservedAt.IsZero() {
		return ErrRecoveryObservationInvalid
	}
	if filepath.Clean(obs.ExpectedCgroup) != obs.ExpectedCgroup ||
		!filepath.IsAbs(obs.ExpectedCgroup) {
		return fmt.Errorf("%w: expected cgroup path is not a clean absolute path", ErrRecoveryObservationInvalid)
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
			obs.ObservedCgroupID == 0 || obs.ObservedCgroup == "" ||
			*obs.ExpectedProcessIdentity != *obs.ObservedProcessIdentity ||
			obs.ObservedCgroupID != obs.ExpectedCgroupID ||
			filepath.Clean(obs.ObservedCgroup) != obs.ExpectedCgroup ||
			obs.CurrentBootIDHash != obs.ExpectedProcessIdentity.BootIDHash {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationAbsent:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity != nil ||
			obs.ObservedCgroupID != 0 ||
			obs.CurrentBootIDHash != obs.ExpectedProcessIdentity.BootIDHash {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationBootChanged:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity != nil ||
			obs.CurrentBootIDHash == "" ||
			obs.CurrentBootIDHash == obs.ExpectedProcessIdentity.BootIDHash {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationPIDReused:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity == nil ||
			obs.ObservedCgroup == "" ||
			*obs.ExpectedProcessIdentity == *obs.ObservedProcessIdentity ||
			obs.CurrentBootIDHash != obs.ExpectedProcessIdentity.BootIDHash ||
			obs.ObservedProcessIdentity.BootIDHash != obs.CurrentBootIDHash {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationCgroupMismatch:
		if obs.ExpectedProcessIdentity == nil || obs.ObservedProcessIdentity == nil ||
			obs.ObservedCgroupID == 0 || obs.ObservedCgroup == "" ||
			*obs.ExpectedProcessIdentity != *obs.ObservedProcessIdentity ||
			(obs.ObservedCgroupID == obs.ExpectedCgroupID &&
				filepath.Clean(obs.ObservedCgroup) == obs.ExpectedCgroup) ||
			obs.CurrentBootIDHash != obs.ExpectedProcessIdentity.BootIDHash {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationLegacy:
		if obs.ExpectedProcessIdentity != nil || obs.ObservedProcessIdentity != nil {
			return ErrRecoveryObservationInvalid
		}
	case RecoveryObservationUnverifiable:
		if obs.ExpectedProcessIdentity == nil {
			return ErrRecoveryObservationInvalid
		}
	default:
		return fmt.Errorf("%w: unsupported observation state %q", ErrRecoveryObservationInvalid, obs.State)
	}
	if obs.ObservedCgroup != "" {
		if filepath.Clean(obs.ObservedCgroup) != obs.ObservedCgroup ||
			!filepath.IsAbs(obs.ObservedCgroup) {
			return fmt.Errorf("%w: observed cgroup path is not a clean absolute path", ErrRecoveryObservationInvalid)
		}
	}
	if obs.CurrentBootIDHash != "" {
		if _, err := ParseSHA256Digest(obs.CurrentBootIDHash); err != nil {
			return fmt.Errorf("%w: current boot id hash: %v", ErrRecoveryObservationInvalid, err)
		}
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
		obs.ExpectedCgroup != filepath.Clean(activation.Receipt.TargetCgroup) ||
		obs.ExpectedCgroupID != activation.Receipt.TargetCgroupID {
		return SignedWorkloadReconciliationDecision{}, ErrLifecycleInvalidLineage
	}
	if activation.Receipt.Version == WorkloadActivationReceiptVersionV2 {
		if activation.Receipt.ProcessIdentity == nil ||
			obs.ExpectedProcessIdentity == nil ||
			*obs.ExpectedProcessIdentity != *activation.Receipt.ProcessIdentity {
			return SignedWorkloadReconciliationDecision{}, ErrLifecycleInvalidLineage
		}
	} else if obs.State != RecoveryObservationLegacy ||
		obs.ExpectedProcessIdentity != nil {
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


func EvaluateRecoveredWorkloadRestart(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	reconciliation SignedWorkloadReconciliationDecision,
	remote SignedRemoteAttestationDecision,
	policy WorkloadRestartPolicy,
) (SignedWorkloadRestartDecision, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	if len(policy.LifecycleAuthorityKey) != ed25519.PrivateKeySize ||
		len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize ||
		len(policy.AdmissionIssuerPublicKey) != ed25519.PublicKeySize ||
		len(policy.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedWorkloadRestartDecision{}, errors.New("recovered restart requires lifecycle, verifier, admission and host trust keys")
	}
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if state.State != LifecycleStateExitedUnknown {
		return SignedWorkloadRestartDecision{}, ErrRestartDecisionRejected
	}
	if err := VerifySignedWorkloadAdmissionGrant(
		priorGrant,
		policy.AdmissionIssuerPublicKey,
		activation.Receipt.StartedAt,
	); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedWorkloadActivationReceipt(
		activation,
		policy.HostAttestorPublicKey,
	); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	lifecyclePub := policy.LifecycleAuthorityKey.Public().(ed25519.PublicKey)
	if err := VerifySignedWorkloadReconciliationDecision(
		reconciliation,
		lifecyclePub,
	); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedRemoteAttestationDecision(
		remote,
		policy.RemoteVerifierPublicKey,
	); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}

	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	recoveryDigest, err := SignedWorkloadReconciliationDecisionDigest(reconciliation)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	priorGrantDigest, err := SignedWorkloadAdmissionGrantDigest(priorGrant)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	remoteDigest, err := SignedRemoteAttestationDecisionDigest(remote)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.ActivationDigest != activationDigest ||
		state.RecoveryDigest != recoveryDigest ||
		activation.Receipt.GrantID != priorGrant.Grant.GrantID ||
		activation.Receipt.GrantDigest != priorGrantDigest ||
		activation.Receipt.WorkloadSpecDigest != priorGrant.Grant.WorkloadSpecDigest ||
		activation.Receipt.TargetCgroupID != priorGrant.Grant.TargetCgroupID {
		return SignedWorkloadRestartDecision{}, ErrLifecycleInvalidLineage
	}
	rec := reconciliation.Decision
	if rec.Outcome != ReconciliationMarkExitedUnknown ||
		rec.DeviceID != state.DeviceID ||
		rec.WorkloadID != state.WorkloadID ||
		rec.Generation != state.Generation ||
		rec.ActivationDigest != activationDigest {
		return SignedWorkloadRestartDecision{}, ErrLifecycleInvalidLineage
	}

	window := policy.RestartWindow
	if window <= 0 {
		window = 10 * time.Minute
	}
	maxRestarts := policy.MaxRestartsPerWindow
	if maxRestarts == 0 {
		maxRestarts = 3
	}
	baseBackoff := policy.BaseBackoff
	if baseBackoff <= 0 {
		baseBackoff = time.Second
	}
	maxBackoff := policy.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = time.Minute
	}
	reattestAfter := policy.ReattestAfter
	if reattestAfter <= 0 {
		reattestAfter = DefaultAdmissionAttestationMaxAge
	}
	ttl := policy.DecisionTTL
	if ttl <= 0 {
		ttl = time.Minute
	}

	restartCount := state.RestartCountInWindow
	windowStart := state.RestartWindowStartedAt
	if windowStart.IsZero() || !now.Before(windowStart.Add(window)) {
		restartCount = 0
		windowStart = now
	}

	outcome := RestartOutcomeRequireFreshGrant
	reasons := []string{"RECOVERED_EXIT_REQUIRES_FRESH_GRANT"}
	if restartCount >= maxRestarts {
		outcome = RestartOutcomeBlock
		reasons = []string{"RESTART_BUDGET_EXHAUSTED"}
	} else if remote.Decision.BootstrapDigest != priorGrant.Grant.BootstrapDigest {
		outcome = RestartOutcomeBlock
		reasons = []string{"BOOTSTRAP_CHANGED_REQUIRES_NEW_LIFECYCLE"}
	} else if remote.Decision.Decision != "ALLOW" ||
		remote.Decision.DeviceID != state.DeviceID ||
		remote.Decision.VerifiedAt.IsZero() ||
		!remote.Decision.VerifiedAt.UTC().After(rec.DecidedAt.UTC()) ||
		!now.Before(remote.Decision.VerifiedAt.UTC().Add(reattestAfter)) {
		outcome = RestartOutcomeRequireReattestation
		reasons = []string{"POST_RECOVERY_REATTESTATION_REQUIRED"}
	}

	delay := time.Duration(0)
	if outcome != RestartOutcomeBlock {
		delay = boundedRestartBackoff(baseBackoff, maxBackoff, restartCount)
	}
	notBefore := now
	if outcome != RestartOutcomeBlock {
		backoffDeadline := rec.DecidedAt.UTC().Add(delay)
		if backoffDeadline.After(notBefore) {
			notBefore = backoffDeadline
		}
	}
	decisionID, err := randomToken(24)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	decision := WorkloadRestartDecision{
		Version:                     WorkloadRestartDecisionVersion,
		DecisionID:                  decisionID,
		DeviceID:                    state.DeviceID,
		WorkloadID:                  state.WorkloadID,
		WorkloadSpecDigest:          activation.Receipt.WorkloadSpecDigest,
		TargetCgroup:                activation.Receipt.TargetCgroup,
		TargetCgroupID:              activation.Receipt.TargetCgroupID,
		BootstrapDigest:             priorGrant.Grant.BootstrapDigest,
		PreviousGeneration:          state.Generation,
		LifecycleEpoch:              EffectiveLifecycleEpoch(state),
		PreviousActivationDigest:    activationDigest,
		PreviousRecoveryDigest:      recoveryDigest,
		CurrentRemoteDecisionDigest: remoteDigest,
		Outcome:                     outcome,
		ReasonCodes:                 reasons,
		RestartCountInWindow:        restartCount,
		RestartWindowStartedAt:      windowStart,
		NotBefore:                   notBefore,
		ExpiresAt:                   notBefore.Add(ttl),
		EvaluatedAt:                 now,
		AuthorityID:                 policy.LifecycleAuthorityID,
	}
	return SignWorkloadRestartDecision(decision, policy.LifecycleAuthorityKey)
}
