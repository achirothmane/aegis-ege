package kernelfabric

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	WorkloadExitReceiptVersion     = "aegis.ege/workload-exit-receipt/v1"
	WorkloadRestartDecisionVersion = "aegis.ege/workload-restart-decision/v1"
	WorkloadLifecycleStateVersion  = "aegis.ege/workload-lifecycle-state/v1"

	RestartOutcomeBlock               = "BLOCK"
	RestartOutcomeRequireFreshGrant   = "REQUIRE_FRESH_GRANT"
	RestartOutcomeRequireReattestation = "REQUIRE_REATTESTATION"

	ExitClassClean   = "CLEAN"
	ExitClassNonZero = "NONZERO"
	ExitClassSignal  = "SIGNAL"

	LifecycleStateRunning = "RUNNING"
	LifecycleStateExited  = "EXITED"
)

var (
	ErrLifecycleInvalidLineage = errors.New("workload lifecycle lineage is invalid")
	ErrLifecycleAlreadyRunning = errors.New("workload lifecycle is already running")
	ErrRestartBudgetExhausted  = errors.New("workload restart budget exhausted")
	ErrRestartDecisionRejected = errors.New("workload restart decision does not authorize restart")
)

type WorkloadExitReceipt struct {
	Version              string    `json:"version"`
	ExitID               string    `json:"exit_id"`
	ActivationID         string    `json:"activation_id"`
	ActivationDigest     string    `json:"activation_digest"`
	GrantID              string    `json:"grant_id"`
	GrantDigest          string    `json:"grant_digest"`
	DeviceID             string    `json:"device_id"`
	WorkloadID           string    `json:"workload_id"`
	WorkloadSpecDigest   string    `json:"workload_spec_digest"`
	TargetCgroup         string    `json:"target_cgroup"`
	TargetCgroupID       uint64    `json:"target_cgroup_id"`
	ProcessID            int       `json:"process_id"`
	ExitClass            string    `json:"exit_class"`
	ExitCode             int       `json:"exit_code"`
	Signal               int       `json:"signal,omitempty"`
	StartedAt            time.Time `json:"started_at"`
	ExitedAt             time.Time `json:"exited_at"`
}

type SignedWorkloadExitReceipt struct {
	Receipt   WorkloadExitReceipt `json:"receipt"`
	KeyID     string              `json:"key_id"`
	Signature string              `json:"signature"`
}

func SignWorkloadExitReceipt(
	receipt WorkloadExitReceipt,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadExitReceipt, error) {
	if err := ValidateWorkloadExitReceipt(receipt); err != nil {
		return SignedWorkloadExitReceipt{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadExitReceipt{}, errors.New("host lifecycle attestor private key is invalid")
	}
	payload, err := canonicalWorkloadExitReceiptPayload(receipt)
	if err != nil {
		return SignedWorkloadExitReceipt{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadExitReceipt{}, err
	}
	return SignedWorkloadExitReceipt{
		Receipt:   receipt,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedWorkloadExitReceipt(
	signed SignedWorkloadExitReceipt,
	publicKey ed25519.PublicKey,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("host lifecycle attestor public key is invalid")
	}
	if err := ValidateWorkloadExitReceipt(signed.Receipt); err != nil {
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
	payload, err := canonicalWorkloadExitReceiptPayload(signed.Receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func ValidateWorkloadExitReceipt(receipt WorkloadExitReceipt) error {
	if receipt.Version != WorkloadExitReceiptVersion ||
		strings.TrimSpace(receipt.ExitID) == "" ||
		strings.TrimSpace(receipt.ActivationID) == "" ||
		strings.TrimSpace(receipt.GrantID) == "" ||
		strings.TrimSpace(receipt.DeviceID) == "" ||
		strings.TrimSpace(receipt.WorkloadID) == "" ||
		receipt.TargetCgroupID == 0 ||
		receipt.ProcessID <= 0 ||
		receipt.StartedAt.IsZero() ||
		receipt.ExitedAt.IsZero() ||
		receipt.ExitedAt.Before(receipt.StartedAt) {
		return errors.New("workload exit receipt is incomplete")
	}
	for field, digest := range map[string]string{
		"activation_digest": receipt.ActivationDigest,
		"grant_digest": receipt.GrantDigest,
		"workload_spec_digest": receipt.WorkloadSpecDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	switch receipt.ExitClass {
	case ExitClassClean:
		if receipt.ExitCode != 0 || receipt.Signal != 0 {
			return errors.New("clean exit must have code 0 and no signal")
		}
	case ExitClassNonZero:
		if receipt.ExitCode == 0 || receipt.Signal != 0 {
			return errors.New("nonzero exit must have nonzero code and no signal")
		}
	case ExitClassSignal:
		if receipt.Signal <= 0 {
			return errors.New("signaled exit must include signal")
		}
	default:
		return fmt.Errorf("unsupported exit class %q", receipt.ExitClass)
	}
	return nil
}

func canonicalWorkloadExitReceiptPayload(receipt WorkloadExitReceipt) ([]byte, error) {
	normalized := receipt
	normalized.StartedAt = normalized.StartedAt.UTC()
	normalized.ExitedAt = normalized.ExitedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/workload-exit-receipt/v1\x00"), body...), nil
}

func SignedWorkloadActivationReceiptDigest(
	signed SignedWorkloadActivationReceipt,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed workload activation receipt is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-workload-activation-receipt/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignedWorkloadExitReceiptDigest(
	signed SignedWorkloadExitReceipt,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed workload exit receipt is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-workload-exit-receipt/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type WorkloadLifecycleState struct {
	Version                 string    `json:"version"`
	DeviceID                string    `json:"device_id"`
	WorkloadID              string    `json:"workload_id"`
	Generation              uint64    `json:"generation"`
	State                   string    `json:"state"`
	ActivationDigest        string    `json:"activation_digest"`
	ExitDigest              string    `json:"exit_digest,omitempty"`
	RestartCountInWindow    uint32    `json:"restart_count_in_window"`
	RestartWindowStartedAt  time.Time `json:"restart_window_started_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type WorkloadRestartPolicy struct {
	MaxRestartsPerWindow uint32
	RestartWindow        time.Duration
	BaseBackoff          time.Duration
	MaxBackoff           time.Duration
	ReattestAfter        time.Duration
	ReattestOnNonZero    bool
	ReattestOnSignal     bool
	AllowCleanExitRestart bool
	DecisionTTL          time.Duration
	LifecycleAuthorityKey ed25519.PrivateKey
	LifecycleAuthorityID  string
	RemoteVerifierPublicKey  ed25519.PublicKey
	AdmissionIssuerPublicKey ed25519.PublicKey
	HostAttestorPublicKey    ed25519.PublicKey
	Now func() time.Time
}

type WorkloadRestartDecision struct {
	Version                     string    `json:"version"`
	DecisionID                  string    `json:"decision_id"`
	DeviceID                    string    `json:"device_id"`
	WorkloadID                  string    `json:"workload_id"`
	PreviousGeneration          uint64    `json:"previous_generation"`
	PreviousActivationDigest   string    `json:"previous_activation_digest"`
	PreviousExitDigest         string    `json:"previous_exit_digest"`
	CurrentRemoteDecisionDigest string   `json:"current_remote_decision_digest"`
	Outcome                     string    `json:"outcome"`
	ReasonCodes                 []string  `json:"reason_codes,omitempty"`
	RestartCountInWindow        uint32    `json:"restart_count_in_window"`
	RestartWindowStartedAt      time.Time `json:"restart_window_started_at"`
	NotBefore                   time.Time `json:"not_before"`
	ExpiresAt                   time.Time `json:"expires_at"`
	EvaluatedAt                 time.Time `json:"evaluated_at"`
	AuthorityID                 string    `json:"authority_id"`
}

type SignedWorkloadRestartDecision struct {
	Decision  WorkloadRestartDecision `json:"decision"`
	KeyID     string                  `json:"key_id"`
	Signature string                  `json:"signature"`
}

func EvaluateWorkloadRestart(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	exit SignedWorkloadExitReceipt,
	remote SignedRemoteAttestationDecision,
	policy WorkloadRestartPolicy,
) (SignedWorkloadRestartDecision, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	if len(policy.LifecycleAuthorityKey) != ed25519.PrivateKeySize {
		return SignedWorkloadRestartDecision{}, errors.New("lifecycle authority private key is required")
	}
	if strings.TrimSpace(policy.LifecycleAuthorityID) == "" {
		return SignedWorkloadRestartDecision{}, errors.New("lifecycle authority id is required")
	}
	if len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize ||
		len(policy.AdmissionIssuerPublicKey) != ed25519.PublicKeySize ||
		len(policy.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedWorkloadRestartDecision{}, errors.New("trusted remote verifier, admission issuer, and host attestor public keys are required")
	}
	if err := VerifySignedWorkloadAdmissionGrant(priorGrant, policy.AdmissionIssuerPublicKey, activation.Receipt.StartedAt); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedWorkloadActivationReceipt(activation, policy.HostAttestorPublicKey); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedWorkloadExitReceipt(exit, policy.HostAttestorPublicKey); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedRemoteAttestationDecision(remote, policy.RemoteVerifierPublicKey); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	priorGrantDigest, err := SignedWorkloadAdmissionGrantDigest(priorGrant)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if activation.Receipt.GrantID != priorGrant.Grant.GrantID ||
		activation.Receipt.GrantDigest != priorGrantDigest ||
		activation.Receipt.DeviceID != priorGrant.Grant.DeviceID ||
		activation.Receipt.WorkloadID != priorGrant.Grant.WorkloadID ||
		activation.Receipt.WorkloadSpecDigest != priorGrant.Grant.WorkloadSpecDigest ||
		activation.Receipt.TargetCgroupID != priorGrant.Grant.TargetCgroupID {
		return SignedWorkloadRestartDecision{}, ErrLifecycleInvalidLineage
	}
	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	exitDigest, err := SignedWorkloadExitReceiptDigest(exit)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	remoteDigest, err := SignedRemoteAttestationDecisionDigest(remote)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := validateLifecycleRestartLineage(state, activation, exit, activationDigest, exitDigest); err != nil {
		return SignedWorkloadRestartDecision{}, err
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
	var reasons []string
	if exit.Receipt.ExitClass == ExitClassClean && !policy.AllowCleanExitRestart {
		outcome = RestartOutcomeBlock
		reasons = append(reasons, "CLEAN_EXIT_RESTART_DISABLED")
	}
	if outcome != RestartOutcomeBlock && restartCount >= maxRestarts {
		outcome = RestartOutcomeBlock
		reasons = append(reasons, "RESTART_BUDGET_EXHAUSTED")
	}
	if outcome != RestartOutcomeBlock {
		if remote.Decision.BootstrapDigest != priorGrant.Grant.BootstrapDigest {
			outcome = RestartOutcomeBlock
			reasons = append(reasons, "BOOTSTRAP_CHANGED_REQUIRES_NEW_LIFECYCLE")
		} else if remote.Decision.Decision != "ALLOW" ||
			remote.Decision.DeviceID != state.DeviceID {
			outcome = RestartOutcomeRequireReattestation
			reasons = append(reasons, "REMOTE_ATTESTATION_NOT_CURRENT_ALLOW")
		} else if remote.Decision.VerifiedAt.IsZero() ||
			!now.Before(remote.Decision.VerifiedAt.UTC().Add(reattestAfter)) {
			outcome = RestartOutcomeRequireReattestation
			reasons = append(reasons, "REMOTE_ATTESTATION_TOO_OLD")
		} else if exit.Receipt.ExitClass == ExitClassNonZero &&
			policy.ReattestOnNonZero &&
			!remote.Decision.VerifiedAt.UTC().After(exit.Receipt.ExitedAt.UTC()) {
			outcome = RestartOutcomeRequireReattestation
			reasons = append(reasons, "NONZERO_EXIT_REQUIRES_POST_EXIT_REATTESTATION")
		} else if exit.Receipt.ExitClass == ExitClassSignal &&
			policy.ReattestOnSignal &&
			!remote.Decision.VerifiedAt.UTC().After(exit.Receipt.ExitedAt.UTC()) {
			outcome = RestartOutcomeRequireReattestation
			reasons = append(reasons, "SIGNAL_EXIT_REQUIRES_POST_EXIT_REATTESTATION")
		} else {
			reasons = append(reasons, "FRESH_GRANT_REQUIRED")
		}
	}

	delay := time.Duration(0)
	if outcome != RestartOutcomeBlock {
		exponent := restartCount
		if exponent > 30 {
			exponent = 30
		}
		multiplier := math.Pow(2, float64(exponent))
		delay = time.Duration(float64(baseBackoff) * multiplier)
		if delay > maxBackoff {
			delay = maxBackoff
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
		PreviousGeneration:          state.Generation,
		PreviousActivationDigest:    activationDigest,
		PreviousExitDigest:          exitDigest,
		CurrentRemoteDecisionDigest: remoteDigest,
		Outcome:                     outcome,
		ReasonCodes:                 reasons,
		RestartCountInWindow:        restartCount,
		RestartWindowStartedAt:      windowStart,
		NotBefore:                   now.Add(delay),
		ExpiresAt:                   now.Add(ttl),
		EvaluatedAt:                 now,
		AuthorityID:                 policy.LifecycleAuthorityID,
	}
	return SignWorkloadRestartDecision(decision, policy.LifecycleAuthorityKey)
}

func validateLifecycleRestartLineage(
	state WorkloadLifecycleState,
	activation SignedWorkloadActivationReceipt,
	exit SignedWorkloadExitReceipt,
	activationDigest string,
	exitDigest string,
) error {
	if state.Version != WorkloadLifecycleStateVersion ||
		state.State != LifecycleStateExited ||
		state.Generation == 0 ||
		state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.DeviceID != exit.Receipt.DeviceID ||
		state.WorkloadID != exit.Receipt.WorkloadID ||
		state.ActivationDigest != activationDigest ||
		state.ExitDigest != exitDigest ||
		exit.Receipt.ActivationID != activation.Receipt.ActivationID ||
		exit.Receipt.ActivationDigest != activationDigest ||
		exit.Receipt.GrantID != activation.Receipt.GrantID ||
		exit.Receipt.GrantDigest != activation.Receipt.GrantDigest ||
		exit.Receipt.ProcessID != activation.Receipt.ProcessID ||
		exit.Receipt.WorkloadSpecDigest != activation.Receipt.WorkloadSpecDigest ||
		exit.Receipt.TargetCgroupID != activation.Receipt.TargetCgroupID {
		return ErrLifecycleInvalidLineage
	}
	return nil
}

func IssueRestartWorkloadAdmissionGrant(
	req WorkloadAdmissionRequest,
	remote SignedRemoteAttestationDecision,
	restart SignedWorkloadRestartDecision,
	lifecycleAuthorityPublicKey ed25519.PublicKey,
	policy WorkloadAdmissionPolicy,
	now time.Time,
) (SignedWorkloadAdmissionGrant, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedWorkloadRestartDecision(
		restart,
		lifecycleAuthorityPublicKey,
		now,
	); err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	if restart.Decision.Outcome != RestartOutcomeRequireFreshGrant {
		return SignedWorkloadAdmissionGrant{}, ErrRestartDecisionRejected
	}
	if restart.Decision.DeviceID != req.DeviceID ||
		restart.Decision.WorkloadID != req.WorkloadID {
		return SignedWorkloadAdmissionGrant{}, ErrLifecycleInvalidLineage
	}
	remoteDigest, err := SignedRemoteAttestationDecisionDigest(remote)
	if err != nil {
		return SignedWorkloadAdmissionGrant{}, err
	}
	if restart.Decision.CurrentRemoteDecisionDigest != remoteDigest {
		return SignedWorkloadAdmissionGrant{}, ErrLifecycleInvalidLineage
	}
	if policy.Now == nil {
		policy.Now = func() time.Time { return now }
	}
	return IssueWorkloadAdmissionGrant(req, remote, policy)
}

func SignWorkloadRestartDecision(
	decision WorkloadRestartDecision,
	privateKey ed25519.PrivateKey,
) (SignedWorkloadRestartDecision, error) {
	if err := ValidateWorkloadRestartDecision(decision, time.Time{}); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedWorkloadRestartDecision{}, errors.New("invalid lifecycle authority key")
	}
	payload, err := canonicalWorkloadRestartDecisionPayload(decision)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	return SignedWorkloadRestartDecision{
		Decision: decision,
		KeyID: keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedWorkloadRestartDecision(
	signed SignedWorkloadRestartDecision,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("lifecycle authority public key is invalid")
	}
	if err := ValidateWorkloadRestartDecision(signed.Decision, now); err != nil {
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
	payload, err := canonicalWorkloadRestartDecisionPayload(signed.Decision)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func ValidateWorkloadRestartDecision(
	decision WorkloadRestartDecision,
	now time.Time,
) error {
	if decision.Version != WorkloadRestartDecisionVersion ||
		strings.TrimSpace(decision.DecisionID) == "" ||
		strings.TrimSpace(decision.DeviceID) == "" ||
		strings.TrimSpace(decision.WorkloadID) == "" ||
		decision.PreviousGeneration == 0 ||
		strings.TrimSpace(decision.AuthorityID) == "" ||
		decision.EvaluatedAt.IsZero() ||
		decision.RestartWindowStartedAt.IsZero() ||
		decision.NotBefore.IsZero() ||
		decision.ExpiresAt.IsZero() ||
		!decision.ExpiresAt.After(decision.EvaluatedAt) {
		return errors.New("workload restart decision is incomplete")
	}
	for field, digest := range map[string]string{
		"previous_activation_digest": decision.PreviousActivationDigest,
		"previous_exit_digest": decision.PreviousExitDigest,
		"current_remote_decision_digest": decision.CurrentRemoteDecisionDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	switch decision.Outcome {
	case RestartOutcomeBlock, RestartOutcomeRequireFreshGrant, RestartOutcomeRequireReattestation:
	default:
		return fmt.Errorf("unsupported restart outcome %q", decision.Outcome)
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(decision.NotBefore.UTC()) {
			return errors.New("workload restart decision backoff has not elapsed")
		}
		if !now.Before(decision.ExpiresAt.UTC()) {
			return errors.New("workload restart decision expired")
		}
	}
	return nil
}

func canonicalWorkloadRestartDecisionPayload(
	decision WorkloadRestartDecision,
) ([]byte, error) {
	normalized := decision
	normalized.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	normalized.RestartWindowStartedAt = normalized.RestartWindowStartedAt.UTC()
	normalized.NotBefore = normalized.NotBefore.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	normalized.EvaluatedAt = normalized.EvaluatedAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/workload-restart-decision/v1\x00"), body...), nil
}
