
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
	QuarantineOperatorApprovalVersion = "aegis.ege/quarantine-operator-approval/v1"
	QuarantineReleaseDecisionVersion  = "aegis.ege/quarantine-release-decision/v1"

	QuarantineReleaseOutcome = "RELEASE_TO_EXITED_UNKNOWN"

	DefaultQuarantineApprovalTTL = 10 * time.Minute
	DefaultQuarantineReleaseTTL  = time.Minute
)

var (
	ErrQuarantineReleaseRejected = errors.New("quarantine release evidence is not admissible")
	ErrQuarantineClearanceUnsafe = errors.New("quarantined workload has not been proven inactive")
)

type QuarantineOperatorApproval struct {
	Version                    string    `json:"version"`
	ApprovalID                 string    `json:"approval_id"`
	DeviceID                   string    `json:"device_id"`
	WorkloadID                 string    `json:"workload_id"`
	Generation                 uint64    `json:"generation"`
	CurrentLifecycleEpoch      uint64    `json:"current_lifecycle_epoch"`
	RequestedLifecycleEpoch    uint64    `json:"requested_lifecycle_epoch"`
	ActivationDigest           string    `json:"activation_digest"`
	QuarantineRecoveryDigest   string    `json:"quarantine_recovery_digest"`
	ClearanceObservationDigest string    `json:"clearance_observation_digest"`
	RemoteDecisionDigest       string    `json:"remote_decision_digest"`
	OperatorID                 string    `json:"operator_id"`
	CaseReference              string    `json:"case_reference"`
	Reason                     string    `json:"reason"`
	IssuedAt                   time.Time `json:"issued_at"`
	ExpiresAt                  time.Time `json:"expires_at"`
}

type SignedQuarantineOperatorApproval struct {
	Approval  QuarantineOperatorApproval `json:"approval"`
	KeyID     string                     `json:"key_id"`
	Signature string                     `json:"signature"`
}

func ValidateQuarantineOperatorApproval(
	approval QuarantineOperatorApproval,
	now time.Time,
) error {
	if approval.Version != QuarantineOperatorApprovalVersion ||
		strings.TrimSpace(approval.ApprovalID) == "" ||
		strings.TrimSpace(approval.DeviceID) == "" ||
		strings.TrimSpace(approval.WorkloadID) == "" ||
		approval.Generation == 0 ||
		approval.CurrentLifecycleEpoch == 0 ||
		approval.RequestedLifecycleEpoch == 0 ||
		strings.TrimSpace(approval.OperatorID) == "" ||
		strings.TrimSpace(approval.CaseReference) == "" ||
		strings.TrimSpace(approval.Reason) == "" ||
		approval.IssuedAt.IsZero() ||
		approval.ExpiresAt.IsZero() ||
		!approval.ExpiresAt.After(approval.IssuedAt) {
		return errors.New("quarantine operator approval is incomplete")
	}
	if approval.RequestedLifecycleEpoch != approval.CurrentLifecycleEpoch+1 {
		return errors.New("quarantine operator approval must request exactly the next lifecycle epoch")
	}
	for field, digest := range map[string]string{
		"activation_digest":            approval.ActivationDigest,
		"quarantine_recovery_digest":   approval.QuarantineRecoveryDigest,
		"clearance_observation_digest": approval.ClearanceObservationDigest,
		"remote_decision_digest":       approval.RemoteDecisionDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(approval.IssuedAt.UTC()) {
			return errors.New("quarantine operator approval is not yet valid")
		}
		if !now.Before(approval.ExpiresAt.UTC()) {
			return errors.New("quarantine operator approval expired")
		}
	}
	return nil
}

func SignQuarantineOperatorApproval(
	approval QuarantineOperatorApproval,
	privateKey ed25519.PrivateKey,
) (SignedQuarantineOperatorApproval, error) {
	if err := ValidateQuarantineOperatorApproval(approval, time.Time{}); err != nil {
		return SignedQuarantineOperatorApproval{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedQuarantineOperatorApproval{}, errors.New("operator approval private key is invalid")
	}
	payload, err := canonicalQuarantineOperatorApprovalPayload(approval)
	if err != nil {
		return SignedQuarantineOperatorApproval{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedQuarantineOperatorApproval{}, err
	}
	return SignedQuarantineOperatorApproval{
		Approval:  approval,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedQuarantineOperatorApproval(
	signed SignedQuarantineOperatorApproval,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("operator approval public key is invalid")
	}
	if err := ValidateQuarantineOperatorApproval(signed.Approval, now); err != nil {
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
	payload, err := canonicalQuarantineOperatorApprovalPayload(signed.Approval)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedQuarantineOperatorApprovalDigest(
	signed SignedQuarantineOperatorApproval,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed quarantine operator approval is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-quarantine-operator-approval/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalQuarantineOperatorApprovalPayload(
	approval QuarantineOperatorApproval,
) ([]byte, error) {
	normalized := approval
	normalized.IssuedAt = normalized.IssuedAt.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/quarantine-operator-approval/v1\x00"), body...), nil
}

type QuarantineReleaseTrust struct {
	LifecycleAuthorityPublicKey ed25519.PublicKey
	HostAttestorPublicKey       ed25519.PublicKey
	RemoteVerifierPublicKey     ed25519.PublicKey
	AdmissionIssuerPublicKey    ed25519.PublicKey
	OperatorPublicKey           ed25519.PublicKey
	MaxAttestationAge           time.Duration
}

type quarantineReleaseEvidence struct {
	ActivationDigest           string
	QuarantineRecoveryDigest   string
	ClearanceObservationDigest string
	RemoteDecisionDigest       string
}

func validateQuarantineReleaseEvidence(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	quarantine SignedWorkloadReconciliationDecision,
	clearance SignedWorkloadRecoveryObservation,
	remote SignedRemoteAttestationDecision,
	trust QuarantineReleaseTrust,
	now time.Time,
) (quarantineReleaseEvidence, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return quarantineReleaseEvidence{}, err
	}
	if state.State != LifecycleStateQuarantined {
		return quarantineReleaseEvidence{}, ErrQuarantineReleaseRejected
	}
	if len(trust.LifecycleAuthorityPublicKey) != ed25519.PublicKeySize ||
		len(trust.HostAttestorPublicKey) != ed25519.PublicKeySize ||
		len(trust.RemoteVerifierPublicKey) != ed25519.PublicKeySize ||
		len(trust.AdmissionIssuerPublicKey) != ed25519.PublicKeySize {
		return quarantineReleaseEvidence{}, errors.New("quarantine release trust roots are incomplete")
	}
	if err := VerifySignedWorkloadAdmissionGrant(
		priorGrant,
		trust.AdmissionIssuerPublicKey,
		activation.Receipt.StartedAt,
	); err != nil {
		return quarantineReleaseEvidence{}, err
	}
	if err := VerifySignedWorkloadActivationReceipt(
		activation,
		trust.HostAttestorPublicKey,
	); err != nil {
		return quarantineReleaseEvidence{}, err
	}
	if err := VerifySignedWorkloadReconciliationDecision(
		quarantine,
		trust.LifecycleAuthorityPublicKey,
	); err != nil {
		return quarantineReleaseEvidence{}, err
	}
	if err := VerifySignedWorkloadRecoveryObservation(
		clearance,
		trust.HostAttestorPublicKey,
	); err != nil {
		return quarantineReleaseEvidence{}, err
	}
	if err := VerifySignedRemoteAttestationDecision(
		remote,
		trust.RemoteVerifierPublicKey,
	); err != nil {
		return quarantineReleaseEvidence{}, err
	}

	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return quarantineReleaseEvidence{}, err
	}
	priorGrantDigest, err := SignedWorkloadAdmissionGrantDigest(priorGrant)
	if err != nil {
		return quarantineReleaseEvidence{}, err
	}
	quarantineDigest, err := SignedWorkloadReconciliationDecisionDigest(quarantine)
	if err != nil {
		return quarantineReleaseEvidence{}, err
	}
	clearanceDigest, err := SignedWorkloadRecoveryObservationDigest(clearance)
	if err != nil {
		return quarantineReleaseEvidence{}, err
	}
	remoteDigest, err := SignedRemoteAttestationDecisionDigest(remote)
	if err != nil {
		return quarantineReleaseEvidence{}, err
	}

	if state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.ActivationDigest != activationDigest ||
		state.RecoveryDigest != quarantineDigest ||
		activation.Receipt.GrantID != priorGrant.Grant.GrantID ||
		activation.Receipt.GrantDigest != priorGrantDigest ||
		activation.Receipt.DeviceID != priorGrant.Grant.DeviceID ||
		activation.Receipt.WorkloadID != priorGrant.Grant.WorkloadID ||
		activation.Receipt.WorkloadSpecDigest != priorGrant.Grant.WorkloadSpecDigest ||
		activation.Receipt.TargetCgroupID != priorGrant.Grant.TargetCgroupID {
		return quarantineReleaseEvidence{}, ErrLifecycleInvalidLineage
	}

	q := quarantine.Decision
	if q.Outcome != ReconciliationQuarantine ||
		q.DeviceID != state.DeviceID ||
		q.WorkloadID != state.WorkloadID ||
		q.Generation != state.Generation ||
		q.ActivationDigest != activationDigest {
		return quarantineReleaseEvidence{}, ErrLifecycleInvalidLineage
	}

	c := clearance.Observation
	if c.DeviceID != state.DeviceID ||
		c.WorkloadID != state.WorkloadID ||
		c.Generation != state.Generation ||
		c.ActivationID != activation.Receipt.ActivationID ||
		c.ActivationDigest != activationDigest ||
		c.PriorRecoveryDigest != state.RecoveryDigest ||
		c.ExpectedCgroup != activation.Receipt.TargetCgroup ||
		c.ExpectedCgroupID != activation.Receipt.TargetCgroupID ||
		!c.ObservedAt.UTC().After(q.DecidedAt.UTC()) {
		return quarantineReleaseEvidence{}, ErrLifecycleInvalidLineage
	}
	if activation.Receipt.Version != WorkloadActivationReceiptVersionV2 ||
		activation.Receipt.ProcessIdentity == nil ||
		c.ExpectedProcessIdentity == nil ||
		*c.ExpectedProcessIdentity != *activation.Receipt.ProcessIdentity {
		return quarantineReleaseEvidence{}, ErrQuarantineClearanceUnsafe
	}
	switch c.State {
	case RecoveryObservationAbsent, RecoveryObservationBootChanged, RecoveryObservationPIDReused:
	default:
		return quarantineReleaseEvidence{}, ErrQuarantineClearanceUnsafe
	}

	if remote.Decision.Decision != "ALLOW" ||
		remote.Decision.DeviceID != state.DeviceID ||
		remote.Decision.BootstrapDigest != priorGrant.Grant.BootstrapDigest ||
		remote.Decision.VerifiedAt.IsZero() ||
		!remote.Decision.VerifiedAt.UTC().After(c.ObservedAt.UTC()) {
		return quarantineReleaseEvidence{}, ErrQuarantineReleaseRejected
	}
	maxAge := trust.MaxAttestationAge
	if maxAge <= 0 {
		maxAge = DefaultAdmissionAttestationMaxAge
	}
	if !now.Before(remote.Decision.VerifiedAt.UTC().Add(maxAge)) {
		return quarantineReleaseEvidence{}, ErrAdmissionRemoteDecisionStale
	}

	return quarantineReleaseEvidence{
		ActivationDigest:           activationDigest,
		QuarantineRecoveryDigest:   quarantineDigest,
		ClearanceObservationDigest: clearanceDigest,
		RemoteDecisionDigest:       remoteDigest,
	}, nil
}

func IssueQuarantineOperatorApproval(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	quarantine SignedWorkloadReconciliationDecision,
	clearance SignedWorkloadRecoveryObservation,
	remote SignedRemoteAttestationDecision,
	trust QuarantineReleaseTrust,
	operatorPrivateKey ed25519.PrivateKey,
	operatorID string,
	caseReference string,
	reason string,
	ttl time.Duration,
	now time.Time,
) (SignedQuarantineOperatorApproval, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	evidence, err := validateQuarantineReleaseEvidence(
		state, priorGrant, activation, quarantine, clearance, remote, trust, now,
	)
	if err != nil {
		return SignedQuarantineOperatorApproval{}, err
	}
	if len(operatorPrivateKey) != ed25519.PrivateKeySize {
		return SignedQuarantineOperatorApproval{}, errors.New("operator private key is required")
	}
	operatorID = strings.TrimSpace(operatorID)
	caseReference = strings.TrimSpace(caseReference)
	reason = strings.TrimSpace(reason)
	if operatorID == "" || caseReference == "" || reason == "" {
		return SignedQuarantineOperatorApproval{}, errors.New("operator id, case reference and reason are required")
	}
	if ttl <= 0 {
		ttl = DefaultQuarantineApprovalTTL
	}
	approvalID, err := randomToken(24)
	if err != nil {
		return SignedQuarantineOperatorApproval{}, err
	}
	epoch := EffectiveLifecycleEpoch(state)
	approval := QuarantineOperatorApproval{
		Version:                    QuarantineOperatorApprovalVersion,
		ApprovalID:                 approvalID,
		DeviceID:                   state.DeviceID,
		WorkloadID:                 state.WorkloadID,
		Generation:                 state.Generation,
		CurrentLifecycleEpoch:      epoch,
		RequestedLifecycleEpoch:    epoch + 1,
		ActivationDigest:           evidence.ActivationDigest,
		QuarantineRecoveryDigest:   evidence.QuarantineRecoveryDigest,
		ClearanceObservationDigest: evidence.ClearanceObservationDigest,
		RemoteDecisionDigest:       evidence.RemoteDecisionDigest,
		OperatorID:                 operatorID,
		CaseReference:              caseReference,
		Reason:                     reason,
		IssuedAt:                   now.UTC(),
		ExpiresAt:                  now.UTC().Add(ttl),
	}
	return SignQuarantineOperatorApproval(approval, operatorPrivateKey)
}

type QuarantineReleaseDecision struct {
	Version                    string    `json:"version"`
	DecisionID                 string    `json:"decision_id"`
	DeviceID                   string    `json:"device_id"`
	WorkloadID                 string    `json:"workload_id"`
	Generation                 uint64    `json:"generation"`
	PreviousLifecycleEpoch     uint64    `json:"previous_lifecycle_epoch"`
	NewLifecycleEpoch          uint64    `json:"new_lifecycle_epoch"`
	ActivationDigest           string    `json:"activation_digest"`
	QuarantineRecoveryDigest   string    `json:"quarantine_recovery_digest"`
	ClearanceObservationDigest string    `json:"clearance_observation_digest"`
	RemoteDecisionDigest       string    `json:"remote_decision_digest"`
	OperatorApprovalDigest     string    `json:"operator_approval_digest"`
	Outcome                    string    `json:"outcome"`
	ReasonCodes                []string  `json:"reason_codes,omitempty"`
	DecidedAt                  time.Time `json:"decided_at"`
	ExpiresAt                  time.Time `json:"expires_at"`
	AuthorityID                string    `json:"authority_id"`
}

type SignedQuarantineReleaseDecision struct {
	Decision  QuarantineReleaseDecision `json:"decision"`
	KeyID     string                    `json:"key_id"`
	Signature string                    `json:"signature"`
}

func ValidateQuarantineReleaseDecision(
	decision QuarantineReleaseDecision,
	now time.Time,
) error {
	if decision.Version != QuarantineReleaseDecisionVersion ||
		strings.TrimSpace(decision.DecisionID) == "" ||
		strings.TrimSpace(decision.DeviceID) == "" ||
		strings.TrimSpace(decision.WorkloadID) == "" ||
		decision.Generation == 0 ||
		decision.PreviousLifecycleEpoch == 0 ||
		decision.NewLifecycleEpoch != decision.PreviousLifecycleEpoch+1 ||
		decision.Outcome != QuarantineReleaseOutcome ||
		decision.DecidedAt.IsZero() ||
		decision.ExpiresAt.IsZero() ||
		!decision.ExpiresAt.After(decision.DecidedAt) ||
		strings.TrimSpace(decision.AuthorityID) == "" {
		return errors.New("quarantine release decision is incomplete")
	}
	for field, digest := range map[string]string{
		"activation_digest":             decision.ActivationDigest,
		"quarantine_recovery_digest":    decision.QuarantineRecoveryDigest,
		"clearance_observation_digest":  decision.ClearanceObservationDigest,
		"remote_decision_digest":        decision.RemoteDecisionDigest,
		"operator_approval_digest":      decision.OperatorApprovalDigest,
	} {
		if _, err := ParseSHA256Digest(digest); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(decision.DecidedAt.UTC()) {
			return errors.New("quarantine release decision is not yet valid")
		}
		if !now.Before(decision.ExpiresAt.UTC()) {
			return errors.New("quarantine release decision expired")
		}
	}
	return nil
}

func SignQuarantineReleaseDecision(
	decision QuarantineReleaseDecision,
	privateKey ed25519.PrivateKey,
) (SignedQuarantineReleaseDecision, error) {
	if err := ValidateQuarantineReleaseDecision(decision, time.Time{}); err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedQuarantineReleaseDecision{}, errors.New("lifecycle authority private key is invalid")
	}
	payload, err := canonicalQuarantineReleaseDecisionPayload(decision)
	if err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	keyID, err := BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	return SignedQuarantineReleaseDecision{
		Decision:  decision,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedQuarantineReleaseDecision(
	signed SignedQuarantineReleaseDecision,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("lifecycle authority public key is invalid")
	}
	if err := ValidateQuarantineReleaseDecision(signed.Decision, now); err != nil {
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
	payload, err := canonicalQuarantineReleaseDecisionPayload(signed.Decision)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func SignedQuarantineReleaseDecisionDigest(
	signed SignedQuarantineReleaseDecision,
) (string, error) {
	if strings.TrimSpace(signed.KeyID) == "" || strings.TrimSpace(signed.Signature) == "" {
		return "", errors.New("signed quarantine release decision is incomplete")
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/signed-quarantine-release-decision/v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalQuarantineReleaseDecisionPayload(
	decision QuarantineReleaseDecision,
) ([]byte, error) {
	normalized := decision
	normalized.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
	sort.Strings(normalized.ReasonCodes)
	normalized.DecidedAt = normalized.DecidedAt.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/quarantine-release-decision/v1\x00"), body...), nil
}

func EvaluateQuarantineRelease(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	quarantine SignedWorkloadReconciliationDecision,
	clearance SignedWorkloadRecoveryObservation,
	remote SignedRemoteAttestationDecision,
	approval SignedQuarantineOperatorApproval,
	trust QuarantineReleaseTrust,
	lifecycleAuthorityPrivateKey ed25519.PrivateKey,
	lifecycleAuthorityID string,
	ttl time.Duration,
	now time.Time,
) (SignedQuarantineReleaseDecision, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	evidence, err := validateQuarantineReleaseEvidence(
		state, priorGrant, activation, quarantine, clearance, remote, trust, now,
	)
	if err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	if len(trust.OperatorPublicKey) != ed25519.PublicKeySize {
		return SignedQuarantineReleaseDecision{}, errors.New("trusted operator public key is required")
	}
	if err := VerifySignedQuarantineOperatorApproval(
		approval,
		trust.OperatorPublicKey,
		now,
	); err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	approvalDigest, err := SignedQuarantineOperatorApprovalDigest(approval)
	if err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	a := approval.Approval
	currentEpoch := EffectiveLifecycleEpoch(state)
	if a.DeviceID != state.DeviceID ||
		a.WorkloadID != state.WorkloadID ||
		a.Generation != state.Generation ||
		a.CurrentLifecycleEpoch != currentEpoch ||
		a.RequestedLifecycleEpoch != currentEpoch+1 ||
		a.ActivationDigest != evidence.ActivationDigest ||
		a.QuarantineRecoveryDigest != evidence.QuarantineRecoveryDigest ||
		a.ClearanceObservationDigest != evidence.ClearanceObservationDigest ||
		a.RemoteDecisionDigest != evidence.RemoteDecisionDigest ||
		a.IssuedAt.UTC().Before(clearance.Observation.ObservedAt.UTC()) ||
		a.IssuedAt.UTC().Before(remote.Decision.VerifiedAt.UTC()) {
		return SignedQuarantineReleaseDecision{}, ErrLifecycleInvalidLineage
	}
	if len(lifecycleAuthorityPrivateKey) != ed25519.PrivateKeySize {
		return SignedQuarantineReleaseDecision{}, errors.New("lifecycle authority private key is required")
	}
	lifecycleAuthorityID = strings.TrimSpace(lifecycleAuthorityID)
	if lifecycleAuthorityID == "" {
		return SignedQuarantineReleaseDecision{}, errors.New("lifecycle authority id is required")
	}
	if ttl <= 0 {
		ttl = DefaultQuarantineReleaseTTL
	}
	decisionID, err := randomToken(24)
	if err != nil {
		return SignedQuarantineReleaseDecision{}, err
	}
	decision := QuarantineReleaseDecision{
		Version:                    QuarantineReleaseDecisionVersion,
		DecisionID:                 decisionID,
		DeviceID:                   state.DeviceID,
		WorkloadID:                 state.WorkloadID,
		Generation:                 state.Generation,
		PreviousLifecycleEpoch:     currentEpoch,
		NewLifecycleEpoch:          currentEpoch + 1,
		ActivationDigest:           evidence.ActivationDigest,
		QuarantineRecoveryDigest:   evidence.QuarantineRecoveryDigest,
		ClearanceObservationDigest: evidence.ClearanceObservationDigest,
		RemoteDecisionDigest:       evidence.RemoteDecisionDigest,
		OperatorApprovalDigest:     approvalDigest,
		Outcome:                    QuarantineReleaseOutcome,
		ReasonCodes: []string{
			"QUARANTINED_PROCESS_PROVEN_INACTIVE",
			"FRESH_REMOTE_ATTESTATION_VERIFIED",
			"OPERATOR_APPROVAL_VERIFIED",
			"LIFECYCLE_EPOCH_ADVANCED",
		},
		DecidedAt:   now.UTC(),
		ExpiresAt:   now.UTC().Add(ttl),
		AuthorityID: lifecycleAuthorityID,
	}
	return SignQuarantineReleaseDecision(decision, lifecycleAuthorityPrivateKey)
}


func EvaluateQuarantineReleasedRestart(
	state WorkloadLifecycleState,
	priorGrant SignedWorkloadAdmissionGrant,
	activation SignedWorkloadActivationReceipt,
	release SignedQuarantineReleaseDecision,
	remote SignedRemoteAttestationDecision,
	policy WorkloadRestartPolicy,
) (SignedWorkloadRestartDecision, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	state = NormalizeWorkloadLifecycleState(state)
	if err := ValidateWorkloadLifecycleState(state); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if state.State != LifecycleStateExitedUnknown {
		return SignedWorkloadRestartDecision{}, ErrRestartDecisionRejected
	}
	if len(policy.LifecycleAuthorityKey) != ed25519.PrivateKeySize ||
		len(policy.RemoteVerifierPublicKey) != ed25519.PublicKeySize ||
		len(policy.AdmissionIssuerPublicKey) != ed25519.PublicKeySize ||
		len(policy.HostAttestorPublicKey) != ed25519.PublicKeySize {
		return SignedWorkloadRestartDecision{}, errors.New("released restart requires lifecycle, verifier, admission and host trust keys")
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
	if err := VerifySignedQuarantineReleaseDecision(release, lifecyclePub, now); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	if err := VerifySignedRemoteAttestationDecision(remote, policy.RemoteVerifierPublicKey); err != nil {
		return SignedWorkloadRestartDecision{}, err
	}

	activationDigest, err := SignedWorkloadActivationReceiptDigest(activation)
	if err != nil {
		return SignedWorkloadRestartDecision{}, err
	}
	releaseDigest, err := SignedQuarantineReleaseDecisionDigest(release)
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
	r := release.Decision
	if state.DeviceID != activation.Receipt.DeviceID ||
		state.WorkloadID != activation.Receipt.WorkloadID ||
		state.ActivationDigest != activationDigest ||
		state.RecoveryDigest != releaseDigest ||
		state.LifecycleEpoch != r.NewLifecycleEpoch ||
		r.Outcome != QuarantineReleaseOutcome ||
		r.DeviceID != state.DeviceID ||
		r.WorkloadID != state.WorkloadID ||
		r.Generation != state.Generation ||
		r.ActivationDigest != activationDigest ||
		r.NewLifecycleEpoch != r.PreviousLifecycleEpoch+1 ||
		activation.Receipt.GrantID != priorGrant.Grant.GrantID ||
		activation.Receipt.GrantDigest != priorGrantDigest ||
		activation.Receipt.WorkloadSpecDigest != priorGrant.Grant.WorkloadSpecDigest ||
		activation.Receipt.TargetCgroupID != priorGrant.Grant.TargetCgroupID {
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
	reasons := []string{"QUARANTINE_RELEASE_REQUIRES_FRESH_GRANT"}
	if restartCount >= maxRestarts {
		outcome = RestartOutcomeBlock
		reasons = []string{"RESTART_BUDGET_EXHAUSTED"}
	} else if remote.Decision.BootstrapDigest != priorGrant.Grant.BootstrapDigest {
		outcome = RestartOutcomeBlock
		reasons = []string{"BOOTSTRAP_CHANGED_REQUIRES_NEW_LIFECYCLE"}
	} else if remote.Decision.Decision != "ALLOW" ||
		remote.Decision.DeviceID != state.DeviceID ||
		remoteDigest != r.RemoteDecisionDigest ||
		remote.Decision.VerifiedAt.IsZero() ||
		!now.Before(remote.Decision.VerifiedAt.UTC().Add(reattestAfter)) {
		outcome = RestartOutcomeRequireReattestation
		reasons = []string{"POST_QUARANTINE_ATTESTATION_REQUIRED"}
	}

	delay := time.Duration(0)
	if outcome != RestartOutcomeBlock {
		delay = boundedRestartBackoff(baseBackoff, maxBackoff, restartCount)
	}
	notBefore := now
	if outcome != RestartOutcomeBlock {
		backoffDeadline := r.DecidedAt.UTC().Add(delay)
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
		LifecycleEpoch:              state.LifecycleEpoch,
		PreviousActivationDigest:    activationDigest,
		PreviousRecoveryDigest:      releaseDigest,
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
