package ege

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	ConsequenceAdmissionVersion = "aegis.ege/consequence/v0alpha1"

	ConsequenceDecisionAdmissible = "ADMISSIBLE"
	ConsequenceDecisionBlocked    = "BLOCKED"

	ConsequenceClassOperationalStateChange = "operational_state_change"
)

type ConsequencePolicy struct {
	Ref                string
	Version            string
	ConsequenceClass   string
	AllowedKinds       []string
	AllowedActions     []string
	AllowedTargetTypes []string
	MaxEvidenceAge     time.Duration
}

type ConsequenceAdmission struct {
	APIVersion        string    `json:"api_version"`
	Decision          string    `json:"decision"`
	ConsequenceClass  string    `json:"consequence_class"`
	PolicyRef         string    `json:"policy_ref"`
	PolicyVersion     string    `json:"policy_version"`
	PolicyHash        string    `json:"policy_hash"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
	ActionScopeDigest string    `json:"action_scope_digest"`
}

func KubernetesNodeDrainConsequencePolicy(maxEvidenceAge time.Duration) ConsequencePolicy {
	return ConsequencePolicy{
		Ref:                "aegis-ege/policy/kubernetes-node-drain-consequence",
		Version:            "v1",
		ConsequenceClass:   ConsequenceClassOperationalStateChange,
		AllowedKinds:       []string{"kubernetes.node_drain"},
		AllowedActions:     []string{"drain"},
		AllowedTargetTypes: []string{"kubernetes.node"},
		MaxEvidenceAge:     maxEvidenceAge,
	}
}

func ValidateConsequencePolicy(policy ConsequencePolicy) error {
	if policy.Ref == "" || policy.Version == "" || policy.ConsequenceClass == "" {
		return errors.New("CONSEQUENCE_POLICY_IDENTITY_INVALID")
	}
	if len(policy.AllowedKinds) == 0 || len(policy.AllowedActions) == 0 || len(policy.AllowedTargetTypes) == 0 {
		return errors.New("CONSEQUENCE_POLICY_SCOPE_EMPTY")
	}
	if policy.MaxEvidenceAge < 0 {
		return errors.New("CONSEQUENCE_POLICY_MAX_EVIDENCE_AGE_INVALID")
	}
	return nil
}

func EvaluateConsequenceAdmission(
	policy ConsequencePolicy,
	claims PermitClaims,
	manifest EvidenceManifest,
	now time.Time,
) (ConsequenceAdmission, error) {
	if err := ValidateConsequencePolicy(policy); err != nil {
		return ConsequenceAdmission{}, err
	}
	if now.IsZero() {
		return ConsequenceAdmission{}, errors.New("CONSEQUENCE_EVALUATION_TIME_REQUIRED")
	}
	now = now.UTC()

	policyHash, err := consequencePolicyHash(policy)
	if err != nil {
		return ConsequenceAdmission{}, err
	}
	actionScopeDigest, err := consequenceActionScopeDigest(claims)
	if err != nil {
		return ConsequenceAdmission{}, err
	}

	admission := ConsequenceAdmission{
		APIVersion:        ConsequenceAdmissionVersion,
		Decision:          ConsequenceDecisionBlocked,
		ConsequenceClass:  policy.ConsequenceClass,
		PolicyRef:         policy.Ref,
		PolicyVersion:     policy.Version,
		PolicyHash:        policyHash,
		EvaluatedAt:       now,
		ActionScopeDigest: actionScopeDigest,
	}

	if !containsConsequenceValue(policy.AllowedKinds, claims.Kind) {
		return admission, fmt.Errorf("CONSEQUENCE_KIND_NOT_ADMISSIBLE:%s", claims.Kind)
	}
	if !containsConsequenceValue(policy.AllowedActions, claims.Action) {
		return admission, fmt.Errorf("CONSEQUENCE_ACTION_NOT_ADMISSIBLE:%s", claims.Action)
	}
	if !containsConsequenceValue(policy.AllowedTargetTypes, claims.Target.Type) {
		return admission, fmt.Errorf("CONSEQUENCE_TARGET_NOT_ADMISSIBLE:%s", claims.Target.Type)
	}
	if claims.ValidUntil.IsZero() || now.After(claims.ValidUntil.UTC()) {
		return admission, errors.New("CONSEQUENCE_PERMIT_EXPIRED")
	}

	if manifest.IntentID != claims.IntentID ||
		manifest.Kind != claims.Kind ||
		manifest.Target != claims.Target ||
		manifest.ResourceVersion != claims.ResourceVersion ||
		manifest.EvidenceDigest != claims.EvidenceDigest ||
		manifest.PlanDigest != claims.PlanDigest {
		return admission, errors.New("CONSEQUENCE_EVIDENCE_BINDING_MISMATCH")
	}
	if manifest.ObservedAt.IsZero() {
		return admission, errors.New("CONSEQUENCE_EVIDENCE_TIME_MISSING")
	}
	observedAt := manifest.ObservedAt.UTC()
	if observedAt.After(now) {
		return admission, errors.New("CONSEQUENCE_EVIDENCE_FROM_FUTURE")
	}
	if policy.MaxEvidenceAge > 0 && now.Sub(observedAt) > policy.MaxEvidenceAge {
		return admission, errors.New("CONSEQUENCE_EVIDENCE_STALE")
	}

	admission.Decision = ConsequenceDecisionAdmissible
	return admission, nil
}

func ValidateConsequenceAdmission(admission ConsequenceAdmission) error {
	if admission.APIVersion != ConsequenceAdmissionVersion {
		return errors.New("CONSEQUENCE_ADMISSION_VERSION_INVALID")
	}
	if admission.Decision != ConsequenceDecisionAdmissible && admission.Decision != ConsequenceDecisionBlocked {
		return errors.New("CONSEQUENCE_ADMISSION_DECISION_INVALID")
	}
	if admission.ConsequenceClass == "" ||
		admission.PolicyRef == "" ||
		admission.PolicyVersion == "" ||
		admission.PolicyHash == "" ||
		admission.ActionScopeDigest == "" ||
		admission.EvaluatedAt.IsZero() {
		return errors.New("CONSEQUENCE_ADMISSION_INCOMPLETE")
	}
	return nil
}

func consequencePolicyHash(policy ConsequencePolicy) (string, error) {
	normalized := struct {
		Ref                string   `json:"ref"`
		Version            string   `json:"version"`
		ConsequenceClass   string   `json:"consequence_class"`
		AllowedKinds       []string `json:"allowed_kinds"`
		AllowedActions     []string `json:"allowed_actions"`
		AllowedTargetTypes []string `json:"allowed_target_types"`
		MaxEvidenceAgeNS   int64    `json:"max_evidence_age_ns"`
	}{
		Ref:                policy.Ref,
		Version:            policy.Version,
		ConsequenceClass:   policy.ConsequenceClass,
		AllowedKinds:       sortedConsequenceValues(policy.AllowedKinds),
		AllowedActions:     sortedConsequenceValues(policy.AllowedActions),
		AllowedTargetTypes: sortedConsequenceValues(policy.AllowedTargetTypes),
		MaxEvidenceAgeNS:   int64(policy.MaxEvidenceAge),
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal consequence policy: %w", err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func consequenceActionScopeDigest(claims PermitClaims) (string, error) {
	body, err := json.Marshal(struct {
		IntentID        string `json:"intent_id"`
		Kind            string `json:"kind"`
		Target          Target `json:"target"`
		Action          string `json:"action"`
		ResourceVersion string `json:"resource_version"`
		PlanDigest      string `json:"plan_digest"`
	}{
		IntentID:        claims.IntentID,
		Kind:            claims.Kind,
		Target:          claims.Target,
		Action:          claims.Action,
		ResourceVersion: claims.ResourceVersion,
		PlanDigest:      claims.PlanDigest,
	})
	if err != nil {
		return "", fmt.Errorf("marshal consequence action scope: %w", err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sortedConsequenceValues(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func containsConsequenceValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
