package ege

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const EBAContractVersion = "eba.integration/v0.1"

type KubernetesDrainConformanceInput struct {
	PrincipalID        string
	AssumptionArtifacts []json.RawMessage
	AuthorityArtifact   json.RawMessage
	BudgetArtifact      json.RawMessage
	Approvals           []ApprovalAttestation
	EvidenceManifest    EvidenceManifest
	Permit              Permit
}

func ValidateKubernetesDrainConformance(
	ctx context.Context,
	permitAuthority SignatureVerifier,
	approvalAuthority SignatureVerifier,
	input KubernetesDrainConformanceInput,
	now time.Time,
) error {
	if input.Permit.Claims.Kind != "kubernetes.node_drain" {
		return fmt.Errorf("unsupported conformance kind %q", input.Permit.Claims.Kind)
	}
	if input.Permit.Claims.Action != "drain" {
		return errors.New("conformance action must be drain")
	}
	if input.Permit.Claims.Target.Type != "kubernetes.node" {
		return errors.New("conformance target must be kubernetes.node")
	}
	if len(input.AssumptionArtifacts) == 0 {
		return errors.New("ASSUMPTION_REFERENCE_MISSING")
	}
	if len(input.AuthorityArtifact) == 0 {
		return errors.New("AUTHORITY_REFERENCE_MISSING")
	}
	if len(input.Approvals) == 0 {
		return errors.New("APPROVAL_REFERENCE_MISSING")
	}
	if len(input.BudgetArtifact) != 0 {
		return errors.New("BUDGET_NOT_APPLICABLE")
	}

	manifestDigest, err := DigestEvidenceManifest(input.EvidenceManifest)
	if err != nil {
		return fmt.Errorf("digest evidence manifest: %w", err)
	}
	if input.Permit.Claims.EvidenceManifestDigest != manifestDigest {
		return errors.New("EVIDENCE_MANIFEST_MISMATCH")
	}
	if input.EvidenceManifest.IntentID != input.Permit.Claims.IntentID ||
		input.EvidenceManifest.Kind != input.Permit.Claims.Kind ||
		input.EvidenceManifest.Target != input.Permit.Claims.Target ||
		input.EvidenceManifest.ResourceVersion != input.Permit.Claims.ResourceVersion ||
		input.EvidenceManifest.EvidenceDigest != input.Permit.Claims.EvidenceDigest ||
		input.EvidenceManifest.PlanDigest != input.Permit.Claims.PlanDigest {
		return errors.New("EVIDENCE_BINDING_MISMATCH")
	}

	for _, raw := range input.AssumptionArtifacts {
		if err := validateEBAAssumption(raw, now); err != nil {
			return err
		}
	}
	if err := validateEBAAuthority(
		input.AuthorityArtifact,
		input.PrincipalID,
		input.Permit.Claims,
		now,
	); err != nil {
		return err
	}
	if err := VerifyPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		input.Permit,
		input.Approvals,
		now,
	); err != nil {
		return fmt.Errorf("APPROVAL_OR_PERMIT_INVALID: %w", err)
	}
	return nil
}

func validateEBAAssumption(raw json.RawMessage, now time.Time) error {
	var artifact map[string]any
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return fmt.Errorf("ASSUMPTION_INVALID_JSON: %w", err)
	}
	if artifact["contract_version"] != EBAContractVersion {
		return errors.New("ASSUMPTION_CONTRACT_VERSION_INVALID")
	}
	if artifact["kind"] != "AssumptionState" {
		return errors.New("ASSUMPTION_KIND_INVALID")
	}
	if artifact["status"] != "VALID" {
		return fmt.Errorf("ASSUMPTION_NOT_VALID:%v", artifact["status"])
	}
	if err := validateEBAIntegrity(artifact, "ASSUMPTION_INTEGRITY_INVALID"); err != nil {
		return err
	}
	if value, ok := artifact["valid_until"].(string); ok && value != "" {
		expires, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return errors.New("ASSUMPTION_VALID_UNTIL_INVALID")
		}
		if !now.IsZero() && now.UTC().After(expires.UTC()) {
			return errors.New("ASSUMPTION_STALE")
		}
	}
	return nil
}

func validateEBAAuthority(
	raw json.RawMessage,
	principalID string,
	claims PermitClaims,
	now time.Time,
) error {
	var artifact map[string]any
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return fmt.Errorf("AUTHORITY_INVALID_JSON: %w", err)
	}
	if artifact["contract_version"] != EBAContractVersion {
		return errors.New("AUTHORITY_CONTRACT_VERSION_INVALID")
	}
	if artifact["kind"] != "AuthorityGrant" {
		return errors.New("AUTHORITY_KIND_INVALID")
	}
	if revoked, ok := artifact["revoked"].(bool); !ok || revoked {
		return errors.New("AUTHORITY_REVOKED")
	}
	if err := validateEBAIntegrity(artifact, "AUTHORITY_INTEGRITY_INVALID"); err != nil {
		return err
	}

	principal, ok := artifact["principal"].(map[string]any)
	if !ok || principal["id"] != principalID {
		return errors.New("AUTHORITY_PRINCIPAL_MISMATCH")
	}
	if artifact["action_id"] != claims.IntentID {
		return errors.New("AUTHORITY_ACTION_ID_MISMATCH")
	}

	resource := "kubernetes://node/" + claims.Target.Name
	resources, ok := artifact["resource_scope"].([]any)
	if !ok || !containsString(resources, resource) {
		return errors.New("AUTHORITY_RESOURCE_MISMATCH")
	}

	allowed, ok := artifact["allowed_actions"].([]any)
	if !ok || !containsAllowedAction(allowed, "kubernetes", claims.Action, true) {
		return errors.New("AUTHORITY_OPERATION_MISMATCH")
	}

	if constraints, ok := artifact["context_constraints"].(map[string]any); ok {
		if kinds, exists := constraints["kind"]; exists {
			values, ok := kinds.([]any)
			if !ok || !containsString(values, claims.Kind) {
				return errors.New("AUTHORITY_CONTEXT_MISMATCH")
			}
		}
	}

	expectedScope := map[string]any{
		"actor":       principalID,
		"tool":        "kubernetes",
		"operation":   claims.Action,
		"resource":    resource,
		"side_effect": true,
	}
	expectedDigest, err := canonicalMapDigest(expectedScope)
	if err != nil {
		return err
	}
	if artifact["action_scope_digest"] != expectedDigest {
		return errors.New("AUTHORITY_SCOPE_MISMATCH")
	}

	if value, ok := artifact["not_before"].(string); ok && value != "" {
		notBefore, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return errors.New("AUTHORITY_NOT_BEFORE_INVALID")
		}
		if !now.IsZero() && now.UTC().Before(notBefore.UTC()) {
			return errors.New("AUTHORITY_NOT_YET_VALID")
		}
	}
	if value, ok := artifact["expires_at"].(string); ok && value != "" {
		expires, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return errors.New("AUTHORITY_EXPIRES_AT_INVALID")
		}
		if !now.IsZero() && now.UTC().After(expires.UTC()) {
			return errors.New("AUTHORITY_EXPIRED")
		}
	}
	return nil
}

func validateEBAIntegrity(artifact map[string]any, code string) error {
	integrity, ok := artifact["integrity"].(map[string]any)
	if !ok || integrity["algorithm"] != "sha256" {
		return errors.New(code)
	}
	expected, ok := integrity["digest"].(string)
	if !ok || expected == "" {
		return errors.New(code)
	}
	unsigned := make(map[string]any, len(artifact)-1)
	for key, value := range artifact {
		if key == "integrity" {
			continue
		}
		unsigned[key] = value
	}
	actual, err := canonicalMapDigest(unsigned)
	if err != nil {
		return fmt.Errorf("%s: %w", code, err)
	}
	if actual != expected {
		return errors.New(code)
	}
	return nil
}

func canonicalMapDigest(value map[string]any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical map: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func containsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsAllowedAction(values []any, tool, operation string, sideEffect bool) bool {
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if item["tool"] == tool &&
			item["operation"] == operation &&
			item["side_effect"] == sideEffect {
			return true
		}
	}
	return false
}

// CanonicalJSON normalizes arbitrary EBA artifacts for cross-language fixture
// checks. encoding/json orders string map keys deterministically.
func CanonicalJSON(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

// SortedStrings is kept local to the conformance package to make ordering
// expectations explicit in tests without affecting permit semantics.
func SortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
