package ege

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const EBAContractVersion = "eba.integration/v0.1"
const EBAContextProfileVersion = "eba.context/v1"
const EBACanonicalProfileVersion = "eba.canonical-json/v1"

const maxCanonicalSafeInteger int64 = 9007199254740991

type KubernetesDrainConformanceInput struct {
	PrincipalID        string
	Audience           string
	Namespace          string
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
	if now.IsZero() {
		return errors.New("EBA_EVALUATION_TIME_REQUIRED")
	}
	now = now.UTC()
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
	claims := input.Permit.Claims
	if claims.EBAContextProfile != EBAContextProfileVersion {
		return errors.New("EBA_CONTEXT_PROFILE_INVALID")
	}
	if input.Audience == "" || input.Namespace == "" {
		return errors.New("EBA_CONSUMER_CONTEXT_MISSING")
	}
	if claims.EBATraceID == "" || claims.EBAAudience == "" || claims.EBANamespace == "" {
		return errors.New("EBA_CONTEXT_BINDING_MISSING")
	}
	if claims.EBAAudience != input.Audience {
		return errors.New("EBA_AUDIENCE_MISMATCH")
	}
	if claims.EBANamespace != input.Namespace {
		return errors.New("EBA_NAMESPACE_MISMATCH")
	}
	if claims.EBAAuthorityRef == "" || len(claims.EBAAssumptionRefs) == 0 {
		return errors.New("EBA_ARTIFACT_BINDING_MISSING")
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

	actualAssumptionRefs := make([]string, 0, len(input.AssumptionArtifacts))
	for _, raw := range input.AssumptionArtifacts {
		ref, err := EBAArtifactRef(raw)
		if err != nil {
			return fmt.Errorf("ASSUMPTION_REFERENCE_INVALID: %w", err)
		}
		actualAssumptionRefs = append(actualAssumptionRefs, ref)
		if err := validateEBAAssumption(raw, input.Permit.Claims, now); err != nil {
			return err
		}
	}
	sort.Strings(actualAssumptionRefs)
	expectedAssumptionRefs := append([]string(nil), input.Permit.Claims.EBAAssumptionRefs...)
	sort.Strings(expectedAssumptionRefs)
	if len(actualAssumptionRefs) != len(expectedAssumptionRefs) {
		return errors.New("ASSUMPTION_REFERENCE_SET_MISMATCH")
	}
	for i := range actualAssumptionRefs {
		if actualAssumptionRefs[i] != expectedAssumptionRefs[i] {
			return errors.New("ASSUMPTION_REFERENCE_SET_MISMATCH")
		}
	}

	authorityRef, err := EBAArtifactRef(input.AuthorityArtifact)
	if err != nil {
		return fmt.Errorf("AUTHORITY_REFERENCE_INVALID: %w", err)
	}
	if authorityRef != input.Permit.Claims.EBAAuthorityRef {
		return errors.New("AUTHORITY_REFERENCE_MISMATCH")
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

func validateEBAAssumption(raw json.RawMessage, claims PermitClaims, now time.Time) error {
	artifact, err := decodeCanonicalObject(raw)
	if err != nil {
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
	if artifact["context_profile"] != EBAContextProfileVersion {
		return errors.New("ASSUMPTION_CONTEXT_PROFILE_INVALID")
	}
	if artifact["canonical_profile"] != EBACanonicalProfileVersion {
		return errors.New("ASSUMPTION_CANONICAL_PROFILE_INVALID")
	}
	if artifact["trace_id"] != claims.EBATraceID {
		return errors.New("ASSUMPTION_TRACE_MISMATCH")
	}
	if artifact["subject_ref"] != claims.IntentID {
		return errors.New("ASSUMPTION_SUBJECT_MISMATCH")
	}
	trust, ok := artifact["trust"].(map[string]any)
	if !ok || trust["mode"] != "authenticated_parent_binding" {
		return errors.New("ASSUMPTION_TRUST_ENVELOPE_INVALID")
	}
	if trust["audience"] != claims.EBAAudience {
		return errors.New("ASSUMPTION_AUDIENCE_MISMATCH")
	}
	if trust["namespace"] != claims.EBANamespace {
		return errors.New("ASSUMPTION_NAMESPACE_MISMATCH")
	}
	evidenceRefs, ok := artifact["evidence_refs"].([]any)
	if !ok || len(evidenceRefs) != 1 || evidenceRefs[0] != claims.EvidenceDigest {
		return errors.New("ASSUMPTION_EVIDENCE_BINDING_MISMATCH")
	}
	if err := validateEBAIntegrity(artifact, "ASSUMPTION_INTEGRITY_INVALID"); err != nil {
		return err
	}
	checkedAtValue, ok := artifact["checked_at"].(string)
	if !ok || checkedAtValue == "" {
		return errors.New("ASSUMPTION_CHECKED_AT_INVALID")
	}
	checkedAt, err := time.Parse(time.RFC3339, checkedAtValue)
	if err != nil {
		return errors.New("ASSUMPTION_CHECKED_AT_INVALID")
	}
	if checkedAt.UTC().After(now.UTC()) {
		return errors.New("ASSUMPTION_CHECKED_AT_FUTURE")
	}

	value, ok := artifact["valid_until"].(string)
	if !ok || value == "" {
		return errors.New("ASSUMPTION_VALID_UNTIL_INVALID")
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.New("ASSUMPTION_VALID_UNTIL_INVALID")
	}
	if !now.UTC().Before(expires.UTC()) {
		return errors.New("ASSUMPTION_STALE")
	}
	return nil
}

func validateEBAAuthority(
	raw json.RawMessage,
	principalID string,
	claims PermitClaims,
	now time.Time,
) error {
	artifact, err := decodeCanonicalObject(raw)
	if err != nil {
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
	if artifact["context_profile"] != EBAContextProfileVersion {
		return errors.New("AUTHORITY_CONTEXT_PROFILE_INVALID")
	}
	if artifact["canonical_profile"] != EBACanonicalProfileVersion {
		return errors.New("AUTHORITY_CANONICAL_PROFILE_INVALID")
	}
	if artifact["trace_id"] != claims.EBATraceID {
		return errors.New("AUTHORITY_TRACE_MISMATCH")
	}
	if artifact["subject_ref"] != claims.IntentID {
		return errors.New("AUTHORITY_SUBJECT_MISMATCH")
	}
	trust, ok := artifact["trust"].(map[string]any)
	if !ok || trust["mode"] != "authenticated_parent_binding" {
		return errors.New("AUTHORITY_TRUST_ENVELOPE_INVALID")
	}
	if trust["audience"] != claims.EBAAudience {
		return errors.New("AUTHORITY_AUDIENCE_MISMATCH")
	}
	if trust["namespace"] != claims.EBANamespace {
		return errors.New("AUTHORITY_NAMESPACE_MISMATCH")
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

	notBeforeValue, ok := artifact["not_before"].(string)
	if !ok || notBeforeValue == "" {
		return errors.New("AUTHORITY_NOT_BEFORE_INVALID")
	}
	notBefore, err := time.Parse(time.RFC3339, notBeforeValue)
	if err != nil {
		return errors.New("AUTHORITY_NOT_BEFORE_INVALID")
	}
	expiresValue, ok := artifact["expires_at"].(string)
	if !ok || expiresValue == "" {
		return errors.New("AUTHORITY_EXPIRES_AT_INVALID")
	}
	expires, err := time.Parse(time.RFC3339, expiresValue)
	if err != nil {
		return errors.New("AUTHORITY_EXPIRES_AT_INVALID")
	}
	if !expires.UTC().After(notBefore.UTC()) {
		return errors.New("AUTHORITY_WINDOW_INVALID")
	}
	if now.UTC().Before(notBefore.UTC()) {
		return errors.New("AUTHORITY_NOT_YET_VALID")
	}
	if !now.UTC().Before(expires.UTC()) {
		return errors.New("AUTHORITY_EXPIRED")
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

func EBAArtifactRef(raw json.RawMessage) (string, error) {
	body, err := CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalMapDigest(value map[string]any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical map: %w", err)
	}
	body, err := CanonicalJSON(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize map: %w", err)
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

// CanonicalJSON implements eba.canonical-json/v1 for cross-language EBA
// artifacts. The supported number domain is integer-only within IEEE-754's
// exact safe range. Object keys are unique, strings are Unicode scalar values,
// map keys are sorted by encoding/json, and Go's JSON string escaping is the
// canonical escape form (including HTML characters and U+2028/U+2029).
func CanonicalJSON(raw json.RawMessage) ([]byte, error) {
	value, err := decodeCanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func decodeCanonicalObject(raw json.RawMessage) (map[string]any, error) {
	value, err := decodeCanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("CANONICAL_ROOT_MUST_BE_OBJECT")
	}
	return object, nil
}

func decodeCanonicalJSON(raw json.RawMessage) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("CANONICAL_UTF8_INVALID")
	}
	if err := validateJSONStringEscapes(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := readCanonicalValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("CANONICAL_TRAILING_DATA")
		}
		return nil, fmt.Errorf("CANONICAL_JSON_INVALID: %w", err)
	}
	return value, nil
}

func readCanonicalValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("CANONICAL_JSON_INVALID: %w", err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("CANONICAL_JSON_INVALID: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("CANONICAL_OBJECT_KEY_INVALID")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("CANONICAL_DUPLICATE_KEY:%s", key)
				}
				item, err := readCanonicalValue(dec)
				if err != nil {
					return nil, err
				}
				object[key] = item
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("CANONICAL_JSON_INVALID")
			}
			return object, nil
		case '[':
			items := make([]any, 0)
			for dec.More() {
				item, err := readCanonicalValue(dec)
				if err != nil {
					return nil, err
				}
				items = append(items, item)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("CANONICAL_JSON_INVALID")
			}
			return items, nil
		default:
			return nil, errors.New("CANONICAL_JSON_INVALID")
		}
	case json.Number:
		rawNumber := value.String()
		if rawNumber == "-0" {
			return nil, errors.New("CANONICAL_NEGATIVE_ZERO")
		}
		if strings.ContainsAny(rawNumber, ".eE") {
			return nil, fmt.Errorf("CANONICAL_NON_INTEGER_NUMBER:%s", rawNumber)
		}
		parsed, err := strconv.ParseInt(rawNumber, 10, 64)
		if err != nil || parsed < -maxCanonicalSafeInteger || parsed > maxCanonicalSafeInteger {
			return nil, fmt.Errorf("CANONICAL_INTEGER_OUT_OF_RANGE:%s", rawNumber)
		}
		return json.Number(strconv.FormatInt(parsed, 10)), nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, fmt.Errorf("CANONICAL_TYPE_UNSUPPORTED:%T", value)
	}
}

func validateJSONStringEscapes(raw []byte) error {
	for i := 0; i < len(raw); {
		if raw[i] != '"' {
			i++
			continue
		}
		i++
		closed := false
		for i < len(raw) {
			switch raw[i] {
			case '"':
				i++
				closed = true
			case '\\':
				i++
				if i >= len(raw) {
					return errors.New("CANONICAL_JSON_INVALID")
				}
				if raw[i] != 'u' {
					i++
					continue
				}
				if i+4 >= len(raw) {
					return errors.New("CANONICAL_JSON_INVALID")
				}
				code, ok := parseHex4(raw[i+1 : i+5])
				if !ok {
					return errors.New("CANONICAL_JSON_INVALID")
				}
				if code >= 0xD800 && code <= 0xDBFF {
					if i+10 >= len(raw) || raw[i+5] != '\\' || raw[i+6] != 'u' {
						return errors.New("CANONICAL_STRING_INVALID")
					}
					low, ok := parseHex4(raw[i+7 : i+11])
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return errors.New("CANONICAL_STRING_INVALID")
					}
					i += 11
					continue
				}
				if code >= 0xDC00 && code <= 0xDFFF {
					return errors.New("CANONICAL_STRING_INVALID")
				}
				i += 5
			default:
				if raw[i] < 0x20 {
					return errors.New("CANONICAL_STRING_INVALID")
				}
				i++
			}
			if closed {
				break
			}
		}
		if !closed {
			return errors.New("CANONICAL_JSON_INVALID")
		}
	}
	return nil
}

func parseHex4(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, ch := range raw {
		value <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			value |= uint16(ch - '0')
		case ch >= 'a' && ch <= 'f':
			value |= uint16(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			value |= uint16(ch-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// SortedStrings is kept local to the conformance package to make ordering
// expectations explicit in tests without affecting permit semantics.
func SortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
