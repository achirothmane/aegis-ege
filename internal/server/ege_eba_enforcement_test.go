package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

func signedEBAArtifact(t *testing.T, value map[string]any) json.RawMessage {
	t.Helper()
	unsigned, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(unsigned)
	value["integrity"] = map[string]any{
		"algorithm": "sha256",
		"digest":    hex.EncodeToString(sum[:]),
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func canonicalTestDigest(t *testing.T, value map[string]any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func newEBAExecuteFixture(t *testing.T) (
	*Server,
	*fakeController,
	egeproto.Permit,
	egeExecutionEBABundle,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 18, 30, 0, 0, time.UTC)

	permitAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approvalAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}

	manifest := egeproto.EvidenceManifest{
		APIVersion:      egeproto.EvidenceManifestVersion,
		IntentID:        "intent-eba-1",
		Kind:            egeNodeDrainKind,
		Target:          egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ObservedAt:      now.Add(-10 * time.Second),
		EvidenceClasses: []string{"state", "pdb", "plan"},
	}
	manifestDigest, err := egeproto.DigestEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}

	claims := egeproto.PermitClaims{
		IntentID:               manifest.IntentID,
		Kind:                   manifest.Kind,
		Target:                 manifest.Target,
		Action:                 "drain",
		ResourceVersion:        manifest.ResourceVersion,
		EvidenceDigest:         manifest.EvidenceDigest,
		EvidenceManifestDigest: manifestDigest,
		PlanDigest:             manifest.PlanDigest,
		ValidUntil:             now.Add(2 * time.Minute),
	}

	approval, err := egeproto.SignApproval(ctx, approvalAuthority, egeproto.ApprovalClaims{
		ApprovalID:      "approval-eba-1",
		IntentID:        claims.IntentID,
		ApproverID:      "human:release-owner",
		Kind:            claims.Kind,
		Target:          claims.Target,
		Action:          claims.Action,
		ResourceVersion: claims.ResourceVersion,
		PlanDigest:      claims.PlanDigest,
		ValidUntil:      now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	permit, err := egeproto.SignPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		claims,
		[]egeproto.ApprovalAttestation{approval},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}

	assumption := signedEBAArtifact(t, map[string]any{
		"contract_version":     egeproto.EBAContractVersion,
		"kind":                 "AssumptionState",
		"id":                   "as_eba_1",
		"trace_id":             "tr_eba_1",
		"producer":             "assumption-gate/kubernetes-drain-profile",
		"created_at":           now.Format(time.RFC3339),
		"assumption_id":        "kubernetes.node-drain-preconditions-hold",
		"proposition":          "The observed node and workload state still satisfies the drain preconditions.",
		"status":               "VALID",
		"evidence_refs":        []any{"sha256:evidence"},
		"dependencies":         []any{"node-resource-version", "pod-set", "pdb-state"},
		"checked_at":           now.Format(time.RFC3339),
		"valid_until":          now.Add(time.Minute).Format(time.RFC3339),
		"invalidation_reasons": []any{},
	})

	scope := map[string]any{
		"actor":       "aegis-ege",
		"tool":        "kubernetes",
		"operation":   "drain",
		"resource":    "kubernetes://node/node-7",
		"side_effect": true,
	}
	authority := signedEBAArtifact(t, map[string]any{
		"contract_version": egeproto.EBAContractVersion,
		"kind":             "AuthorityGrant",
		"id":               "auth_eba_1",
		"trace_id":         "tr_eba_1",
		"producer":         "agent-action-guard/kubernetes-drain-profile",
		"created_at":       now.Format(time.RFC3339),
		"principal":        map[string]any{"type": "agent", "id": "aegis-ege"},
		"allowed_actions": []any{
			map[string]any{"tool": "kubernetes", "operation": "drain", "side_effect": true},
		},
		"resource_scope":      []any{"kubernetes://node/node-7"},
		"context_constraints": map[string]any{"kind": []any{egeNodeDrainKind}},
		"issued_by":           "policy:kubernetes-drain-authority-v1",
		"not_before":          now.Add(-time.Minute).Format(time.RFC3339),
		"expires_at":          now.Add(time.Minute).Format(time.RFC3339),
		"revoked":             false,
		"policy_ref":          "kubernetes-drain-authority-v1",
		"matched_allow_rule_ids": []any{
			"allow-aegis-node-drain",
		},
		"action_id":           claims.IntentID,
		"action_scope_digest": canonicalTestDigest(t, scope),
	})

	controller := &fakeController{
		report: kubeadapter.GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: claims.PlanDigest,
		},
	}
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(controller, store, Config{
		MutationsEnabled:      true,
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		ReplayGuard:           replay,
		Clock:                 func() time.Time { return now },
		EGEPermitAuthority:    permitAuthority,
		RequireEBAConformance: true,
		EBAApprovalAuthority:  approvalAuthority,
		EBAExecutionPrincipal: "aegis-ege",
	})
	if err != nil {
		t.Fatal(err)
	}

	return s, controller, permit, egeExecutionEBABundle{
		EvidenceManifest:    &manifest,
		AssumptionArtifacts: []json.RawMessage{assumption},
		AuthorityArtifact:   authority,
		Approvals:           []egeproto.ApprovalAttestation{approval},
	}
}

func TestNewRequiresApprovalAuthorityWhenEBAEnforcementEnabled(t *testing.T) {
	_, err := New(&fakeController{}, nil, Config{RequireEBAConformance: true})
	if err == nil || !strings.Contains(err.Error(), "EBA approval authority") {
		t.Fatalf("expected EBA approval authority requirement, got %v", err)
	}
}

func TestEGEExecuteEBAEnforcementRejectsMissingBundleBeforeReplayOrController(t *testing.T) {
	s, controller, permit, _ := newEBAExecuteFixture(t)

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-eba-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "EBA_CONFORMANCE_REQUIRED") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("missing EBA bundle must not reach controller")
	}
}

func TestEGEExecuteEBAEnforcementAllowsConformantBundle(t *testing.T) {
	s, controller, permit, bundle := newEBAExecuteFixture(t)

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-eba-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
		EBA:      &bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 1 {
		t.Fatalf("expected conformant EBA request to reach controller once, got %d", controller.executeCalls)
	}
}

func TestEGEExecuteEBAEnforcementRejectsTamperedAuthority(t *testing.T) {
	s, controller, permit, bundle := newEBAExecuteFixture(t)

	var authority map[string]any
	if err := json.Unmarshal(bundle.AuthorityArtifact, &authority); err != nil {
		t.Fatal(err)
	}
	authority["resource_scope"] = []any{"kubernetes://node/node-999"}
	tampered, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	bundle.AuthorityArtifact = tampered

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-eba-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
		EBA:      &bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "EBA_CONFORMANCE_BLOCKED") ||
		!strings.Contains(recorder.Body.String(), "AUTHORITY_INTEGRITY_INVALID") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("tampered authority must not reach controller")
	}
}

func TestEGEExecuteRemainsBackwardCompatibleWhenEBAEnforcementDisabled(t *testing.T) {
	now := time.Date(2026, 9, 27, 18, 30, 0, 0, time.UTC)
	permitAuthority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	manifest := egeproto.EvidenceManifest{
		APIVersion:      egeproto.EvidenceManifestVersion,
		IntentID:        "intent-legacy-1",
		Kind:            egeNodeDrainKind,
		Target:          egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ObservedAt:      now.Add(-time.Second),
		EvidenceClasses: []string{"state"},
	}
	manifestDigest, err := egeproto.DigestEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := egeproto.SignPermit(context.Background(), permitAuthority, egeproto.PermitClaims{
		IntentID:               manifest.IntentID,
		Kind:                   manifest.Kind,
		Target:                 manifest.Target,
		Action:                 "drain",
		ResourceVersion:        manifest.ResourceVersion,
		EvidenceDigest:         manifest.EvidenceDigest,
		EvidenceManifestDigest: manifestDigest,
		PlanDigest:             manifest.PlanDigest,
		ValidUntil:             now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	controller := &fakeController{
		report: kubeadapter.GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: manifest.PlanDigest,
		},
	}
	store := kubeadapter.NewMemoryDrainCheckpointStore()
	replay, err := NewFileReplayGuard(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(controller, store, Config{
		MutationsEnabled:      true,
		RequireAuthentication: true,
		Authorizer:            allowAuthorizer{},
		ReplayGuard:           replay,
		Clock:                 func() time.Time { return now },
		EGEPermitAuthority:    permitAuthority,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: manifest.IntentID,
		Kind:     manifest.Kind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected legacy 200 with EBA enforcement disabled, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 1 {
		t.Fatalf("legacy request should still reach controller, got %d calls", controller.executeCalls)
	}
}
