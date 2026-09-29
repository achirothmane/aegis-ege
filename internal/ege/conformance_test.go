package ege

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadEBAFixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "eba", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func rewriteEBAFixture(
	t *testing.T,
	raw json.RawMessage,
	mutate func(map[string]any),
) json.RawMessage {
	t.Helper()
	var artifact map[string]any
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	mutate(artifact)
	delete(artifact, "integrity")
	digest, err := canonicalMapDigest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact["integrity"] = map[string]any{
		"algorithm": "sha256",
		"digest":    digest,
	}
	body, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func validKubernetesDrainConformanceScenario(t *testing.T) (
	KubernetesDrainConformanceInput,
	PermitAuthority,
	PermitAuthority,
	time.Time,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 18, 0, 30, 0, time.UTC)

	permitAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approvalAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}

	manifest := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        "intent-1",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ObservedAt:      now.Add(-30 * time.Second),
		EvidenceClasses: []string{"state", "pdb", "plan"},
	}
	manifestDigest, err := DigestEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}

	traceID := "tr_k8s_drain_001"
	audience := "aegis-ege"
	namespace := "deployment:aegis-ege"

	assumption := rewriteEBAFixture(t, loadEBAFixture(t, "assumption-state.json"), func(artifact map[string]any) {
		artifact["context_profile"] = EBAContextProfileVersion
		artifact["trace_id"] = traceID
		artifact["subject_ref"] = manifest.IntentID
		artifact["evidence_refs"] = []any{manifest.EvidenceDigest}
		artifact["trust"] = map[string]any{
			"mode":      "authenticated_parent_binding",
			"issuer":    "assumption-gate/kubernetes-drain-profile",
			"audience":  audience,
			"namespace": namespace,
		}
	})
	authority := rewriteEBAFixture(t, loadEBAFixture(t, "authority-grant.json"), func(artifact map[string]any) {
		artifact["context_profile"] = EBAContextProfileVersion
		artifact["trace_id"] = traceID
		artifact["subject_ref"] = manifest.IntentID
		artifact["trust"] = map[string]any{
			"mode":      "authenticated_parent_binding",
			"issuer":    "policy:kubernetes-drain-authority-v1",
			"audience":  audience,
			"namespace": namespace,
		}
	})
	assumptionRef, err := EBAArtifactRef(assumption)
	if err != nil {
		t.Fatal(err)
	}
	authorityRef, err := EBAArtifactRef(authority)
	if err != nil {
		t.Fatal(err)
	}

	claims := PermitClaims{
		IntentID:               "intent-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: manifestDigest,
		PlanDigest:             "sha256:plan",
		EBAContextProfile:      EBAContextProfileVersion,
		EBATraceID:             traceID,
		EBAAudience:            audience,
		EBANamespace:           namespace,
		EBAAssumptionRefs:      []string{assumptionRef},
		EBAAuthorityRef:        authorityRef,
		ValidUntil:             now.Add(2 * time.Minute),
	}
	approval, err := SignApproval(ctx, approvalAuthority, ApprovalClaims{
		ApprovalID:      "approval-1",
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
	permit, err := SignPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		claims,
		[]ApprovalAttestation{approval},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}

	return KubernetesDrainConformanceInput{
		PrincipalID:         "aegis-ege",
		AssumptionArtifacts: []json.RawMessage{assumption},
		AuthorityArtifact:   authority,
		Approvals:           []ApprovalAttestation{approval},
		EvidenceManifest:    manifest,
		Permit:              permit,
	}, permitAuthority, approvalAuthority, now
}

func TestEBAKubernetesDrainConformanceScenario(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	if err := ValidateKubernetesDrainConformance(
		context.Background(),
		permitAuthority,
		approvalAuthority,
		input,
		now,
	); err != nil {
		t.Fatalf("valid cross-project conformance scenario rejected: %v", err)
	}
}

func TestEBAKubernetesDrainConformanceFailsClosedWhenAssumptionMissing(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AssumptionArtifacts = nil

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "ASSUMPTION_REFERENCE_MISSING") {
		t.Fatalf("expected missing assumption block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsTamperedAuthority(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	var authority map[string]any
	if err := json.Unmarshal(input.AuthorityArtifact, &authority); err != nil {
		t.Fatal(err)
	}
	authority["resource_scope"] = []any{"kubernetes://node/node-999"}
	body, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	input.AuthorityArtifact = body

	err = ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "AUTHORITY_INTEGRITY_INVALID") {
		t.Fatalf("expected tampered authority block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsMissingApproval(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.Approvals = nil

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "APPROVAL_REFERENCE_MISSING") {
		t.Fatalf("expected missing approval block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsSyntheticTokenBudget(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.BudgetArtifact = json.RawMessage(`{"kind":"BudgetReservation"}`)

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "BUDGET_NOT_APPLICABLE") {
		t.Fatalf("expected non-applicable budget block, got %v", err)
	}
}



func TestEBAKubernetesDrainConformanceRejectsAuthorityAtExactExpiry(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AuthorityArtifact = rewriteEBAFixture(t, input.AuthorityArtifact, func(artifact map[string]any) {
		artifact["expires_at"] = now.Format(time.RFC3339)
	})

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "AUTHORITY_EXPIRED") {
		t.Fatalf("expected exact-expiry authority block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsMissingAuthorityExpiry(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AuthorityArtifact = rewriteEBAFixture(t, input.AuthorityArtifact, func(artifact map[string]any) {
		delete(artifact, "expires_at")
	})

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "AUTHORITY_EXPIRES_AT_INVALID") {
		t.Fatalf("expected missing authority expiry block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsAssumptionAtExactExpiry(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AssumptionArtifacts[0] = rewriteEBAFixture(t, input.AssumptionArtifacts[0], func(artifact map[string]any) {
		artifact["valid_until"] = now.Format(time.RFC3339)
	})

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "ASSUMPTION_STALE") {
		t.Fatalf("expected exact-expiry assumption block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsMalformedAssumptionExpiry(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AssumptionArtifacts[0] = rewriteEBAFixture(t, input.AssumptionArtifacts[0], func(artifact map[string]any) {
		artifact["valid_until"] = 123
	})

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "ASSUMPTION_VALID_UNTIL_INVALID") {
		t.Fatalf("expected malformed assumption expiry block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsFutureAssumptionCheck(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.AssumptionArtifacts[0] = rewriteEBAFixture(t, input.AssumptionArtifacts[0], func(artifact map[string]any) {
		artifact["checked_at"] = now.Add(time.Second).Format(time.RFC3339)
	})

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "ASSUMPTION_CHECKED_AT_FUTURE") {
		t.Fatalf("expected future assumption check block, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRequiresExplicitClock(t *testing.T) {
	input, permitAuthority, approvalAuthority, _ := validKubernetesDrainConformanceScenario(t)
	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, time.Time{},
	)
	if err == nil || !strings.Contains(err.Error(), "EBA_EVALUATION_TIME_REQUIRED") {
		t.Fatalf("expected explicit evaluation time requirement, got %v", err)
	}
}

func TestEBAKubernetesDrainConformanceRejectsEvidenceManifestMismatch(t *testing.T) {
	input, permitAuthority, approvalAuthority, now := validKubernetesDrainConformanceScenario(t)
	input.EvidenceManifest.PlanDigest = "sha256:other-plan"

	err := ValidateKubernetesDrainConformance(
		context.Background(), permitAuthority, approvalAuthority, input, now,
	)
	if err == nil || !strings.Contains(err.Error(), "EVIDENCE_MANIFEST_MISMATCH") {
		t.Fatalf("expected evidence mismatch block, got %v", err)
	}
}
