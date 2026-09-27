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

	claims := PermitClaims{
		IntentID:               "intent-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: manifestDigest,
		PlanDigest:             "sha256:plan",
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
		AssumptionArtifacts: []json.RawMessage{loadEBAFixture(t, "assumption-state.json")},
		AuthorityArtifact:   loadEBAFixture(t, "authority-grant.json"),
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
