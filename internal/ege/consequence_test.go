package ege

import (
	"strings"
	"testing"
	"time"
)

func consequenceTestClaims(now time.Time) PermitClaims {
	return PermitClaims{
		IntentID:        "intent-consequence-1",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		Action:          "drain",
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ValidUntil:      now.Add(time.Minute),
	}
}

func consequenceTestManifest(claims PermitClaims, observedAt time.Time) EvidenceManifest {
	return EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        claims.IntentID,
		Kind:            claims.Kind,
		Target:          claims.Target,
		ResourceVersion: claims.ResourceVersion,
		EvidenceDigest:  claims.EvidenceDigest,
		PlanDigest:      claims.PlanDigest,
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"state", "plan"},
	}
}

func TestEvaluateConsequenceAdmissionAllowsBoundFreshNodeDrain(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	claims := consequenceTestClaims(now)
	policy := KubernetesNodeDrainConsequencePolicy(15 * time.Second)

	admission, err := EvaluateConsequenceAdmission(
		policy,
		claims,
		consequenceTestManifest(claims, now.Add(-10*time.Second)),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Decision != ConsequenceDecisionAdmissible {
		t.Fatalf("expected ADMISSIBLE, got %s", admission.Decision)
	}
	if admission.ConsequenceClass != ConsequenceClassOperationalStateChange {
		t.Fatalf("unexpected consequence class %q", admission.ConsequenceClass)
	}
	if admission.PolicyHash == "" || admission.ActionScopeDigest == "" {
		t.Fatal("expected policy and action digests")
	}
	if err := ValidateConsequenceAdmission(admission); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateConsequenceAdmissionBlocksStaleEvidence(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	claims := consequenceTestClaims(now)
	policy := KubernetesNodeDrainConsequencePolicy(15 * time.Second)

	admission, err := EvaluateConsequenceAdmission(
		policy,
		claims,
		consequenceTestManifest(claims, now.Add(-16*time.Second)),
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "CONSEQUENCE_EVIDENCE_STALE") {
		t.Fatalf("expected stale-evidence rejection, got %v", err)
	}
	if admission.Decision != ConsequenceDecisionBlocked {
		t.Fatalf("expected BLOCKED admission, got %s", admission.Decision)
	}
}

func TestEvaluateConsequenceAdmissionBlocksActionOutsidePolicy(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	claims := consequenceTestClaims(now)
	policy := KubernetesNodeDrainConsequencePolicy(15 * time.Second)
	policy.AllowedActions = []string{"delete"}

	admission, err := EvaluateConsequenceAdmission(
		policy,
		claims,
		consequenceTestManifest(claims, now.Add(-time.Second)),
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "CONSEQUENCE_ACTION_NOT_ADMISSIBLE") {
		t.Fatalf("expected action-policy rejection, got %v", err)
	}
	if admission.Decision != ConsequenceDecisionBlocked {
		t.Fatalf("expected BLOCKED admission, got %s", admission.Decision)
	}
}

func TestConsequencePolicyHashIsStableAcrossSetOrdering(t *testing.T) {
	left := KubernetesNodeDrainConsequencePolicy(15 * time.Second)
	left.AllowedKinds = []string{"b", "a"}
	left.AllowedActions = []string{"z", "a"}

	right := KubernetesNodeDrainConsequencePolicy(15 * time.Second)
	right.AllowedKinds = []string{"a", "b"}
	right.AllowedActions = []string{"a", "z"}

	leftHash, err := consequencePolicyHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := consequencePolicyHash(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftHash != rightHash {
		t.Fatalf("equivalent consequence policy sets produced different hashes: %s vs %s", leftHash, rightHash)
	}
}

func TestConsequenceActionScopeDigestChangesWithBoundTarget(t *testing.T) {
	now := time.Now().UTC()
	left := consequenceTestClaims(now)
	right := left
	right.Target.Name = "node-8"

	leftDigest, err := consequenceActionScopeDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := consequenceActionScopeDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("materially changed target retained the same action-scope digest")
	}
}
