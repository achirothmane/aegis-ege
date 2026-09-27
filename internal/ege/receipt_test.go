package ege

import (
	"context"
	"testing"
	"time"
)

func receiptTestPermit(t *testing.T, now time.Time) Permit {
	t.Helper()
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermit(context.Background(), authority, PermitClaims{
		IntentID:               "intent-receipt-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return permit
}

func TestExecutionReceiptProducesBoundEvidence(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC)
	receipt, evidence, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:      receiptTestPermit(t, now),
		Decision:    "ALLOW",
		PlanDigest:  "sha256:plan",
		StartedAt:   now,
		FinishedAt:  now.Add(2 * time.Second),
		ResourceChanges: []ReceiptResourceChange{
			{Resource: "kubernetes://node/node-7", Operation: "CORDON_NODE", Result: "APPLIED"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ContractVersion != EBAContractVersion || receipt.Kind != ExecutionReceiptKind {
		t.Fatalf("unexpected receipt contract: %+v", receipt)
	}
	if receipt.Outcome != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED, got %s", receipt.Outcome)
	}
	if len(receipt.ProducedEvidenceRefs) != 1 || receipt.ProducedEvidenceRefs[0] != evidence.ID {
		t.Fatalf("receipt/evidence reference mismatch")
	}
	if evidence.SourceRef != receipt.ID || evidence.Claims.ActionDigest != receipt.ActionDigest {
		t.Fatalf("evidence is not bound to receipt/action")
	}
	if err := ValidateExecutionReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceiptEvidence(evidence, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionReceiptMapsEscalationWithoutClaimingSuccess(t *testing.T) {
	now := time.Now().UTC()
	receipt, _, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:      receiptTestPermit(t, now),
		Decision:    "ESCALATE",
		ReasonCodes: []string{"EXECUTION_PLAN_CHANGED"},
		PlanDigest:  "sha256:plan",
		StartedAt:   now,
		FinishedAt:  now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != "ESCALATED" {
		t.Fatalf("expected ESCALATED, got %s", receipt.Outcome)
	}
}

func TestExecutionReceiptTamperingBreaksIntegrity(t *testing.T) {
	now := time.Now().UTC()
	receipt, _, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:     receiptTestPermit(t, now),
		Decision:   "ALLOW",
		PlanDigest: "sha256:plan",
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Outcome = "BLOCKED"
	if err := ValidateExecutionReceipt(receipt); err == nil {
		t.Fatal("tampered receipt unexpectedly validated")
	}
}

func TestReceiptEvidenceTamperingBreaksIntegrity(t *testing.T) {
	now := time.Now().UTC()
	receipt, evidence, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:     receiptTestPermit(t, now),
		Decision:   "ALLOW",
		PlanDigest: "sha256:plan",
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence.Claims.Outcome = "BLOCKED"
	if err := ValidateReceiptEvidence(evidence, receipt); err == nil {
		t.Fatal("tampered receipt evidence unexpectedly validated")
	}
}

func TestExecutionReceiptActionDigestChangesWithBoundAction(t *testing.T) {
	now := time.Now().UTC()
	permit := receiptTestPermit(t, now)
	left, _, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:     permit,
		Decision:   "ALLOW",
		PlanDigest: permit.Claims.PlanDigest,
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	changed := permit
	changed.Claims.ResourceVersion = "101"
	right, _, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:     changed,
		Decision:   "ALLOW",
		PlanDigest: changed.Claims.PlanDigest,
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if left.ActionDigest == right.ActionDigest {
		t.Fatal("materially changed action retained same action digest")
	}
}


func TestExecutionReceiptBindsConsequenceAdmissionIntoProducedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 27, 19, 30, 0, 0, time.UTC)
	permit := receiptTestPermit(t, now)
	manifest := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        permit.Claims.IntentID,
		Kind:            permit.Claims.Kind,
		Target:          permit.Claims.Target,
		ResourceVersion: permit.Claims.ResourceVersion,
		EvidenceDigest:  permit.Claims.EvidenceDigest,
		PlanDigest:      permit.Claims.PlanDigest,
		ObservedAt:      now,
	}
	admission, err := EvaluateConsequenceAdmission(
		KubernetesNodeDrainConsequencePolicy(15*time.Second),
		permit.Claims,
		manifest,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}

	receipt, evidence, err := BuildExecutionReceiptFeedback(ExecutionReceiptInput{
		Permit:               permit,
		Decision:             "ALLOW",
		PlanDigest:           permit.Claims.PlanDigest,
		StartedAt:            now.Add(time.Second),
		FinishedAt:           now.Add(2 * time.Second),
		ConsequenceAdmission: &admission,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ConsequenceAdmission == nil {
		t.Fatal("expected consequence admission in execution receipt")
	}
	if evidence.Claims.ConsequenceAdmissionDigest == "" {
		t.Fatal("expected produced evidence to bind consequence admission")
	}
	if err := ValidateExecutionReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceiptEvidence(evidence, receipt); err != nil {
		t.Fatal(err)
	}
}
