package ege

import (
	"context"
	"testing"
	"time"
)

func approvalClaims(now time.Time) ApprovalClaims {
	return ApprovalClaims{
		ApprovalID:      "approval-1",
		IntentID:        "intent-1",
		ApproverID:      "human:release-owner",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		Action:          "drain",
		ResourceVersion: "100",
		PlanDigest:      "sha256:plan",
		ValidUntil:      now.Add(5 * time.Minute),
	}
}

func permitClaims(now time.Time) PermitClaims {
	return PermitClaims{
		IntentID:               "intent-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             now.Add(3 * time.Minute),
	}
}

func TestSignedApprovalCanBeBoundIntoPermit(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC)

	approvalAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permitAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}

	approval, err := SignApproval(ctx, approvalAuthority, approvalClaims(now))
	if err != nil {
		t.Fatal(err)
	}

	permit, err := SignPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		permitClaims(now),
		[]ApprovalAttestation{approval},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(permit.Claims.ApprovalRefs) != 1 {
		t.Fatalf("expected one approval ref, got %d", len(permit.Claims.ApprovalRefs))
	}
	if err := VerifyPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		permit,
		[]ApprovalAttestation{approval},
		now,
	); err != nil {
		t.Fatalf("valid permit+approval rejected: %v", err)
	}
}

func TestApprovalTamperingIsRejected(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignApproval(ctx, authority, approvalClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	approval.Claims.PlanDigest = "sha256:tampered"
	if err := VerifyApproval(ctx, authority, approval); err == nil {
		t.Fatal("tampered approval unexpectedly verified")
	}
}

func TestApprovalForDifferentPlanIsRejected(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignApproval(ctx, authority, approvalClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	claims := permitClaims(now)
	claims.PlanDigest = "sha256:other-plan"
	if err := ValidateApprovalForPermit(ctx, authority, approval, claims, now); err == nil {
		t.Fatal("approval for another plan unexpectedly accepted")
	}
}

func TestExpiredApprovalIsRejected(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	claims := approvalClaims(now)
	claims.ValidUntil = now.Add(-time.Second)
	approval, err := SignApproval(ctx, authority, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateApprovalForPermit(ctx, authority, approval, permitClaims(now), now); err == nil {
		t.Fatal("expired approval unexpectedly accepted")
	}
}

func TestPermitVerificationRequiresExactApprovalSet(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	approvalAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permitAuthority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignApproval(ctx, approvalAuthority, approvalClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		permitClaims(now),
		[]ApprovalAttestation{approval},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPermitWithApprovals(
		ctx,
		permitAuthority,
		approvalAuthority,
		permit,
		nil,
		now,
	); err == nil {
		t.Fatal("permit unexpectedly verified without referenced approval")
	}
}

func TestApprovalReferenceIsStable(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC)
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignApproval(ctx, authority, approvalClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	left, err := ApprovalRef(approval)
	if err != nil {
		t.Fatal(err)
	}
	right, err := ApprovalRef(approval)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("approval ref is not stable: %s != %s", left, right)
	}
}
