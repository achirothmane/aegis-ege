package ege

import (
	"context"
	"testing"
	"time"
)

func TestSignedPermitRejectsTampering(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
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
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             time.Now().UTC().Add(time.Minute),
	}
	permit, err := SignPermit(context.Background(), authority, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPermit(context.Background(), authority, permit); err != nil {
		t.Fatalf("valid permit rejected: %v", err)
	}

	permit.Claims.PlanDigest = "sha256:tampered"
	if err := VerifyPermit(context.Background(), authority, permit); err == nil {
		t.Fatal("tampered permit unexpectedly verified")
	}
}

func TestEvidenceManifestDigestIsStableAcrossEvidenceClassOrder(t *testing.T) {
	observedAt := time.Date(2026, 9, 25, 15, 0, 0, 0, time.UTC)
	left := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        "intent-1",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"server-dry-run", "state", "pdb"},
	}
	right := left
	right.EvidenceClasses = []string{"pdb", "server-dry-run", "state"}

	leftDigest, err := DigestEvidenceManifest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := DigestEvidenceManifest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("manifest digest changed with evidence class order: %s != %s", leftDigest, rightDigest)
	}
}
