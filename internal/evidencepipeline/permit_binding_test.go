package evidencepipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestSignEvidenceBoundPermitBindsPacketDigest(t *testing.T) {
	packet, err := Compile(fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}

	claims := fixturePermitClaims(packet)
	permit, err := SignEvidenceBoundPermit(context.Background(), authority, packet, claims)
	if err != nil {
		t.Fatal(err)
	}
	if permit.Claims.EvidencePacketDigest != packet.Integrity.Digest {
		t.Fatalf("evidence packet digest = %q, want %q", permit.Claims.EvidencePacketDigest, packet.Integrity.Digest)
	}
	if err := egeproto.VerifyPermit(context.Background(), authority, permit); err != nil {
		t.Fatalf("evidence-bound permit rejected: %v", err)
	}

	permit.Claims.EvidencePacketDigest = "sha256:tampered"
	if err := egeproto.VerifyPermit(context.Background(), authority, permit); err == nil {
		t.Fatal("tampered evidence packet digest unexpectedly verified")
	}
}

func TestBindPermitClaimsRejectsWrongActionBinding(t *testing.T) {
	packet, err := Compile(fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	claims := fixturePermitClaims(packet)
	claims.Target.Name = "c-99"

	_, err = BindPermitClaims(packet, claims)
	if err == nil || !strings.Contains(err.Error(), "target mismatch") {
		t.Fatalf("BindPermitClaims() error = %v, want target mismatch", err)
	}
}

func TestBindPermitClaimsRejectsReadOnlyPacketForExecutionPermit(t *testing.T) {
	req := fixtureRequest()
	req.Event.Action.SideEffect = false
	packet, err := Compile(req)
	if err != nil {
		t.Fatal(err)
	}
	claims := fixturePermitClaims(packet)

	_, err = BindPermitClaims(packet, claims)
	if err == nil || !strings.Contains(err.Error(), "side-effecting") {
		t.Fatalf("BindPermitClaims() error = %v, want side-effect binding failure", err)
	}
}

func fixturePermitClaims(packet Packet) egeproto.PermitClaims {
	return egeproto.PermitClaims{
		IntentID:               packet.IntentID,
		Kind:                   packet.Action.Kind,
		Target:                 egeproto.Target{Type: "customer", Name: "c-17"},
		Action:                 packet.Action.Operation,
		ResourceVersion:        "crm-rv-7",
		EvidenceDigest:         "sha256:runtime-evidence",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             time.Date(2026, 9, 28, 3, 10, 0, 0, time.UTC),
	}
}
