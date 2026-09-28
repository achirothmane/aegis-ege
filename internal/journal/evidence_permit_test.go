package journal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestEvidenceBoundPermitIsProjectedIntoTamperEvidentJournal(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	claims := egeproto.PermitClaims{
		IntentID:               "intent-eep-1",
		Kind:                   "crm.customer_update",
		Target:                 egeproto.Target{Type: "customer", Name: "c-17"},
		Action:                 "update_customer",
		ResourceVersion:        "crm-rv-7",
		EvidenceDigest:         "sha256:runtime",
		EvidenceManifestDigest: "sha256:manifest",
		EvidencePacketDigest:   "sha256:eep-packet",
		PlanDigest:             "sha256:plan",
		ValidUntil:             time.Date(2026, 9, 28, 3, 10, 0, 0, time.UTC),
	}
	permit, err := egeproto.SignPermit(context.Background(), authority, claims)
	if err != nil {
		t.Fatal(err)
	}

	event, err := AuthorizationEventFromEvidenceBoundPermit(
		context.Background(),
		authority,
		permit,
		time.Date(2026, 9, 28, 3, 5, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if event.EvidencePacketDigest != claims.EvidencePacketDigest {
		t.Fatalf("journal packet digest = %q, want %q", event.EvidencePacketDigest, claims.EvidencePacketDigest)
	}
	if event.PayloadDigest == "" {
		t.Fatal("journal authorization event is missing the signed permit payload digest")
	}

	j, path, anchorPath := newTestJournal(t)
	if _, err := j.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if got := j.Verify(context.Background()); !got.Valid || got.EntryCount != 1 {
		t.Fatalf("expected valid evidence-bound journal, got %+v", got)
	}

	lines := readLines(t, path)
	var entry Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	entry.Event.EvidencePacketDigest = "sha256:substituted"
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(tampered)
	writeLines(t, path, lines)

	assertInvalid(t, VerifyFiles(path, anchorPath, j.PublicKey()), "hash mismatch")
}

func TestJournalProjectionRejectsPermitWithoutEvidencePacket(t *testing.T) {
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := egeproto.SignPermit(context.Background(), authority, egeproto.PermitClaims{
		IntentID:               "intent-no-eep",
		Kind:                   "crm.customer_update",
		Target:                 egeproto.Target{Type: "customer", Name: "c-17"},
		Action:                 "update_customer",
		ResourceVersion:        "crm-rv-7",
		EvidenceDigest:         "sha256:runtime",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             time.Date(2026, 9, 28, 3, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = AuthorizationEventFromEvidenceBoundPermit(context.Background(), authority, permit, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "not bound to an evidence packet") {
		t.Fatalf("projection error = %v, want missing evidence-packet binding", err)
	}
}
