package evidenceverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Field ordering follows journal v2's signed/hash encoding. This intentionally
// independent implementation is tested against producer-generated records.
type historyEvent struct {
	Type                 string    `json:"type"`
	ActionID             string    `json:"action_id,omitempty"`
	Target               string    `json:"target,omitempty"`
	Decision             string    `json:"decision,omitempty"`
	ReasonCodes          []string  `json:"reason_codes,omitempty"`
	EvidenceDigest       string    `json:"evidence_digest,omitempty"`
	EvidencePacketDigest string    `json:"evidence_packet_digest,omitempty"`
	PlanDigest           string    `json:"plan_digest,omitempty"`
	AttemptID            string    `json:"attempt_id,omitempty"`
	DestinationID        string    `json:"destination_id,omitempty"`
	AccountID            string    `json:"account_id,omitempty"`
	ObservationHandle    string    `json:"observation_handle,omitempty"`
	AttemptState         string    `json:"attempt_state,omitempty"`
	OutcomeVerdict       string    `json:"outcome_verdict,omitempty"`
	PayloadDigest        string    `json:"payload_digest,omitempty"`
	OccurredAt           time.Time `json:"occurred_at"`
}

type historyEntry struct {
	Version   int          `json:"version"`
	JournalID string       `json:"journal_id"`
	Sequence  uint64       `json:"sequence"`
	PrevHash  string       `json:"prev_hash"`
	Event     historyEvent `json:"event"`
	EntryHash string       `json:"entry_hash"`
}

type historyAnchor struct {
	Version   int       `json:"version"`
	JournalID string    `json:"journal_id"`
	Sequence  uint64    `json:"sequence"`
	HeadHash  string    `json:"head_hash"`
	KeyID     string    `json:"key_id"`
	UpdatedAt time.Time `json:"updated_at"`
	Signature string    `json:"signature"`
}

func (a *assessment) history(b Bundle, e Execution) {
	h := b.History
	if a.p.Checkpoint == nil || a.p.HistoryID == "" {
		a.uncertain("No independently supplied history identity and checkpoint; local signatures cannot establish continuity")
		return
	}
	var witness Witness
	if !a.statement("witness", h.Witness, &witness) {
		return
	}
	if witness.BuildSHA != a.p.BuildSHA || witness.CaseID != a.p.CaseID || witness.Head != *a.p.Checkpoint || witness.Head.JournalID != a.p.HistoryID {
		a.uncertain("Witness differs from the independently expected history head")
		return
	}
	var anchor historyAnchor
	if err := Decode(h.Anchor, &anchor); err != nil {
		a.r.Structure = "INVALID"
		a.fail("history anchor: " + err.Error())
		return
	}
	head := Head{anchor.JournalID, anchor.Sequence, anchor.HeadHash, anchor.KeyID}
	if anchor.Version != 2 || head != witness.Head || anchor.UpdatedAt.IsZero() {
		a.uncertain("Signed anchor does not reach the expected history head")
		return
	}
	key, ok := a.key("history", anchor.KeyID)
	if !ok {
		return
	}
	sig, err := base64.StdEncoding.DecodeString(anchor.Signature)
	anchor.Signature = ""
	payload, marshalErr := json.Marshal(anchor)
	if err != nil || marshalErr != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, payload, sig) {
		a.r.Signatures = "INVALID"
		a.fail("history anchor signature is invalid")
		return
	}
	if len(h.Entries) == 0 || uint64(len(h.Entries)) != anchor.Sequence {
		a.uncertain("History entries are incomplete at the expected checkpoint")
		return
	}
	prev := ""
	var last historyEvent
	for i, raw := range h.Entries {
		var entry historyEntry
		if err := Decode(raw, &entry); err != nil {
			a.r.Structure = "INVALID"
			a.fail("history entry: " + err.Error())
			return
		}
		if entry.Version != 2 || entry.JournalID != a.p.HistoryID || entry.Sequence != uint64(i)+1 || entry.PrevHash != prev || entry.Event.OccurredAt.IsZero() {
			a.uncertain("History identity, sequence or predecessor is discontinuous")
			return
		}
		expected := entry.EntryHash
		entry.EntryHash = ""
		payload, err := json.Marshal(entry)
		if err != nil || ContentDigest(payload) != expected {
			a.uncertain("History entry hash does not match its content")
			return
		}
		prev, last = expected, entry.Event
	}
	if prev != anchor.HeadHash {
		a.uncertain("History chain does not reach the independently pinned head")
		return
	}
	if last.Type != "OUTCOME" || last.ActionID != e.EffectID || last.AttemptID != e.Request.AttemptID || last.PayloadDigest != BundleHistoryBinding(b) || last.OutcomeVerdict != e.ClaimedClosure {
		a.uncertain("History does not bind the exact evidence and outcome being evaluated")
		return
	}
	a.r.HistoricalTrust = "TRUSTED_HISTORY"
}
