package decision

import "time"

type Decision string

const (
	Allow    Decision = "ALLOW"
	Block    Decision = "BLOCK"
	Escalate Decision = "ESCALATE"
)

type ReasonCode string

const (
	EvidenceStale        ReasonCode = "EVIDENCE_STALE"
	EvidenceContradicted ReasonCode = "EVIDENCE_CONTRADICTED"
	InsufficientEvidence ReasonCode = "INSUFFICIENT_EVIDENCE"
)

type EvidenceObservation struct {
	Source     string
	Value      string
	ObservedAt time.Time
}

type Request struct {
	ActionID              string
	Target                string
	RequestedAt           time.Time
	MaxEvidenceAge        time.Duration
	RequiredEvidenceCount int
	Evidence              []EvidenceObservation
}

type Result struct {
	Decision    Decision
	ReasonCodes []ReasonCode
}
