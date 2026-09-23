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
	EvidenceStale            ReasonCode = "EVIDENCE_STALE"
	EvidenceContradicted     ReasonCode = "EVIDENCE_CONTRADICTED"
	InsufficientEvidence     ReasonCode = "INSUFFICIENT_EVIDENCE"
	BlastRadiusExceeded      ReasonCode = "BLAST_RADIUS_EXCEEDED"
	InsufficientStateBinding ReasonCode = "INSUFFICIENT_STATE_BINDING"
	AuthorizationExpired     ReasonCode = "AUTHORIZATION_EXPIRED"
	ResourceVersionChanged   ReasonCode = "RESOURCE_VERSION_CHANGED"
	ExecutionPlanChanged     ReasonCode = "EXECUTION_PLAN_CHANGED"
	ActionChanged            ReasonCode = "ACTION_CHANGED"
	TargetChanged            ReasonCode = "TARGET_CHANGED"
)

type EvidenceObservation struct {
	Claim      string
	Source     string
	Value      string
	ObservedAt time.Time
}

type Request struct {
	ActionID            string
	Action              string
	Target              string
	ResourceVersion     string
	RequestedAt         time.Time
	AuthorizationTTL    time.Duration
	MaxEvidenceAge      time.Duration
	RequiredSourceCount int
	BlastRadius         int
	MaxBlastRadius      int
	Evidence            []EvidenceObservation
}

type Authorization struct {
	ActionID        string
	Action          string
	Target          string
	ResourceVersion string
	EvidenceDigest  string
	PlanDigest      string
	ValidUntil      time.Time
}

type Result struct {
	Decision      Decision
	ReasonCodes   []ReasonCode
	Authorization *Authorization
}

type ExecutionAttempt struct {
	ActionID        string
	Action          string
	Target          string
	ResourceVersion string
	PlanDigest      string
	Now             time.Time
}

type AuthorizationValidation struct {
	Valid       bool
	ReasonCodes []ReasonCode
}
