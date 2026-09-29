package evidencepipeline

import "time"

const PacketVersion = "aegis.ege/evidence-packet/v0alpha2"

type Source struct {
	Name           string `json:"name"`
	TrustDomain    string `json:"trust_domain"`
	AttestationRef string `json:"attestation_ref,omitempty"`
}

type Actor struct {
	PrincipalID string `json:"principal_id"`
	AgentID     string `json:"agent_id,omitempty"`
}

type Action struct {
	Kind       string `json:"kind"`
	Tool       string `json:"tool"`
	Operation  string `json:"operation"`
	Target     string `json:"target"`
	SideEffect bool   `json:"side_effect"`
}

type RuntimeEvent struct {
	IntentID   string         `json:"intent_id"`
	EventID    string         `json:"event_id"`
	WorkflowID string         `json:"workflow_id,omitempty"`
	RunID      string         `json:"run_id,omitempty"`
	Actor      Actor          `json:"actor"`
	Action     Action         `json:"action"`
	ObservedAt time.Time      `json:"observed_at"`
	Data       map[string]any `json:"data"`
}

type ExecutionBinding struct {
	DestinationID           string `json:"destination_id"`
	AccountID               string `json:"account_id"`
	Endpoint                string `json:"endpoint"`
	AdapterProfile          string `json:"adapter_profile"`
	ExpectedResourceVersion string `json:"expected_resource_version"`
}

type BootstrapContext struct {
	AuthorityRef        string            `json:"authority_ref"`
	PolicyRef           string            `json:"policy_ref"`
	RedactionProfileRef string            `json:"redaction_profile_ref"`
	ConsequenceClass    string            `json:"consequence_class"`
	ExecutionBinding    *ExecutionBinding `json:"execution_binding,omitempty"`
	ControlRefs         []string          `json:"control_refs,omitempty"`
	ApprovalRefs        []string          `json:"approval_refs,omitempty"`
}

type CompileRequest struct {
	Event          RuntimeEvent
	Source         Source
	Context        BootstrapContext
	SensitivePaths []string
	CapturedAt     time.Time
}

type Provenance struct {
	Source      Source    `json:"source"`
	EventID     string    `json:"event_id"`
	WorkflowID  string    `json:"workflow_id,omitempty"`
	RunID       string    `json:"run_id,omitempty"`
	InputDigest string    `json:"input_digest"`
	ObservedAt  time.Time `json:"observed_at"`
	CapturedAt  time.Time `json:"captured_at"`
}

type RedactionSummary struct {
	ProfileRef    string   `json:"profile_ref"`
	RedactedPaths []string `json:"redacted_paths,omitempty"`
}

type Integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type Packet struct {
	APIVersion string           `json:"api_version"`
	IntentID   string           `json:"intent_id"`
	Provenance Provenance       `json:"provenance"`
	Actor      Actor            `json:"actor"`
	Action     Action           `json:"action"`
	Context    BootstrapContext `json:"context"`
	Evidence   map[string]any   `json:"evidence"`
	Redaction  RedactionSummary `json:"redaction"`
	Integrity  Integrity        `json:"integrity"`
}
