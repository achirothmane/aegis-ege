// Package evidenceverify re-evaluates portable claims using an independently
// supplied policy. It imports neither the executing runtime nor its adapters.
package evidenceverify

import "encoding/json"

const Schema = "aegis/composite-evidence/v1"

type Envelope struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type Identity struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type State struct {
	Target   string `json:"target"`
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}

func (s State) complete() bool { return s.Target != "" && s.Revision != "" && s.Digest != "" }

type Request struct {
	Subject          Identity `json:"subject"`
	Executor         Identity `json:"executor"`
	Before           State    `json:"before"`
	After            State    `json:"after"`
	Operation        string   `json:"operation"`
	AttemptID        string   `json:"attempt_id"`
	AdmissionBinding string   `json:"admission_binding"`
}

type Admission struct {
	BuildSHA            string `json:"build_sha"`
	CaseID              string `json:"case_id"`
	PolicyHash          string `json:"policy_hash"`
	RequestBinding      string `json:"request_binding"`
	ObservedBefore      State  `json:"observed_before"`
	AllowedOperation    string `json:"allowed_operation"`
	AuthorityEpoch      uint64 `json:"authority_epoch"`
	AuthorityGeneration uint64 `json:"authority_generation"`
	AuthorityActive     bool   `json:"authority_active"`
}

type Execution struct {
	BuildSHA            string          `json:"build_sha"`
	CaseID              string          `json:"case_id"`
	Grade               string          `json:"grade"`
	ClaimType           string          `json:"claim_type"`
	IntentID            string          `json:"intent_id"`
	Request             Request         `json:"request"`
	EffectID            string          `json:"effect_id"`
	CustodyGeneration   uint64          `json:"custody_generation"`
	AuthorityEpoch      uint64          `json:"authority_epoch"`
	AuthorityGeneration uint64          `json:"authority_generation"`
	Admitted            bool            `json:"admitted"`
	AcknowledgementLost bool            `json:"acknowledgement_lost"`
	RecoveredBy         Identity        `json:"recovered_by"`
	ClaimedClosure      string          `json:"claimed_closure"`
	ClaimedCausality    string          `json:"claimed_causality"`
	ClaimedHistory      string          `json:"claimed_history"`
	EvidenceGrades      *EvidenceGrades `json:"evidence_grades,omitempty"`
}

type Commit struct {
	EffectID            string   `json:"effect_id"`
	AttemptID           string   `json:"attempt_id"`
	Owner               Identity `json:"owner"`
	CustodyGeneration   uint64   `json:"custody_generation"`
	AdmissionBinding    string   `json:"admission_binding"`
	AuthorityEpoch      uint64   `json:"authority_epoch"`
	AuthorityGeneration uint64   `json:"authority_generation"`
	AuthorityActive     bool     `json:"authority_active"`
	Operation           string   `json:"operation"`
	Before              State    `json:"before"`
	After               State    `json:"after"`
	CommittedAt         string   `json:"committed_at"`
}

type Destination struct {
	BuildSHA                   string  `json:"build_sha"`
	CaseID                     string  `json:"case_id"`
	Profile                    string  `json:"profile"`
	ObservationError           string  `json:"observation_error,omitempty"`
	Observed                   State   `json:"observed"`
	EffectCount                uint64  `json:"effect_count"`
	Commit                     *Commit `json:"commit,omitempty"`
	AuthorityCurrentlyActive   bool    `json:"authority_currently_active"`
	CurrentAuthorityGeneration uint64  `json:"current_authority_generation"`
}

type Head struct {
	JournalID string `json:"journal_id"`
	Sequence  uint64 `json:"sequence"`
	HeadHash  string `json:"head_hash"`
	KeyID     string `json:"key_id"`
}

type Witness struct {
	BuildSHA string `json:"build_sha"`
	CaseID   string `json:"case_id"`
	Head     Head   `json:"head"`
}

type History struct {
	Entries []json.RawMessage `json:"entries"`
	Anchor  json.RawMessage   `json:"anchor"`
	Witness Envelope          `json:"witness"`
}

type Bundle struct {
	Schema      string      `json:"schema"`
	Admission   Envelope    `json:"admission"`
	Execution   Envelope    `json:"execution"`
	Destination *Envelope   `json:"destination,omitempty"`
	History     *History    `json:"history,omitempty"`
	Succession  *Succession `json:"succession,omitempty"`
}

// Policy must be provisioned through the relying party's independent channel.
// A copy packaged alongside a bundle is demonstration data, not a trust grant.
type Policy struct {
	Schema              string            `json:"schema"`
	BuildSHA            string            `json:"build_sha"`
	CaseID              string            `json:"case_id"`
	DestinationProfile  string            `json:"destination_profile"`
	AdmissionPolicyHash string            `json:"admission_policy_hash"`
	MaximumGrade        string            `json:"maximum_grade"`
	PublicKeys          map[string]string `json:"public_keys"`
	RoleKeys            map[string]string `json:"role_keys"`
	HistoryID           string            `json:"history_id"`
	Checkpoint          *Head             `json:"checkpoint,omitempty"`
	Succession          *SuccessionPolicy `json:"succession,omitempty"`
}

type Report struct {
	Schema                     string          `json:"schema"`
	Structure                  string          `json:"structure"`
	Signatures                 string          `json:"signatures"`
	TrustRoots                 string          `json:"trust_roots"`
	Admitted                   bool            `json:"admitted"`
	IntentID                   string          `json:"intent_id"`
	EffectID                   string          `json:"effect_id"`
	AttemptID                  string          `json:"attempt_id"`
	AuthorityAtCommit          string          `json:"authority_at_commit"`
	AuthorityCurrentlyActive   *bool           `json:"authority_currently_active,omitempty"`
	EffectEvidence             string          `json:"effect_evidence"`
	ExternallyCommittedEffects *uint64         `json:"externally_committed_effects,omitempty"`
	Causality                  string          `json:"causality"`
	Closure                    string          `json:"closure"`
	HistoricalTrust            string          `json:"historical_trust"`
	ClaimType                  string          `json:"claim_type"`
	Grade                      string          `json:"grade"`
	ClaimsSupported            bool            `json:"claims_supported"`
	Uncertainty                []string        `json:"uncertainty"`
	Errors                     []string        `json:"errors"`
	SuccessionValidity         string          `json:"succession_validity"`
	CurrentCustodian           *Identity       `json:"current_custodian,omitempty"`
	CustodianAuthority         string          `json:"custodian_authority"`
	EvidenceGrades             *EvidenceGrades `json:"evidence_grades,omitempty"`
}
