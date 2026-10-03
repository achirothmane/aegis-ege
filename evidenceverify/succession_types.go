package evidenceverify

// These are portable encodings of existing Genesis, authority, quorum, history
// and identity relations. They do not introduce execution permissions.
type EvidenceGrades struct {
	Effect     string `json:"effect"`
	Succession string `json:"succession"`
	Genesis    string `json:"genesis"`
}

type PortableGenesis struct {
	Payload            []byte `json:"payload"`
	KeyID              string `json:"key_id"`
	Signature          string `json:"signature"`
	CapabilityEnvelope []byte `json:"capability_envelope"`
}

type CustodianGrant struct {
	Purpose   string   `json:"purpose"`
	JournalID string   `json:"journal_id"`
	Custodian Identity `json:"custodian"`
	KeyID     string   `json:"key_id"`
	Scope     string   `json:"scope"`
}

type QuorumPolicy struct {
	Phase          string `json:"phase"`
	GenesisEpoch   uint64 `json:"genesis_epoch"`
	PolicyHash     string `json:"policy_hash"`
	FromPolicyHash string `json:"from_policy_hash,omitempty"`
	ToPolicyHash   string `json:"to_policy_hash,omitempty"`
}

type QuorumTransition struct {
	Ordinal       uint64       `json:"ordinal"`
	WitnessID     string       `json:"witness_id"`
	Before        QuorumPolicy `json:"before"`
	After         QuorumPolicy `json:"after"`
	Head          Head         `json:"head"`
	AuthorityHead Head         `json:"authority_head"`
}

type WitnessState struct {
	Policy        QuorumPolicy `json:"policy"`
	HistoryHead   Head         `json:"history_head"`
	AuthorityHead Head         `json:"authority_head"`
}

type SuccessionObservation struct {
	BuildSHA              string                  `json:"build_sha"`
	CaseID                string                  `json:"case_id"`
	ObservedAt            string                  `json:"observed_at"`
	HistoryBefore         Head                    `json:"history_before"`
	AuthorityBefore       Head                    `json:"authority_before"`
	AuthorityFrozen       Head                    `json:"authority_frozen"`
	AuthorityAfter        Head                    `json:"authority_after"`
	HistoryTransitionHash string                  `json:"history_transition_hash"`
	QuorumTransitionHash  string                  `json:"quorum_transition_hash"`
	Transitions           []QuorumTransition      `json:"transitions"`
	Current               map[string]WitnessState `json:"current"`
}

type Succession struct {
	OldGenesis        PortableGenesis `json:"old_genesis"`
	NewGenesis        PortableGenesis `json:"new_genesis"`
	AuthorityRotation []byte          `json:"authority_rotation"`
	BeforeAnchor      []byte          `json:"before_anchor"`
	Witness           Envelope        `json:"witness"`
}

type SuccessionPolicy struct {
	OldManifestHash        string         `json:"old_manifest_hash"`
	NewManifestHash        string         `json:"new_manifest_hash"`
	HistoryPurpose         string         `json:"history_purpose"`
	OldCheckpoint          Head           `json:"old_checkpoint"`
	OldAuthorityCheckpoint Head           `json:"old_authority_checkpoint"`
	OldCustodian           Identity       `json:"old_custodian"`
	NewCustodian           Identity       `json:"new_custodian"`
	EvaluationTime         string         `json:"evaluation_time"`
	Grades                 EvidenceGrades `json:"grades"`
}
