package evidenceverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const authorityRotationVersion = "aegis-ege/successor-governance-rotation/v1"

type quorumMember struct {
	ID                string `json:"id"`
	TrustManifestHash string `json:"trust_manifest_hash"`
}
type quorumPolicyDocument struct {
	Protocol  string         `json:"protocol"`
	Threshold int            `json:"threshold"`
	Members   []quorumMember `json:"members"`
}
type historyIdentity struct {
	Purpose   string `json:"purpose"`
	JournalID string `json:"journal_id"`
}
type historyPolicyDocument struct {
	Protocol  string            `json:"protocol"`
	Histories []historyIdentity `json:"histories"`
}
type governanceDocument struct {
	Protocol    string `json:"protocol"`
	AuthorityID string `json:"authority_id"`
	PublicKey   string `json:"public_key_base64"`
}
type successionCapability struct {
	Quorum     quorumPolicyDocument  `json:"external_witness_quorum"`
	History    historyPolicyDocument `json:"governed_histories"`
	Governance governanceDocument    `json:"enrollment_successor_governance"`
	Custody    CustodianGrant        `json:"history_custody"`
}
type successionGenesis struct {
	epoch                                                         uint64
	manifest, envelope, quorum, history, governance, authorityKey string
	cap                                                           successionCapability
	validFrom, validUntil                                         time.Time
}

// Encodings mirror the existing signed protocol, without importing its
// implementation. Transport bytes are canonicalized only in this bounded
// ASCII/exact-integer profile; incompatible encodings fail closed.
type rotationAuthorization struct {
	Version                   string    `json:"version"`
	RotationID                string    `json:"rotation_id"`
	JournalID                 string    `json:"journal_id"`
	PreviousSequence          uint64    `json:"previous_sequence"`
	PreviousHeadHash          string    `json:"previous_head_hash"`
	PreviousKeyID             string    `json:"previous_key_id"`
	OldGenesisManifestHash    string    `json:"old_genesis_manifest_hash"`
	NewGenesisManifestHash    string    `json:"new_genesis_manifest_hash"`
	OldGenesisEpoch           uint64    `json:"old_genesis_epoch"`
	OldCapabilityEnvelopeHash string    `json:"old_capability_envelope_hash"`
	OldPolicyHash             string    `json:"old_policy_hash"`
	OldAuthorityID            string    `json:"old_authority_id"`
	OldAuthorityKeyID         string    `json:"old_authority_key_id"`
	NewGenesisEpoch           uint64    `json:"new_genesis_epoch"`
	NewCapabilityEnvelopeHash string    `json:"new_capability_envelope_hash"`
	NewPolicyHash             string    `json:"new_policy_hash"`
	NewAuthorityID            string    `json:"new_authority_id"`
	NewAuthorityKeyID         string    `json:"new_authority_key_id"`
	NotBefore                 time.Time `json:"not_before"`
	ExpiresAt                 time.Time `json:"expires_at"`
}
type rotationApproval struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type signedRotation struct {
	Authorization rotationAuthorization `json:"authorization"`
	OldApproval   rotationApproval      `json:"old_approval"`
	NewApproval   rotationApproval      `json:"new_approval"`
}

func keyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return "ed25519:" + hex.EncodeToString(sum[:12])
}

func (a *assessment) verifySignature(role, id string, payload []byte, signature string) bool {
	key, ok := a.key(role, id)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || !ed25519.Verify(key, payload, sig) {
		a.r.Signatures = "INVALID"
		a.fail(role + ": invalid signature")
		return false
	}
	return true
}

func (a *assessment) genesis(role string, p PortableGenesis, expectedHash string) (successionGenesis, error) {
	var fields map[string]json.RawMessage
	if err := Decode(p.Payload, &fields); err != nil {
		return successionGenesis{}, err
	}
	canonical, err := successionCanonical(fields)
	if err != nil || !bytes.Equal(canonical, p.Payload) {
		return successionGenesis{}, fmt.Errorf("unsupported/noncanonical Genesis payload")
	}
	if ContentDigest(p.Payload) != expectedHash || !a.verifySignature(role, p.KeyID, p.Payload, p.Signature) {
		return successionGenesis{}, fmt.Errorf("Genesis differs from independently expected manifest/root")
	}
	var manifest struct {
		Epoch  uint64 `json:"genesis_epoch"`
		Threat struct {
			Envelope string `json:"capability_envelope_hash"`
		} `json:"threat_model"`
		Validity struct {
			From  time.Time `json:"valid_from"`
			Until time.Time `json:"valid_until"`
		} `json:"validity"`
		Supply struct {
			Revision string `json:"source_revision"`
		} `json:"supply_chain"`
	}
	if err := json.Unmarshal(p.Payload, &manifest); err != nil {
		return successionGenesis{}, err
	}
	g := successionGenesis{epoch: manifest.Epoch, manifest: expectedHash, envelope: ContentDigest(p.CapabilityEnvelope), validFrom: manifest.Validity.From, validUntil: manifest.Validity.Until}
	if g.epoch == 0 || g.envelope != manifest.Threat.Envelope || manifest.Supply.Revision != a.p.BuildSHA || g.validFrom.IsZero() || !g.validUntil.After(g.validFrom) {
		return g, fmt.Errorf("Genesis epoch/envelope/build/validity mismatch")
	}
	if err := Decode(p.CapabilityEnvelope, &g.cap); err != nil {
		return g, err
	}
	q := &g.cap.Quorum
	if q.Protocol != "aegis-ege/quorum-trust-policy/v1" || q.Threshold <= len(q.Members)/2 || q.Threshold > len(q.Members) {
		return g, fmt.Errorf("unsafe quorum")
	}
	sort.Slice(q.Members, func(i, j int) bool { return q.Members[i].ID < q.Members[j].ID })
	for i, m := range q.Members {
		if m.ID == "" || len(m.TrustManifestHash) != 71 || (i > 0 && q.Members[i-1].ID == m.ID) {
			return g, fmt.Errorf("invalid witness identity")
		}
	}
	g.quorum = successionDigest("", q)
	h := &g.cap.History
	if h.Protocol != "aegis-ege/governed-history-trust-policy/v1" || len(h.Histories) == 0 {
		return g, fmt.Errorf("history policy missing")
	}
	sort.Slice(h.Histories, func(i, j int) bool { return h.Histories[i].Purpose < h.Histories[j].Purpose })
	found := false
	for i, id := range h.Histories {
		if id.Purpose == "" || id.JournalID == "" || (i > 0 && h.Histories[i-1].Purpose == id.Purpose) {
			return g, fmt.Errorf("ambiguous history purpose")
		}
		if id.Purpose == a.p.Succession.HistoryPurpose && id.JournalID == a.p.HistoryID {
			found = true
		}
	}
	if !found {
		return g, fmt.Errorf("Genesis does not govern the expected history")
	}
	g.history = successionDigest("", h)
	gov := g.cap.Governance
	pub, err := base64.StdEncoding.DecodeString(gov.PublicKey)
	if err != nil || len(pub) != 32 || gov.AuthorityID == "" || gov.Protocol != "aegis-ege/enrollment-successor-governance-policy/v1" {
		return g, fmt.Errorf("invalid successor-governance policy")
	}
	g.governance = successionDigest("", gov)
	g.authorityKey = keyFingerprint(pub)
	return g, nil
}

func authorityStateDigest(g successionGenesis) string {
	return successionDigest("aegis-ege/successor-governance-authority-state/v1\x00", map[string]any{"genesis_epoch": g.epoch, "genesis_manifest_hash": g.manifest, "capability_envelope_hash": g.envelope, "policy_hash": g.governance, "authority_id": g.cap.Governance.AuthorityID, "authority_key_id": g.authorityKey})
}

func (a *assessment) succession(b Bundle, e Execution) {
	a.r.SuccessionValidity = "INVALID"
	if b.Succession == nil || a.p.Succession == nil || a.p.Checkpoint == nil || b.History == nil {
		a.fail("succession needs an independent policy, predecessor and current history checkpoint")
		return
	}
	s, p := b.Succession, a.p.Succession
	if e.EvidenceGrades == nil || *e.EvidenceGrades != p.Grades {
		a.fail("component grades differ from independently expected evidence")
		return
	}
	minimum := 4
	for _, grade := range []string{p.Grades.Effect, p.Grades.Succession, p.Grades.Genesis} {
		r := gradeRank[grade]
		if r == 0 {
			a.fail("unsupported component assurance grade")
			return
		}
		if r < minimum {
			minimum = r
		}
	}
	if gradeRank[e.Grade] != minimum {
		a.fail("composite grade exceeds its weakest evidence component")
		return
	}
	a.r.EvidenceGrades = e.EvidenceGrades
	old, err := a.genesis("old_genesis", s.OldGenesis, p.OldManifestHash)
	if err != nil {
		a.fail("old Genesis: " + err.Error())
		return
	}
	new, err := a.genesis("new_genesis", s.NewGenesis, p.NewManifestHash)
	if err != nil {
		a.fail("new Genesis: " + err.Error())
		return
	}
	now, err := time.Parse(time.RFC3339Nano, p.EvaluationTime)
	if err != nil || new.epoch <= old.epoch || e.AuthorityEpoch != old.epoch || now.Before(old.validFrom) || !now.Before(old.validUntil) || now.Before(new.validFrom) || !now.Before(new.validUntil) {
		a.fail("succession epoch or independently supplied evaluation time invalid")
		return
	}
	for i, g := range []successionGenesis{old, new} {
		role, want := "old_history", p.OldCustodian
		if i == 1 {
			role, want = "history", p.NewCustodian
		}
		grant := g.cap.Custody
		_, ok := a.key(role, grant.KeyID)
		if !ok || grant.Purpose != p.HistoryPurpose || grant.JournalID != a.p.HistoryID || grant.Custodian != want || want.ID == "" || want.Kind == "" || grant.Scope != "append_history" {
			a.fail("custodian grant does not bind the independently expected identity/key/history/scope")
			return
		}
	}
	if p.OldCustodian == p.NewCustodian || old.cap.Custody.KeyID == new.cap.Custody.KeyID {
		a.fail("profile requires an actual custodian/key change")
		return
	}
	var rotation signedRotation
	if err := Decode(s.AuthorityRotation, &rotation); err != nil {
		a.fail("authority rotation: " + err.Error())
		return
	}
	r := rotation.Authorization
	before := p.OldAuthorityCheckpoint
	if r.Version != authorityRotationVersion || r.RotationID == "" || r.JournalID != "governance/enrollment-successor-authority" || before.JournalID != r.JournalID || r.PreviousSequence != before.Sequence || r.PreviousHeadHash != before.HeadHash || r.PreviousKeyID != before.KeyID || before.HeadHash != authorityStateDigest(old) || before.KeyID != old.authorityKey || before.Sequence > (1<<53)-3 || r.OldGenesisEpoch != old.epoch || r.NewGenesisEpoch != new.epoch || r.OldGenesisManifestHash != old.manifest || r.NewGenesisManifestHash != new.manifest || r.OldCapabilityEnvelopeHash != old.envelope || r.NewCapabilityEnvelopeHash != new.envelope || r.OldPolicyHash != old.governance || r.NewPolicyHash != new.governance || r.OldAuthorityID != old.cap.Governance.AuthorityID || r.NewAuthorityID != new.cap.Governance.AuthorityID || r.OldAuthorityKeyID != old.authorityKey || r.NewAuthorityKeyID != new.authorityKey || old.authorityKey == new.authorityKey || old.governance == new.governance || r.NotBefore.IsZero() || !r.ExpiresAt.After(r.NotBefore) || now.Before(r.NotBefore) || !now.Before(r.ExpiresAt) {
		a.fail("authority rotation does not bind the exact predecessor and both Genesis sources")
		return
	}
	raw, err := successionCanonical(r)
	if err != nil {
		a.fail(err.Error())
		return
	}
	for i, approval := range []rotationApproval{rotation.OldApproval, rotation.NewApproval} {
		role, want := "old_authority", old
		if i == 1 {
			role, want = "new_authority", new
		}
		key, ok := a.key(role, approval.KeyID)
		if !ok || approval.KeyID != want.authorityKey || base64.StdEncoding.EncodeToString(key) != want.cap.Governance.PublicKey || !a.verifySignature(role, approval.KeyID, append([]byte(authorityRotationVersion+"\x00"), raw...), approval.Signature) {
			a.fail("rotation needs both exact independently trusted authority approvals")
			return
		}
	}
	digest := successionDigest("aegis-ege/signed-successor-governance-rotation/v1\x00", rotation)
	frozen := Head{r.JournalID, before.Sequence + 1, digest, "joint:" + digest}
	active := Head{r.JournalID, before.Sequence + 2, authorityStateDigest(new), new.authorityKey + "/rotation/" + digest}
	var observation SuccessionObservation
	if !a.statement("succession_witness", s.Witness, &observation) {
		return
	}
	observedAt, timeErr := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	if timeErr != nil || observedAt.After(now) || observedAt.Before(r.NotBefore) || !observedAt.Before(r.ExpiresAt) || observation.BuildSHA != a.p.BuildSHA || observation.CaseID != a.p.CaseID || observation.HistoryBefore != p.OldCheckpoint || observation.AuthorityBefore != before || observation.AuthorityFrozen != frozen || observation.AuthorityAfter != active || p.OldCheckpoint.JournalID != a.p.HistoryID || p.OldCheckpoint.Sequence == 0 || p.OldCheckpoint.KeyID != old.cap.Custody.KeyID || a.p.Checkpoint.Sequence <= p.OldCheckpoint.Sequence || a.p.Checkpoint.KeyID != new.cap.Custody.KeyID {
		a.fail("succession observation differs from exact predecessor/transition/checkpoint")
		return
	}
	if !a.predecessorAnchor(s.BeforeAnchor, p.OldCheckpoint) {
		return
	}
	if err := verifyQuorumSuccession(old, new, p.OldCheckpoint, *a.p.Checkpoint, frozen, active, observation, p.HistoryPurpose); err != nil {
		a.fail(err.Error())
		return
	}
	if b.Destination != nil {
		var d Destination
		if Decode(b.Destination.Payload, &d) == nil && d.Commit != nil {
			committedAt, timeErr := time.Parse(time.RFC3339Nano, d.Commit.CommittedAt)
			if timeErr != nil || committedAt.Before(old.validFrom) || !committedAt.Before(old.validUntil) || committedAt.After(observedAt) {
				a.fail("effect timestamp does not fall under old Genesis before succession observation")
				return
			}
		}
	}
	a.r.SuccessionValidity = "VALID"
	a.r.CustodianAuthority = "AUTHORIZED_AT_CHECKPOINT"
	a.r.CurrentCustodian = &p.NewCustodian
	a.uncertain("Custodian authority is append/observe authority at this checkpoint, not permission for new destination effects or future perpetual authority")
}

func (a *assessment) predecessorAnchor(raw []byte, head Head) bool {
	var anchor historyAnchor
	if err := Decode(raw, &anchor); err != nil {
		a.fail("predecessor anchor: " + err.Error())
		return false
	}
	if anchor.Version != 2 || (Head{anchor.JournalID, anchor.Sequence, anchor.HeadHash, anchor.KeyID}) != head || anchor.UpdatedAt.IsZero() {
		a.fail("predecessor signed anchor differs from independently retained checkpoint")
		return false
	}
	signature := anchor.Signature
	anchor.Signature = ""
	payload, _ := json.Marshal(anchor)
	return a.verifySignature("old_history", head.KeyID, payload, signature)
}

func verifyQuorumSuccession(old, new successionGenesis, h, final, frozen, active Head, o SuccessionObservation, purpose string) error {
	oldMembers, newMembers := map[string]string{}, map[string]string{}
	for _, m := range old.cap.Quorum.Members {
		oldMembers[m.ID] = m.TrustManifestHash
	}
	for _, m := range new.cap.Quorum.Members {
		newMembers[m.ID] = m.TrustManifestHash
	}
	shared := []string{}
	for id, hash := range oldMembers {
		if newMembers[id] == hash {
			shared = append(shared, id)
		}
	}
	sort.Strings(shared)
	if len(shared) < len(oldMembers)-old.cap.Quorum.Threshold+1 || len(shared) < len(newMembers)-new.cap.Quorum.Threshold+1 || len(shared) < new.cap.Quorum.Threshold {
		return fmt.Errorf("succession lacks a stable quorum-blocking shared set")
	}
	qhash := successionDigest("", map[string]any{"version": "aegis-ege/quorum-rotation/v1", "journal_id": h.JournalID, "sequence": h.Sequence, "head_hash": h.HeadHash, "key_id": h.KeyID, "old_genesis_epoch": old.epoch, "old_genesis_manifest_hash": old.manifest, "old_policy_hash": old.quorum, "new_genesis_epoch": new.epoch, "new_genesis_manifest_hash": new.manifest, "new_policy_hash": new.quorum, "shared_witnesses": shared})
	hhash := successionDigest("", map[string]any{"version": "aegis-ege/history-succession/v1", "purpose": purpose, "journal_id": h.JournalID, "sequence": h.Sequence, "head_hash": h.HeadHash, "key_id": h.KeyID, "old_genesis_epoch": old.epoch, "old_genesis_manifest_hash": old.manifest, "old_capability_envelope_hash": old.envelope, "old_history_policy_hash": old.history, "old_quorum_policy_hash": old.quorum, "new_genesis_epoch": new.epoch, "new_genesis_manifest_hash": new.manifest, "new_capability_envelope_hash": new.envelope, "new_history_policy_hash": new.history, "new_quorum_policy_hash": new.quorum, "quorum_transition_hash": qhash})
	if qhash == "" || hhash == "" || o.QuorumTransitionHash != qhash || o.HistoryTransitionHash != hhash {
		return fmt.Errorf("succession commitments do not bind the exact history head/Genesis pair")
	}
	oldPolicy := QuorumPolicy{Phase: "ACTIVE", GenesisEpoch: old.epoch, PolicyHash: old.quorum}
	newPolicy := QuorumPolicy{Phase: "ACTIVE", GenesisEpoch: new.epoch, PolicyHash: new.quorum}
	joint := QuorumPolicy{Phase: "JOINT_FROZEN", GenesisEpoch: new.epoch, PolicyHash: qhash, FromPolicyHash: old.quorum, ToPolicyHash: new.quorum}
	states := map[string]QuorumPolicy{}
	for id := range oldMembers {
		states[id] = oldPolicy
	}
	for id := range newMembers {
		if _, ok := states[id]; !ok {
			states[id] = newPolicy
		}
	}
	allowed := map[string]bool{}
	for _, id := range shared {
		allowed[id] = true
	}
	allFrozen := false
	for i, transition := range o.Transitions {
		if transition.Ordinal != uint64(i)+1 || !allowed[transition.WitnessID] || transition.Head != h || transition.AuthorityHead != frozen || transition.Before != states[transition.WitnessID] {
			return fmt.Errorf("native succession trace is discontinuous or changes the frozen head")
		}
		switch {
		case transition.Before == oldPolicy && transition.After == joint:
		case transition.Before == joint && transition.After == newPolicy && allFrozen:
		default:
			return fmt.Errorf("native trace bypasses JOINT_FROZEN or enables NEW before every shared witness is frozen")
		}
		states[transition.WitnessID] = transition.After
		if !allFrozen {
			allFrozen = true
			for _, id := range shared {
				if states[id] != joint {
					allFrozen = false
				}
			}
		}
		oldCount, newCount := 0, 0
		for id, policy := range states {
			if _, ok := oldMembers[id]; ok && policy == oldPolicy {
				oldCount++
			}
			if _, ok := newMembers[id]; ok && policy == newPolicy {
				newCount++
			}
		}
		if oldCount >= old.cap.Quorum.Threshold && newCount >= new.cap.Quorum.Threshold {
			return fmt.Errorf("old and new authority simultaneously current")
		}
	}
	if len(o.Current) != len(states) {
		return fmt.Errorf("native observation omits a configured witness")
	}
	newCount := 0
	for id, policy := range states {
		current, ok := o.Current[id]
		if !ok || current.Policy != policy {
			return fmt.Errorf("current witness policy differs from retained trace")
		}
		if _, ok := newMembers[id]; ok && policy == newPolicy && current.HistoryHead == final && current.AuthorityHead == active {
			newCount++
		}
	}
	for _, id := range shared {
		if states[id] != newPolicy {
			return fmt.Errorf("succession did not activate every shared witness")
		}
	}
	if newCount < new.cap.Quorum.Threshold {
		return fmt.Errorf("new quorum does not hold both current authority and the continued history")
	}
	return nil
}
