package simulation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/easl/genesis"
)

const successionHistoryID = "history:succession:composite"
const successionPurpose = "composite-finality"

// Preparation is separate from the evidence directory. Private fixture keys
// are never uploaded. Genesis is signed by the existing bootstrap test fixture
// in the root module, targeting the actual native executable digest.
func TestPostgresCompositePrepareSuccession(t *testing.T) {
	if os.Getenv("COMPOSITE_PREPARE_SUCCESSION") != "1" {
		return
	}
	keys := map[string][]byte{}
	for _, role := range []string{"old_history", "history", "old_authority", "new_authority"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = key
	}
	public := func(role string) ed25519.PublicKey {
		return ed25519.PrivateKey(keys[role]).Public().(ed25519.PublicKey)
	}
	envelope := func(next bool) []byte {
		ids := []string{"A", "B", "C"}
		historyRole, authorityRole, owner := "old_history", "old_authority", "custodian:N"
		if next {
			ids = []string{"B", "C", "D"}
			historyRole, authorityRole, owner = "history", "new_authority", "custodian:N+1"
		}
		members := []journal.QuorumTrustPolicyMember{}
		for _, id := range ids {
			members = append(members, journal.QuorumTrustPolicyMember{ID: id, TrustManifestHash: v.ContentDigest([]byte("native-postgres-logical-witness:" + id))})
		}
		grant := v.CustodianGrant{Purpose: successionPurpose, JournalID: successionHistoryID, Custodian: v.Identity{ID: owner, Kind: "history-custodian"}, KeyID: journal.Ed25519KeyID(public(historyRole)), Scope: "append_history"}
		raw, err := json.Marshal(map[string]any{"external_witness_quorum": journal.QuorumTrustPolicy{Protocol: journal.QuorumTrustPolicyVersion, Threshold: 2, Members: members}, "governed_histories": journal.GovernedHistoryTrustPolicy{Protocol: journal.GovernedHistoryTrustPolicyVersion, Histories: []journal.GovernedHistoryIdentity{{Purpose: successionPurpose, JournalID: successionHistoryID}}}, "enrollment_successor_governance": journal.EnrollmentSuccessorGovernancePolicy{Protocol: journal.EnrollmentSuccessorGovernancePolicyVersion, AuthorityID: "successor:" + owner, PublicKeyBase64: base64.StdEncoding.EncodeToString(public(authorityRole))}, "history_custody": grant})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	input := map[string]any{"native_binary": os.Getenv("COMPOSITE_NATIVE_BINARY"), "build_sha": os.Getenv("COMPOSITE_BUILD_SHA"), "old_envelope": envelope(false), "new_envelope": envelope(true)}
	writeCompositeJSON(t, os.Getenv("COMPOSITE_GENESIS_INPUT"), input)
	writeCompositeJSON(t, os.Getenv("COMPOSITE_SUCCESSION_KEYS"), keys)
}

type compositeSuccession struct {
	oldPin, newPin         genesisbootstrap.VerifiedGenesisPin
	oldBinding, newBinding journal.GenesisEnrollmentSuccessorGovernanceBinding
	oldAdmin, newAdmin     *journal.QuorumHeadStore
	oldWriter              *journal.QuorumHeadStore
	enrollmentHead         journal.ExternalHead
	oldHistory, newHistory journal.ExternalHeadStore
	members                map[string]*successionPostgresWitness
	signed                 journal.SignedSuccessorGovernanceRotation
	proof                  v.Succession
	observation            v.SuccessionObservation
	historyPlan            journal.HistorySuccessionPlan
}

func loadSuccessionJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}

func prepareCompositeSuccession(t *testing.T, a *postgresNativeFenceAdapter, p *v.Policy, keys map[string]ed25519.PrivateKey) *compositeSuccession {
	t.Helper()
	ctx := context.Background()
	s := &compositeSuccession{members: map[string]*successionPostgresWitness{}}
	var secret map[string][]byte
	loadSuccessionJSON(t, os.Getenv("COMPOSITE_SUCCESSION_KEYS"), &secret)
	for _, role := range []string{"old_history", "history", "old_authority", "new_authority"} {
		key := ed25519.PrivateKey(secret[role])
		if len(key) != 64 {
			t.Fatal("missing fixture private key")
		}
		pub := key.Public().(ed25519.PublicKey)
		keys[role] = key
		p.RoleKeys[role] = journal.Ed25519KeyID(pub)
		p.PublicKeys[p.RoleKeys[role]] = base64.StdEncoding.EncodeToString(pub)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys["succession_witness"] = key
	p.RoleKeys["succession_witness"] = "succession-witness:fixture"
	p.PublicKeys[p.RoleKeys["succession_witness"]] = base64.StdEncoding.EncodeToString(pub)
	p.HistoryID = successionHistoryID
	p.MaximumGrade = "simulation"
	p.Succession = &v.SuccessionPolicy{HistoryPurpose: successionPurpose, OldCustodian: v.Identity{ID: "custodian:N", Kind: "history-custodian"}, NewCustodian: v.Identity{ID: "custodian:N+1", Kind: "history-custodian"}, Grades: v.EvidenceGrades{Effect: "native", Succession: "native", Genesis: "simulation"}}
	subject, err := genesisbootstrap.CurrentProductionSubject("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"old", "new"} {
		dir := filepath.Join(os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR"), name)
		var metadata struct {
			Now    time.Time `json:"now"`
			Grade  string    `json:"genesis_grade"`
			KeyID  string    `json:"manifest_signer_key_id"`
			Public string    `json:"manifest_signer_public_key"`
		}
		loadSuccessionJSON(t, filepath.Join(dir, "fixture-metadata.json"), &metadata)
		var portable v.PortableGenesis
		loadSuccessionJSON(t, filepath.Join(dir, "portable-genesis.json"), &portable)
		_, result, pin, err := genesisbootstrap.BootstrapProductionWithSubjectPin(ctx, filepath.Join(dir, "genesis.json"), filepath.Join(dir, "bundle.json"), uint64(7+i), 3, genesis.ConformanceC3, subject, time.Now().UTC())
		if err != nil || result.State != genesis.StateReady || pin.GenesisEpoch() != uint64(7+i) || pin.ManifestPayloadHash() != v.ContentDigest(portable.Payload) || metadata.Grade != "simulation" {
			t.Fatalf("production Genesis pin unavailable: state=%s epoch=%d err=%v", result.State, pin.GenesisEpoch(), err)
		}
		role := "old_genesis"
		if i == 1 {
			role = "new_genesis"
		}
		p.RoleKeys[role] = metadata.KeyID
		p.PublicKeys[metadata.KeyID] = metadata.Public
		if i == 0 {
			s.oldPin = pin
			s.proof.OldGenesis = portable
			p.Succession.OldManifestHash = pin.ManifestPayloadHash()
		} else {
			s.newPin = pin
			s.proof.NewGenesis = portable
			p.Succession.NewManifestHash = pin.ManifestPayloadHash()
		}
	}
	oldEnvelope, newEnvelope := s.proof.OldGenesis.CapabilityEnvelope, s.proof.NewGenesis.CapabilityEnvelope
	oldQ, oldH, err := s.oldPin.ParseHistorySuccessionEpochs(oldEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	newQ, newH, err := s.newPin.ParseHistorySuccessionEpochs(newEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	// Mixing an otherwise valid envelope must fail before any rotation.
	if _, _, err := s.oldPin.ParseHistorySuccessionEpochs(newEnvelope, successionPurpose); err == nil {
		t.Fatal("verified pin accepted a different Genesis envelope")
	}
	qp, err := journal.NewQuorumRotationPlan(oldQ, newQ)
	if err != nil {
		t.Fatal(err)
	}
	s.historyPlan, err = journal.NewHistorySuccessionPlan(oldH, newH, qp)
	if err != nil {
		t.Fatal(err)
	}
	oldQB, err := s.oldPin.ParseQuorumBinding(oldEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	newQB, err := s.newPin.ParseQuorumBinding(newEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	s.oldBinding, err = s.oldPin.ParseEnrollmentSuccessorGovernanceBinding(oldEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	s.newBinding, err = s.newPin.ParseEnrollmentSuccessorGovernanceBinding(newEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	setupSuccessionSQL(t, a.db, oldQ.GenesisEpoch(), newQ.GenesisEpoch(), p.RoleKeys["old_history"], p.RoleKeys["history"], p.HistoryID)
	oldPolicy, err := oldQB.ActivePolicy(oldQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	newPolicy, err := newQB.ActivePolicy(newQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"A", "B", "C", "D"} {
		policy := oldPolicy
		if id == "D" {
			policy = newPolicy
		}
		if _, err := a.db.Exec("INSERT INTO "+nativeFenceTable("witness_policy")+" VALUES ($1,$2::jsonb)", id, witnessJSON(policy)); err != nil {
			t.Fatal(err)
		}
		s.members[id] = &successionPostgresWitness{db: a.db, id: id, trust: v.ContentDigest([]byte("native-postgres-logical-witness:" + id))}
	}
	memberList := func(ids []string, dbRole string) []journal.QuorumHeadMember {
		members := []journal.QuorumHeadMember{}
		for _, id := range ids {
			member := s.members[id]
			if dbRole != "" {
				u, err := url.Parse(os.Getenv("GOSMIG_SIM_ADMIN_DSN"))
				if err != nil {
					t.Fatal(err)
				}
				password := "fixture-history-old"
				if dbRole == "composite_history_new" {
					password = "fixture-history-new"
				}
				u.User = url.UserPassword(dbRole, password)
				db, err := openDB(u.String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				if id == "B" && dbRole == "composite_history_new" {
					if _, err := db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest=digest"); err == nil || !strings.Contains(err.Error(), "permission denied") {
						t.Fatalf("new history custodian received destination mutation authority: %v", err)
					}
				}
				member = &successionPostgresWitness{db: db, id: id, trust: member.trust}
			}
			members = append(members, journal.QuorumHeadMember{ID: id, Store: member})
		}
		return members
	}
	s.oldAdmin, err = journal.NewGovernedQuorumHeadStore(memberList([]string{"A", "B", "C"}, ""), oldQB, oldQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	s.newAdmin, err = journal.NewGovernedQuorumHeadStore(memberList([]string{"B", "C", "D"}, ""), newQB, newQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	oldWriter, err := journal.NewGovernedQuorumHeadStore(memberList([]string{"A", "B", "C"}, "composite_history_old"), oldQB, oldQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	s.oldWriter = oldWriter
	newWriter, err := journal.NewGovernedQuorumHeadStore(memberList([]string{"B", "C", "D"}, "composite_history_new"), newQB, newQ.GenesisEpoch())
	if err != nil {
		t.Fatal(err)
	}
	oldHB, err := s.oldPin.ParseHistoryBinding(oldEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	newHB, err := s.newPin.ParseHistoryBinding(newEnvelope, successionPurpose)
	if err != nil {
		t.Fatal(err)
	}
	s.oldHistory, err = journal.NewGenesisBoundHistoryStore(oldWriter, oldHB)
	if err != nil {
		t.Fatal(err)
	}
	s.newHistory, err = journal.NewGenesisBoundHistoryStore(newWriter, newHB)
	if err != nil {
		t.Fatal(err)
	}
	before, err := journal.InitializeSuccessorGovernanceAuthority(ctx, s.oldAdmin, journal.SuccessorGovernanceAuthorityJournalID, s.oldBinding)
	if err != nil {
		t.Fatal(err)
	}
	p.Succession.OldAuthorityCheckpoint = portableHead(before)
	s.observation.AuthorityBefore = portableHead(before)
	if _, err := a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET epoch=$1", oldQ.GenesisEpoch()); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *compositeSuccession) rotate(t *testing.T, a *postgresNativeFenceAdapter, p *v.Policy, keys map[string]ed25519.PrivateKey, head journal.ExternalHead, anchorPath string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	p.Succession.OldCheckpoint = portableHead(head)
	s.observation.HistoryBefore = portableHead(head)
	var err error
	s.proof.BeforeAnchor, err = os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := journal.NewSuccessorGovernanceRotationAuthorization("native-composite:Genesis7->8", journal.SuccessorGovernanceAuthorityJournalID, journal.ExternalHead{JournalID: p.Succession.OldAuthorityCheckpoint.JournalID, Sequence: p.Succession.OldAuthorityCheckpoint.Sequence, HeadHash: p.Succession.OldAuthorityCheckpoint.HeadHash, KeyID: p.Succession.OldAuthorityCheckpoint.KeyID}, s.oldBinding, s.newBinding, now.Add(-time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	oldApproval, err := journal.SignSuccessorGovernanceRotationApproval(authorization, keys["old_authority"])
	if err != nil {
		t.Fatal(err)
	}
	newApproval, err := journal.SignSuccessorGovernanceRotationApproval(authorization, keys["new_authority"])
	if err != nil {
		t.Fatal(err)
	}
	s.signed = journal.SignedSuccessorGovernanceRotation{Authorization: authorization, OldApproval: oldApproval, NewApproval: newApproval}
	s.proof.AuthorityRotation, err = json.Marshal(s.signed)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := journal.FreezeSuccessorGovernanceAuthority(ctx, s.oldAdmin, s.signed, s.oldBinding, s.newBinding, now)
	if err != nil {
		t.Fatal(err)
	}
	s.observation.AuthorityFrozen = portableHead(frozen)
	if _, err := journal.RequireActiveSuccessorGovernanceAuthority(ctx, s.oldAdmin, journal.SuccessorGovernanceAuthorityJournalID, s.oldBinding); err == nil {
		t.Fatal("frozen authority remained current")
	}
	// Commit the first native freeze, then lose its response. The second call
	// must resume from durable policy/head state without resetting the history.
	interrupt := errors.New("lost native witness freeze acknowledgement")
	s.members["B"].afterTransition = func() error { s.members["B"].afterTransition = nil; return interrupt }
	if _, err := journal.ExecuteGovernedHistorySuccession(ctx, s.historyPlan, s.oldAdmin, s.newAdmin); err == nil {
		t.Fatal("injected interrupted transition unexpectedly completed")
	}
	if policy, err := s.members["B"].CurrentQuorumPolicy(ctx); err != nil || policy.Phase != journal.QuorumPolicyPhaseJoint {
		t.Fatalf("first native freeze not durable: %+v %v", policy, err)
	}
	for _, check := range []struct {
		store   *journal.QuorumHeadStore
		binding journal.GenesisEnrollmentSuccessorGovernanceBinding
	}{{s.oldAdmin, s.oldBinding}, {s.newAdmin, s.newBinding}} {
		if _, err := journal.RequireActiveSuccessorGovernanceAuthority(ctx, check.store, journal.SuccessorGovernanceAuthorityJournalID, check.binding); err == nil {
			t.Fatal("authority current during interrupted frozen handoff")
		}
	}
	result, err := journal.ExecuteGovernedHistorySuccession(ctx, s.historyPlan, s.oldAdmin, s.newAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if portableHead(result.Head) != portableHead(head) {
		t.Fatal("history succession changed predecessor")
	}
	s.observation.HistoryTransitionHash = result.TransitionHash
	s.observation.QuorumTransitionHash = result.QuorumTransitionHash
	active, err := journal.ActivateSuccessorGovernanceAuthority(ctx, s.newAdmin, s.signed, s.oldBinding, s.newBinding, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	s.observation.AuthorityAfter = portableHead(active)
	if _, err := journal.RequireActiveSuccessorGovernanceAuthority(ctx, s.oldAdmin, journal.SuccessorGovernanceAuthorityJournalID, s.oldBinding); err == nil {
		t.Fatal("stale authority resurrected")
	}
	if current, err := journal.RequireActiveSuccessorGovernanceAuthority(ctx, s.newAdmin, journal.SuccessorGovernanceAuthorityJournalID, s.newBinding); err != nil || portableHead(current) != portableHead(active) {
		t.Fatalf("new authority unavailable: %v", err)
	}
	if _, err := a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET active=FALSE,epoch=$1,generation=generation+1", s.newPin.GenesisEpoch()); err != nil {
		t.Fatal(err)
	}
	// OLD cannot update even after learning NEW's exact policy and public key.
	// The SQL function checks session identity at the same commit boundary.
	u, _ := url.Parse(os.Getenv("GOSMIG_SIM_ADMIN_DSN"))
	u.User = url.UserPassword("composite_history_old", "fixture-history-old")
	oldDB, err := openDB(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer oldDB.Close()
	newPolicy, err := s.members["B"].CurrentQuorumPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	impersonated := head
	impersonated.Sequence++
	impersonated.HeadHash = v.ContentDigest([]byte("unauthorized old custodian"))
	impersonated.KeyID = p.RoleKeys["history"]
	oldActor := &successionPostgresWitness{db: oldDB, id: "B", trust: s.members["B"].trust}
	if _, err := oldActor.CompareAndAdvanceForQuorum(ctx, newPolicy, head, impersonated); err == nil || !strings.Contains(err.Error(), "native custodian fence rejected") {
		t.Fatalf("old SQL actor was not denied at the native custodian fence: %v", err)
	}
	if unchanged, err := s.members["B"].ObserveQuorumRotationHead(ctx, p.HistoryID); err != nil || portableHead(unchanged) != portableHead(head) {
		t.Fatal("denied custodian changed history")
	}
	if _, err := oldDB.Exec("UPDATE " + nativeFenceTable("witness_policy") + " SET policy=policy"); err == nil {
		t.Fatal("old actor could rewrite policy")
	}
}

func TestPostgresCompositeGenesisHistoryCustodianLostAcknowledgement(t *testing.T) {
	if os.Getenv("COMPOSITE_GENESIS_FIXTURE_DIR") == "" {
		if os.Getenv("COMPOSITE_SUCCESSION_REQUIRE") == "1" {
			t.Fatal("required Genesis succession fixture missing")
		}
		t.Skip("run composite-native-assurance for verified Genesis succession")
	}
	for _, withheld := range []bool{false, true} {
		name := "CLOSED"
		if withheld {
			name = "UNKNOWN"
		}
		t.Run(name, func(t *testing.T) { runPostgresCompositeCase(t, name, withheld, true) })
	}
}
