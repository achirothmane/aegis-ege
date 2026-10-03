package simulation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

// Native SQL policy/head fencing for this bounded experiment. Four logical
// witnesses share one PostgreSQL service: this is NOT independent-provider
// fault tolerance. The administrator/controller and SQL server are trusted.
type successionPostgresWitness struct {
	db              *sql.DB
	id, trust       string
	afterTransition func() error
}

func witnessJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }
func portableHead(h journal.ExternalHead) v.Head {
	return v.Head{JournalID: h.JournalID, Sequence: h.Sequence, HeadHash: h.HeadHash, KeyID: h.KeyID}
}

func (s *successionPostgresWitness) QuorumTrustManifestHash() string { return s.trust }
func (s *successionPostgresWitness) CurrentQuorumPolicy(ctx context.Context) (journal.QuorumPolicyState, error) {
	var raw []byte
	var p journal.QuorumPolicyState
	err := s.db.QueryRowContext(ctx, "SELECT policy FROM "+nativeFenceTable("witness_policy")+" WHERE witness_id=$1", s.id).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &p)
	}
	return p, err
}
func (s *successionPostgresWitness) ObserveQuorumRotationHead(ctx context.Context, id string) (journal.ExternalHead, error) {
	var h journal.ExternalHead
	err := s.db.QueryRowContext(ctx, "SELECT journal_id,sequence,head_hash,key_id FROM "+nativeFenceTable("witness_head")+" WHERE witness_id=$1 AND journal_id=$2", s.id, id).Scan(&h.JournalID, &h.Sequence, &h.HeadHash, &h.KeyID)
	if errors.Is(err, sql.ErrNoRows) {
		err = journal.ErrExternalHeadNotFound
	}
	return h, err
}
func (s *successionPostgresWitness) LoadForQuorum(ctx context.Context, id string, p journal.QuorumPolicyState) (journal.ExternalHead, error) {
	// One native statement binds the returned head to the exact policy.
	var h journal.ExternalHead
	err := s.db.QueryRowContext(ctx, "SELECT h.journal_id,h.sequence,h.head_hash,h.key_id FROM "+nativeFenceTable("witness_head")+" h JOIN "+nativeFenceTable("witness_policy")+" p USING(witness_id) WHERE h.witness_id=$1 AND h.journal_id=$2 AND p.policy=$3::jsonb AND p.policy->>'phase'='ACTIVE'", s.id, id, witnessJSON(p)).Scan(&h.JournalID, &h.Sequence, &h.HeadHash, &h.KeyID)
	if errors.Is(err, sql.ErrNoRows) {
		current, policyErr := s.CurrentQuorumPolicy(ctx)
		if policyErr != nil {
			return h, policyErr
		}
		if current != p || current.Phase != journal.QuorumPolicyPhaseActive {
			return h, journal.ErrQuorumPolicyMismatch
		}
		err = journal.ErrExternalHeadNotFound
	}
	return h, err
}
func (s *successionPostgresWitness) Load(ctx context.Context, id string) (journal.ExternalHead, error) {
	return s.ObserveQuorumRotationHead(ctx, id)
}
func (s *successionPostgresWitness) CompareAndAdvance(ctx context.Context, previous, next journal.ExternalHead) (journal.ExternalHead, error) {
	return journal.ExternalHead{}, errors.New("unfenced witness writes are forbidden")
}
func (s *successionPostgresWitness) CompareAndAdvanceForQuorum(ctx context.Context, p journal.QuorumPolicyState, previous, next journal.ExternalHead) (journal.ExternalHead, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, "SELECT "+nativeFenceSchema+".advance_history($1,$2::jsonb,$3::jsonb,$4::jsonb)", s.id, witnessJSON(p), witnessJSON(previous), witnessJSON(next)).Scan(&ok)
	if err != nil {
		return journal.ExternalHead{}, err
	}
	if !ok {
		return journal.ExternalHead{}, journal.ErrExternalHeadConflict
	}
	return next, nil
}
func (s *successionPostgresWitness) CompareAndTransitionQuorumPolicy(ctx context.Context, expected, next journal.QuorumPolicyState, id string, head journal.ExternalHead) error {
	if err := journal.ValidateQuorumPolicyTransition(expected, next); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT policy FROM "+nativeFenceTable("witness_policy")+" WHERE witness_id=$1 FOR UPDATE", s.id).Scan(&raw); err != nil {
		return err
	}
	var current journal.QuorumPolicyState
	if err = json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if current != expected {
		return journal.ErrQuorumPolicyMismatch
	}
	var actual journal.ExternalHead
	if err = tx.QueryRowContext(ctx, "SELECT journal_id,sequence,head_hash,key_id FROM "+nativeFenceTable("witness_head")+" WHERE witness_id=$1 AND journal_id=$2 FOR UPDATE", s.id, id).Scan(&actual.JournalID, &actual.Sequence, &actual.HeadHash, &actual.KeyID); err != nil {
		return err
	}
	if actual != head {
		return journal.ErrExternalHeadConflict
	}
	var authority journal.ExternalHead
	if err = tx.QueryRowContext(ctx, "SELECT journal_id,sequence,head_hash,key_id FROM "+nativeFenceTable("witness_head")+" WHERE witness_id=$1 AND journal_id=$2 FOR UPDATE", s.id, journal.SuccessorGovernanceAuthorityJournalID).Scan(&authority.JournalID, &authority.Sequence, &authority.HeadHash, &authority.KeyID); err != nil {
		return err
	}
	if current == next {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "UPDATE "+nativeFenceTable("witness_policy")+" SET policy=$1::jsonb WHERE witness_id=$2", witnessJSON(next), s.id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO "+nativeFenceTable("policy_trace")+" (witness_id,before_policy,after_policy,head,authority_head) VALUES ($1,$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb)", s.id, witnessJSON(expected), witnessJSON(next), witnessJSON(head), witnessJSON(authority)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if s.afterTransition != nil {
		return s.afterTransition()
	}
	return nil
}

func setupSuccessionSQL(t *testing.T, db *sql.DB, oldEpoch, newEpoch uint64, oldKey, newKey, historyID string) {
	t.Helper()
	statements := []string{
		"CREATE TABLE " + nativeFenceTable("witness_policy") + " (witness_id TEXT PRIMARY KEY,policy JSONB NOT NULL)",
		"CREATE TABLE " + nativeFenceTable("witness_head") + " (witness_id TEXT NOT NULL,journal_id TEXT NOT NULL,sequence BIGINT NOT NULL,head_hash TEXT NOT NULL,key_id TEXT NOT NULL,PRIMARY KEY(witness_id,journal_id))",
		"CREATE TABLE " + nativeFenceTable("policy_trace") + " (ordinal BIGSERIAL PRIMARY KEY,witness_id TEXT NOT NULL,before_policy JSONB NOT NULL,after_policy JSONB NOT NULL,head JSONB NOT NULL,authority_head JSONB NOT NULL)",
		"CREATE TABLE " + nativeFenceTable("custodian_grant") + " (actor TEXT PRIMARY KEY,epoch BIGINT NOT NULL,key_id TEXT NOT NULL,journal_id TEXT NOT NULL)",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='composite_history_old') THEN CREATE ROLE composite_history_old LOGIN PASSWORD 'fixture-history-old'; END IF; IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='composite_history_new') THEN CREATE ROLE composite_history_new LOGIN PASSWORD 'fixture-history-new'; END IF; END $$",
		"GRANT USAGE ON SCHEMA " + nativeFenceSchema + " TO composite_history_old,composite_history_new",
		"GRANT SELECT ON ALL TABLES IN SCHEMA " + nativeFenceSchema + " TO composite_history_old,composite_history_new",
		// Scope is deliberately narrow: no direct table writes, policy changes,
		// custody execution or destination effects are granted to either actor.
		`CREATE FUNCTION ` + nativeFenceSchema + `.advance_history(w TEXT,p JSONB,prev JSONB,nxt JSONB) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE current_policy JSONB; stored RECORD; grant_ok BOOLEAN;
BEGIN
 SELECT policy INTO current_policy FROM ` + nativeFenceTable("witness_policy") + ` WHERE witness_id=w FOR UPDATE;
 IF current_policy IS NULL OR current_policy<>p OR p->>'phase'<>'ACTIVE' THEN RAISE EXCEPTION 'native policy fence rejected'; END IF;
 IF session_user <> 'postgres' THEN
  SELECT EXISTS(SELECT 1 FROM ` + nativeFenceTable("custodian_grant") + ` WHERE actor=session_user AND epoch=(p->>'genesis_epoch')::BIGINT AND key_id=nxt->>'key_id' AND journal_id=nxt->>'journal_id') INTO grant_ok;
  IF NOT grant_ok THEN RAISE EXCEPTION 'native custodian fence rejected'; END IF;
 END IF;
 SELECT * INTO stored FROM ` + nativeFenceTable("witness_head") + ` WHERE witness_id=w AND journal_id=nxt->>'journal_id' FOR UPDATE;
 IF NOT FOUND THEN
  IF COALESCE(prev->>'head_hash','')<>'' OR COALESCE(prev->>'key_id','')<>'' OR (prev->>'sequence')::BIGINT<>0 OR (nxt->>'sequence')::BIGINT<>0 THEN RETURN FALSE; END IF;
  INSERT INTO ` + nativeFenceTable("witness_head") + ` VALUES(w,nxt->>'journal_id',(nxt->>'sequence')::BIGINT,nxt->>'head_hash',nxt->>'key_id'); RETURN TRUE;
 END IF;
 IF stored.journal_id<>prev->>'journal_id' OR stored.sequence<>(prev->>'sequence')::BIGINT OR stored.head_hash<>prev->>'head_hash' OR stored.key_id<>prev->>'key_id' THEN RETURN FALSE; END IF;
 IF (nxt->>'sequence')::BIGINT<stored.sequence OR ((nxt->>'sequence')::BIGINT=stored.sequence AND (nxt->>'head_hash'<>stored.head_hash OR nxt->>'key_id'<>stored.key_id)) THEN RETURN FALSE; END IF;
 UPDATE ` + nativeFenceTable("witness_head") + ` SET sequence=(nxt->>'sequence')::BIGINT,head_hash=nxt->>'head_hash',key_id=nxt->>'key_id' WHERE witness_id=w AND journal_id=stored.journal_id;
 RETURN TRUE;
END $$`,
		"REVOKE ALL ON FUNCTION " + nativeFenceSchema + ".advance_history(TEXT,JSONB,JSONB,JSONB) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION " + nativeFenceSchema + ".advance_history(TEXT,JSONB,JSONB,JSONB) TO composite_history_old,composite_history_new",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []struct {
		actor string
		epoch uint64
		key   string
	}{{"composite_history_old", oldEpoch, oldKey}, {"composite_history_new", newEpoch, newKey}} {
		if _, err := db.Exec("INSERT INTO "+nativeFenceTable("custodian_grant")+" VALUES ($1,$2,$3,$4)", grant.actor, grant.epoch, grant.key, historyID); err != nil {
			t.Fatal(err)
		}
	}
}

func successionObservation(t *testing.T, db *sql.DB, members map[string]*successionPostgresWitness, historyID, authorityID string) ([]v.QuorumTransition, map[string]v.WitnessState) {
	t.Helper()
	rows, err := db.Query("SELECT ordinal,witness_id,before_policy,after_policy,head,authority_head FROM " + nativeFenceTable("policy_trace") + " ORDER BY ordinal")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	trace := []v.QuorumTransition{}
	for rows.Next() {
		var r v.QuorumTransition
		var before, after, head, authority []byte
		if err := rows.Scan(&r.Ordinal, &r.WitnessID, &before, &after, &head, &authority); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			raw []byte
			dst any
		}{{before, &r.Before}, {after, &r.After}, {head, &r.Head}, {authority, &r.AuthorityHead}} {
			if err := json.Unmarshal(item.raw, item.dst); err != nil {
				t.Fatal(err)
			}
		}
		trace = append(trace, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	current := map[string]v.WitnessState{}
	for id, member := range members {
		policy, err := member.CurrentQuorumPolicy(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		history, err := member.ObserveQuorumRotationHead(context.Background(), historyID)
		if errors.Is(err, journal.ErrExternalHeadNotFound) {
			history = journal.ExternalHead{}
		} else if err != nil {
			t.Fatal(err)
		}
		authority, err := member.ObserveQuorumRotationHead(context.Background(), authorityID)
		if errors.Is(err, journal.ErrExternalHeadNotFound) {
			authority = journal.ExternalHead{}
		} else if err != nil {
			t.Fatal(err)
		}
		var portablePolicy v.QuorumPolicy
		if err := json.Unmarshal([]byte(witnessJSON(policy)), &portablePolicy); err != nil {
			t.Fatal(err)
		}
		current[id] = v.WitnessState{Policy: portablePolicy, HistoryHead: portableHead(history), AuthorityHead: portableHead(authority)}
	}
	return trace, current
}

var _ journal.QuorumPolicyFencedStore = (*successionPostgresWitness)(nil)
