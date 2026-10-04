package simulation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

var errNativeCompleted = errors.New("native logical effect already has an immutable completion")

// This alternate native path has no reserve, custody load, phase, transfer or
// current effect-owner generation. Admission authority remains independently
// versioned. The immutable receipt still identifies the actual committer; its
// generation=1 is the v1 transport's fixed initial attempt tag, not a transferable
// ownership register. Durable effect/receipt retention is deliberately retained.
func executeWithoutCustody(ctx context.Context, db *sql.DB, req r.Request, env v.Envelope, policy v.Policy, beforeCommit func() error) error {
	var admission v.Admission
	if err := v.Decode(env.Payload, &admission); err != nil {
		return err
	}
	keyID := policy.RoleKeys["admission"]
	key, keyErr := base64.StdEncoding.DecodeString(policy.PublicKeys[keyID])
	sig, sigErr := base64.StdEncoding.DecodeString(env.Signature)
	var compact bytes.Buffer
	if err := json.Compact(&compact, env.Payload); err != nil {
		return err
	}
	message := append([]byte(v.Schema+"\x00admission\x00"), compact.Bytes()...)
	if env.KeyID != keyID || keyErr != nil || sigErr != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, sig) {
		return errNativeUntrusted
	}
	binding, err := r.AdmissionBindingDigest(req)
	if err != nil {
		return err
	}
	if !req.Executor.Complete() || req.AttemptID == "" || req.Admission.BindingDigest != binding || admission.RequestBinding != binding || admission.ObservedBefore != noCustodyState(req.Current) || admission.AllowedOperation != req.Transition.Operation || admission.BuildSHA != policy.BuildSHA || admission.CaseID != policy.CaseID || admission.PolicyHash != policy.AdmissionPolicyHash || !admission.AuthorityActive || admission.AuthorityEpoch == 0 || admission.AuthorityGeneration == 0 {
		return errNativeAuthority
	}
	effect, err := r.EffectIdentity(req)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var revision, digest string
	if err := tx.QueryRowContext(ctx, "SELECT revision,digest FROM "+nativeFenceTable("target_state")+" WHERE target=$1 FOR UPDATE", req.Current.Target).Scan(&revision, &digest); err != nil {
		return err
	}
	var active bool
	var epoch, generation uint64
	if err := tx.QueryRowContext(ctx, "SELECT active,epoch,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1 FOR SHARE", binding).Scan(&active, &epoch, &generation); err != nil {
		return err
	}
	if !active || epoch != admission.AuthorityEpoch || generation != admission.AuthorityGeneration {
		return errNativeAuthority
	}
	var completed bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM "+nativeFenceTable("effects")+" WHERE effect_id=$1)", effect).Scan(&completed); err != nil {
		return err
	}
	if completed {
		return errNativeCompleted
	}
	if revision != req.Current.Revision || digest != req.Current.Digest {
		return errNativeState
	}
	// This append is the actual non-idempotent effect. Its physical tally is
	// independent of the operation/receipt table and has no dedup key of its own.
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+nativeFenceTable("ledger")+" (amount) VALUES (1)"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE "+nativeFenceTable("target_state")+" SET revision=$1,digest=$2 WHERE target=$3", req.Transition.To.Revision, req.Transition.To.Digest, req.Current.Target); err != nil {
		return err
	}
	if err := retainNativeCompletion(ctx, tx, req, effect, admission); err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func retainNativeCompletion(ctx context.Context, tx *sql.Tx, req r.Request, effect string, admission v.Admission) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO "+nativeFenceTable("effects")+" (effect_id,attempt_id,target,owner_id,owner_kind,generation,operation,from_revision,to_revision,from_digest,to_digest,admission_binding,authority_epoch,authority_generation,authority_active) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,TRUE)",
		effect, req.AttemptID, req.Current.Target, req.Executor.ID, req.Executor.Kind, req.Transition.Operation, req.Current.Revision, req.Transition.To.Revision, req.Current.Digest, req.Transition.To.Digest, req.Admission.BindingDigest, admission.AuthorityEpoch, admission.AuthorityGeneration)
	return err
}

func noCustodyState(s r.State) v.State {
	return v.State{Target: s.Target, Revision: s.Revision, Digest: s.Digest}
}

func observeWithoutCustody(ctx context.Context, db *sql.DB, req r.Request, withheld bool) (v.Destination, error) {
	d := v.Destination{}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+nativeFenceTable("ledger")).Scan(&d.EffectCount); err != nil {
		return d, err
	}
	if err := db.QueryRowContext(ctx, "SELECT active,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1", req.Admission.BindingDigest).Scan(&d.AuthorityCurrentlyActive, &d.CurrentAuthorityGeneration); err != nil {
		return d, err
	}
	if withheld {
		d.ObservationError = "exact native observation withheld; UNKNOWN grants no execution permission"
		return d, nil
	}
	d.Observed.Target = req.Current.Target
	if err := db.QueryRowContext(ctx, "SELECT revision,digest FROM "+nativeFenceTable("target_state")+" WHERE target=$1", req.Current.Target).Scan(&d.Observed.Revision, &d.Observed.Digest); err != nil {
		return d, err
	}
	effect, err := r.EffectIdentity(req)
	if err != nil {
		return d, err
	}
	var c v.Commit
	var committedAt string
	err = db.QueryRowContext(ctx, "SELECT effect_id,attempt_id,owner_id,owner_kind,generation,admission_binding,authority_epoch,authority_generation,authority_active,operation,target,from_revision,from_digest,to_revision,to_digest,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM "+nativeFenceTable("effects")+" WHERE effect_id=$1", effect).Scan(&c.EffectID, &c.AttemptID, &c.Owner.ID, &c.Owner.Kind, &c.CustodyGeneration, &c.AdmissionBinding, &c.AuthorityEpoch, &c.AuthorityGeneration, &c.AuthorityActive, &c.Operation, &c.Before.Target, &c.Before.Revision, &c.Before.Digest, &c.After.Revision, &c.After.Digest, &committedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("native completion observation: %w", err)
	}
	c.After.Target, c.CommittedAt = c.Before.Target, committedAt
	d.Commit = &c
	return d, nil
}
