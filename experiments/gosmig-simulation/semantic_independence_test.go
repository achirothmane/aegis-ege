package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// TestPostgresCompositeThreeObligationIndependence is a bounded separating
// basis over the reduced #241 representation. Each pair keeps two coordinates
// equal while changing the third:
//
//   authority    is not derivable from exact cause + current postcondition;
//   exact cause  is not derivable from admission + current postcondition;
//   postcondition is not derivable from admission + exact cause.
//
// The test does not claim a global minimality theorem. It proves only that, for
// this independently verified PostgreSQL EXACT_EFFECT profile, collapsing any
// one of these three relations into the other two loses information.
func TestPostgresCompositeThreeObligationIndependence(t *testing.T) {
	t.Run("authority", testAuthorityIndependentOfCauseAndState)
	t.Run("causality", testCauseIndependentOfAdmissionAndState)
	t.Run("postcondition", testPostconditionIndependentOfAdmissionAndCause)
}

type causeStateProjection struct {
	EffectID         string
	AttemptID        string
	Owner            v.Identity
	Operation        string
	Before           v.State
	After            v.State
	AdmissionBinding string
	Observed         v.State
	EffectCount      uint64
}

type admissionStateProjection struct {
	Request                    v.Request
	Admission                  v.Admission
	Observed                   v.State
	EffectCount                uint64
	AuthorityCurrentlyActive   bool
	CurrentAuthorityGeneration uint64
}

type admissionCauseProjection struct {
	Request   v.Request
	Admission v.Admission
	Commit    v.Commit
}

func independenceRequest(req r.Request) v.Request {
	return v.Request{
		Subject:          v.Identity{ID: req.Subject.ID, Kind: req.Subject.Kind},
		Executor:         v.Identity{ID: req.Executor.ID, Kind: req.Executor.Kind},
		Before:           noCustodyState(req.Current),
		After:            noCustodyState(req.Transition.To),
		Operation:        req.Transition.Operation,
		AttemptID:        req.AttemptID,
		AdmissionBinding: req.Admission.BindingDigest,
	}
}

func equalJSON(t *testing.T, left, right any, message string) {
	t.Helper()
	a, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("%s\nleft=%s\nright=%s", message, a, b)
	}
}

func causeState(d v.Destination) causeStateProjection {
	c := d.Commit
	if c == nil {
		return causeStateProjection{Observed: d.Observed, EffectCount: d.EffectCount}
	}
	return causeStateProjection{
		EffectID:         c.EffectID,
		AttemptID:        c.AttemptID,
		Owner:            c.Owner,
		Operation:        c.Operation,
		Before:           c.Before,
		After:            c.After,
		AdmissionBinding: c.AdmissionBinding,
		Observed:         d.Observed,
		EffectCount:      d.EffectCount,
	}
}

func admissionState(f *noCustodyFixture, d v.Destination) admissionStateProjection {
	return admissionStateProjection{
		Request:                    independenceRequest(f.req),
		Admission:                  f.admission(f.req, 1),
		Observed:                   d.Observed,
		EffectCount:                d.EffectCount,
		AuthorityCurrentlyActive:   d.AuthorityCurrentlyActive,
		CurrentAuthorityGeneration: d.CurrentAuthorityGeneration,
	}
}

func admissionCause(f *noCustodyFixture, d v.Destination) admissionCauseProjection {
	var commit v.Commit
	if d.Commit != nil {
		commit = *d.Commit
		// Commit time is evidence freshness, not one of the compared semantic
		// coordinates. The retained relation is otherwise byte-for-byte exact.
		commit.CommittedAt = ""
	}
	return admissionCauseProjection{
		Request:   independenceRequest(f.req),
		Admission: f.admission(f.req, 1),
		Commit:    commit,
	}
}

func testAuthorityIndependentOfCauseAndState(t *testing.T) {
	ctx := context.Background()

	control := setupUnifiedEffectRecord(t)
	if err := executeUnifiedEffectRecord(ctx, control.a.db, control.req, control.seal(t, "admission", control.admission(control.req, 1)), control.policy, nil); err != nil {
		t.Fatal(err)
	}
	controlDest, err := observeUnifiedEffectRecord(ctx, control.a.db, control.req, false)
	if err != nil || controlDest.Commit == nil {
		t.Fatal("control lacks the unified exact-cause row")
	}
	controlReport := control.inspect(t, "independence/authority/control", control.req, 1, controlDest, "CLOSED", "EXACT_COMMIT_RECORD", true)
	if controlReport.AuthorityAtCommit != "VALID_AT_COMMIT" {
		t.Fatalf("control authority was not valid at commit: %+v", controlReport)
	}

	invalid := setupUnifiedEffectRecord(t)
	if _, err := invalid.a.db.Exec(
		"UPDATE "+nativeFenceTable("authority")+" SET active=FALSE WHERE binding_digest=$1",
		invalid.req.Admission.BindingDigest,
	); err != nil {
		t.Fatal(err)
	}
	effect, err := r.EffectIdentity(invalid.req)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := invalid.a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var active bool
	var epoch, generation uint64
	if err := tx.QueryRowContext(
		ctx,
		"SELECT active,epoch,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1 FOR SHARE",
		invalid.req.Admission.BindingDigest,
	).Scan(&active, &epoch, &generation); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("invalid world did not remove continuing authority before the physical effect")
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO "+nativeFenceTable("ledger")+" (effect_id,amount,attempt_id,target,owner_id,owner_kind,generation,operation,from_revision,to_revision,from_digest,to_digest,admission_binding,authority_epoch,authority_generation,authority_active) VALUES ($1,1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,FALSE)",
		effect,
		invalid.req.AttemptID,
		invalid.req.Current.Target,
		invalid.req.Executor.ID,
		invalid.req.Executor.Kind,
		invalid.req.Transition.Operation,
		invalid.req.Current.Revision,
		invalid.req.Transition.To.Revision,
		invalid.req.Current.Digest,
		invalid.req.Transition.To.Digest,
		invalid.req.Admission.BindingDigest,
		epoch,
		generation,
	); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Make the present-time authority view equal again. The retained physical
	// row still truthfully records that authority was absent at commitment.
	if _, err := invalid.a.db.Exec(
		"UPDATE "+nativeFenceTable("authority")+" SET active=TRUE WHERE binding_digest=$1",
		invalid.req.Admission.BindingDigest,
	); err != nil {
		t.Fatal(err)
	}
	invalidDest, err := observeUnifiedEffectRecord(ctx, invalid.a.db, invalid.req, false)
	if err != nil || invalidDest.Commit == nil {
		t.Fatal("invalid authority world lacks the genuine physical effect row")
	}
	if invalidDest.Commit.AuthorityActive {
		t.Fatal("invalid authority world rewrote authority-at-commit")
	}
	equalJSON(t, causeState(controlDest), causeState(invalidDest),
		"cause + current postcondition projection changed outside authority-at-commit")
	invalidReport := invalid.inspect(t, "independence/authority/invalid-at-commit", invalid.req, 1, invalidDest, "CLOSED", "EXACT_COMMIT_RECORD", false)
	if invalidReport.AuthorityAtCommit != "INVALID_AT_COMMIT" || invalidReport.Closure != "UNKNOWN" {
		t.Fatalf("exact cause + matching state incorrectly reconstructed authority: %+v", invalidReport)
	}
}

func testCauseIndependentOfAdmissionAndState(t *testing.T) {
	ctx := context.Background()

	owned := setupUnifiedEffectRecord(t)
	if err := executeUnifiedEffectRecord(ctx, owned.a.db, owned.req, owned.seal(t, "admission", owned.admission(owned.req, 1)), owned.policy, nil); err != nil {
		t.Fatal(err)
	}
	ownedDest, err := observeUnifiedEffectRecord(ctx, owned.a.db, owned.req, false)
	if err != nil || ownedDest.Commit == nil {
		t.Fatal("owned world lacks exact effect evidence")
	}
	ownedReport := owned.inspect(t, "independence/causality/owned", owned.req, 1, ownedDest, "CLOSED", "EXACT_COMMIT_RECORD", true)
	if ownedReport.Causality != "EXACT_COMMIT_RECORD" {
		t.Fatalf("owned control lost exact causality: %+v", ownedReport)
	}

	foreign := setupUnifiedEffectRecord(t)
	other := foreign.req
	other.AttemptID = "attempt:independence-other"
	other.Executor.ID = "executor:independence-other"
	originalEffect, err := r.EffectIdentity(foreign.req)
	if err != nil {
		t.Fatal(err)
	}
	otherEffect, err := r.EffectIdentity(other)
	if err != nil || otherEffect != originalEffect {
		t.Fatal("foreign attempt changed the logical effect identity")
	}
	if err := executeUnifiedEffectRecord(ctx, foreign.a.db, other, foreign.seal(t, "admission", foreign.admission(other, 1)), foreign.policy, nil); err != nil {
		t.Fatal(err)
	}
	foreignDest, err := observeUnifiedEffectRecord(ctx, foreign.a.db, foreign.req, false)
	if err != nil || foreignDest.Commit == nil || foreignDest.Commit.AttemptID != other.AttemptID {
		t.Fatal("foreign world did not retain its actual committer")
	}
	equalJSON(t, admissionState(owned, ownedDest), admissionState(foreign, foreignDest),
		"admission + current postcondition projection changed outside actual cause")
	foreignReport := foreign.inspect(t, "independence/causality/foreign-attempt", foreign.req, 1, foreignDest, "CLOSED", "EXACT_COMMIT_RECORD", false)
	if foreignReport.Closure != "UNKNOWN" || foreignReport.Causality != "STATE_ONLY" {
		t.Fatalf("admission + matching state incorrectly reconstructed exact cause: %+v", foreignReport)
	}
}

func testPostconditionIndependentOfAdmissionAndCause(t *testing.T) {
	ctx := context.Background()
	f := setupUnifiedEffectRecord(t)
	if err := executeUnifiedEffectRecord(ctx, f.a.db, f.req, f.seal(t, "admission", f.admission(f.req, 1)), f.policy, nil); err != nil {
		t.Fatal(err)
	}
	before, err := observeUnifiedEffectRecord(ctx, f.a.db, f.req, false)
	if err != nil || before.Commit == nil {
		t.Fatal("control lacks exact effect evidence")
	}
	beforeReport := f.inspect(t, "independence/postcondition/current", f.req, 1, before, "CLOSED", "EXACT_COMMIT_RECORD", true)
	if beforeReport.Causality != "EXACT_COMMIT_RECORD" || beforeReport.AuthorityAtCommit != "VALID_AT_COMMIT" {
		t.Fatalf("control lost admission/cause: %+v", beforeReport)
	}

	if _, err := f.a.db.Exec(
		"UPDATE "+nativeFenceTable("target_state")+" SET digest='independence-later-state' WHERE target=$1",
		f.req.Current.Target,
	); err != nil {
		t.Fatal(err)
	}
	after, err := observeUnifiedEffectRecord(ctx, f.a.db, f.req, false)
	if err != nil || after.Commit == nil {
		t.Fatal("drift world lost the historical physical effect")
	}
	equalJSON(t, admissionCause(f, before), admissionCause(f, after),
		"admission + exact-cause projection changed after independent state drift")
	afterReport := f.inspect(t, "independence/postcondition/drift", f.req, 1, after, "CLOSED", "EXACT_COMMIT_RECORD", false)
	if afterReport.Closure != "UNKNOWN" || afterReport.Causality != "EXACT_COMMIT_RECORD" || afterReport.AuthorityAtCommit != "VALID_AT_COMMIT" {
		t.Fatalf("admission + exact cause incorrectly reconstructed current closure: %+v", afterReport)
	}
}
