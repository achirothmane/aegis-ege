package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// These are truth predicates over native facts, not aliases for the verifier's
// authority-gated report fields. In particular, a truthful unauthorized commit
// can have C=true, and an authorized foreign attempt can have A=true, C=false.
// Every cube world contains one actual physical effect. No-effect is not A=0.
type acpCoordinates struct {
	A bool `json:"A"`
	C bool `json:"C"`
	P bool `json:"P"`
}

func nativeACPCoordinates(t *testing.T, f *noCustodyFixture, d v.Destination) acpCoordinates {
	t.Helper()
	if d.Commit == nil || d.EffectCount != 1 {
		t.Fatal("truth coordinates require one actually committed physical effect")
	}
	c, q := d.Commit, f.req
	effect, err := r.EffectIdentity(q)
	if err != nil || c.EffectID != effect || c.Operation != q.Transition.Operation || c.Before != noCustodyState(q.Current) || c.After != noCustodyState(q.Transition.To) || c.AdmissionBinding != q.Admission.BindingDigest {
		t.Fatal("native fact lost the exact subject/action/target authority scope")
	}
	return acpCoordinates{
		A: c.AuthorityActive && c.AuthorityEpoch == f.epoch && c.AuthorityGeneration == 1,
		C: c.AttemptID == q.AttemptID && c.Owner == (v.Identity{ID: q.Executor.ID, Kind: q.Executor.Kind}),
		P: d.Observed == noCustodyState(q.Transition.To),
	}
}

// This is an explicit privileged destination writer outside the governed
// executor. It captures authority truthfully, without pretending the native
// authority-fenced executor can produce an unauthorized effect. Removing the
// closed-boundary assumption admits this world, just as in constitutional #242.
func nativeUnfencedCommit(t *testing.T, f *noCustodyFixture, q r.Request) {
	t.Helper()
	ctx := context.Background()
	effect, err := r.EffectIdentity(q)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var active bool
	var epoch, generation uint64
	if err := tx.QueryRowContext(ctx, "SELECT active,epoch,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1 FOR SHARE", q.Admission.BindingDigest).Scan(&active, &epoch, &generation); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+nativeFenceTable("ledger")+" (effect_id,amount,attempt_id,target,owner_id,owner_kind,generation,operation,from_revision,to_revision,from_digest,to_digest,admission_binding,authority_epoch,authority_generation,authority_active) VALUES ($1,1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
		effect, q.AttemptID, q.Current.Target, q.Executor.ID, q.Executor.Kind, q.Transition.Operation, q.Current.Revision, q.Transition.To.Revision, q.Current.Digest, q.Transition.To.Digest, q.Admission.BindingDigest, epoch, generation, active); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCompositeACPSeparatingCube(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		want := acpCoordinates{A: mask&4 != 0, C: mask&2 != 0, P: mask&1 != 0}
		name := fmt.Sprintf("%03b", mask)
		t.Run(name, func(t *testing.T) {
			f := setupUnifiedEffectRecord(t)
			q := f.req
			if !want.C {
				q.AttemptID, q.Executor.ID = "attempt:other", "executor:other"
			}
			if want.A {
				if err := executeUnifiedEffectRecord(context.Background(), f.a.db, q, f.seal(t, "admission", f.admission(q, 1)), f.policy, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("authority") + " SET active=FALSE"); err != nil {
					t.Fatal(err)
				}
				nativeUnfencedCommit(t, f, q)
				// Equalize current authority; A remains the historical predicate.
				if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("authority") + " SET active=TRUE"); err != nil {
					t.Fatal(err)
				}
			}
			if !want.P {
				if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest='later-authorized-state'"); err != nil {
					t.Fatal(err)
				}
			}
			d, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
			if err != nil {
				t.Fatal(err)
			}
			got := nativeACPCoordinates(t, f, d)
			if got != want || unifiedEffectTally(t, f) != 1 {
				t.Fatalf("native cube differs: got=%+v want=%+v", got, want)
			}
			closed := got.A && got.C && got.P
			report := f.inspect(t, "conditional-collapse/cube/"+name, f.req, 1, d, "CLOSED", "EXACT_COMMIT_RECORD", closed)
			if (report.Closure == "CLOSED") != closed || report.HistoricalTrust != "UNTRUSTED_HISTORY" {
				t.Fatalf("truth/claim/history dimensions were conflated: %+v", report)
			}
			if root := os.Getenv("COMPOSITE_ARTIFACT_DIR"); root != "" {
				writeCompositeJSON(t, filepath.Join(root, "acp-cube", name+".json"), struct {
					Coordinates acpCoordinates `json:"coordinates"`
					Destination v.Destination  `json:"native_facts"`
					Report      v.Report       `json:"independent_report"`
					Retry       string         `json:"retry"`
				}{got, d, report, "no replay: one effect already committed; UNKNOWN grants no retry"})
			}
		})
	}
}

func TestPostgresCompositeACPAtomicAuthorityDischarge(t *testing.T) {
	for _, name := range []string{"revoked", "stale-generation", "stale-epoch"} {
		t.Run(name, func(t *testing.T) {
			f := setupUnifiedEffectRecord(t)
			admission := f.seal(t, "admission", f.admission(f.req, 1))
			change := "active=FALSE"
			if name == "stale-generation" {
				change = "generation=2"
			} else if name == "stale-epoch" {
				change = "epoch=2"
			}
			if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("authority") + " SET " + change); err != nil {
				t.Fatal(err)
			}
			err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, admission, f.policy, nil)
			if !errors.Is(err, errNativeAuthority) || unifiedEffectTally(t, f) != 0 {
				t.Fatalf("atomic authority discharge failed: error=%v", err)
			}
		})
	}
	// A revocation serialized after the effect does not invalidate A at commit.
	t.Run("revocation-serialized-after-commit", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		barrier := func() error {
			tx, err := f.a.db.Begin()
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()
			if _, err = tx.Exec("SET LOCAL lock_timeout='100ms'"); err != nil {
				return err
			}
			_, err = tx.Exec("UPDATE " + nativeFenceTable("authority") + " SET active=FALSE")
			if err == nil {
				return errors.New("authority mutation passed the in-transaction shared fence")
			}
			// Do not count arbitrary connection/query errors as lock protection.
			if sqlState(err) != "55P03" {
				return fmt.Errorf("expected PostgreSQL lock timeout, got %w", err)
			}
			return nil
		}
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, f.seal(t, "admission", f.admission(f.req, 1)), f.policy, barrier); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.db.Exec("UPDATE " + nativeFenceTable("authority") + " SET active=FALSE"); err != nil {
			t.Fatal(err)
		}
		d, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
		if err != nil || !nativeACPCoordinates(t, f, d).A || d.AuthorityCurrentlyActive {
			t.Fatal("current revocation replaced authority-at-commit")
		}
		f.inspect(t, "conditional-collapse/atomic-authority", f.req, 1, d, "CLOSED", "EXACT_COMMIT_RECORD", true)
	})
}

func sqlState(err error) string {
	var e interface{ SQLState() string }
	if errors.As(err, &e) {
		return e.SQLState()
	}
	return ""
}

func TestPostgresCompositeACPOriginRestriction(t *testing.T) {
	// Unique effect identity, atomic execution, and one-effect cardinality do
	// not imply that the claimed attempt won. A second authorized attempt can.
	t.Run("unique-effect-is-not-unique-origin", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		other := f.req
		other.AttemptID, other.Executor.ID = "attempt:other", "executor:other"
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, other, f.seal(t, "admission", f.admission(other, 1)), f.policy, nil); err != nil {
			t.Fatal(err)
		}
		d, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
		if err != nil || nativeACPCoordinates(t, f, d) != (acpCoordinates{A: true, C: false, P: true}) {
			t.Fatal("unique effect incorrectly implied unique actual-attempt origin")
		}
	})
	// Closed-world, initially empty, sole-attempt destination. This restrictive
	// mechanism really rules out other causes, but carries C in its boundary.
	t.Run("sole-attempt-boundary-discharges-cause", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		// Fixture identities are fixed constants, not interpolated user input.
		if _, err := f.a.db.Exec("ALTER TABLE " + nativeFenceTable("ledger") + " ADD CONSTRAINT sole_attempt CHECK (attempt_id='" + f.req.AttemptID + "' AND owner_id='" + f.req.Executor.ID + "')"); err != nil {
			t.Fatal(err)
		}
		other := f.req
		other.AttemptID, other.Executor.ID = "attempt:other", "executor:other"
		err := executeUnifiedEffectRecord(context.Background(), f.a.db, other, f.seal(t, "admission", f.admission(other, 1)), f.policy, nil)
		if sqlState(err) != "23514" || unifiedEffectTally(t, f) != 0 {
			t.Fatal("sole-origin native constraint did not exclude the foreign attempt")
		}
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, f.seal(t, "admission", f.admission(f.req, 1)), f.policy, nil); err != nil {
			t.Fatal(err)
		}
		d, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
		if err != nil || nativeACPCoordinates(t, f, d) != (acpCoordinates{true, true, true}) {
			t.Fatal("sole-origin positive control failed")
		}
	})
}
