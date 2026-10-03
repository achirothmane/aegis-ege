package simulation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

const nativeFenceSchema = "native_destination_fence_v1"

var (
	errNativeFence       = errors.New("native destination fence rejected stale owner or generation")
	errNativeState       = errors.New("native destination fence rejected stale state")
	errNativeAuthority   = errors.New("native destination fence rejected inactive authority")
	errNativeTransition  = errors.New("native destination fence rejected transition substitution")
	errNativeObservation = errors.New("native destination observation missing exact effect")
	errNativeUntrusted   = errors.New("native destination attestation issuer is not trusted")
	errNativeCAS         = errors.New("native destination custody compare-and-swap failed")
)

var (
	nativePolicyIssuer   = gaRuntime.Identity{ID: "policy:native-postgres", Kind: "policy"}
	nativeTakeoverIssuer = gaRuntime.Identity{ID: "controller:native-postgres", Kind: "controller"}
	nativeObserverIssuer = gaRuntime.Identity{ID: "observer:native-postgres", Kind: "observer"}
)

type postgresNativeFenceAdapter struct {
	db  *sql.DB
	req gaRuntime.Request

	mu                sync.Mutex
	policyVerifyCount int
	afterPolicyVerify func(int)
}

func nativeFenceTable(name string) string {
	return nativeFenceSchema + "." + name
}

func (a *postgresNativeFenceAdapter) CurrentState(ctx context.Context, target string) (gaRuntime.State, error) {
	var state gaRuntime.State
	state.Target = target
	err := a.db.QueryRowContext(
		ctx,
		"SELECT revision, digest FROM "+nativeFenceTable("target_state")+" WHERE target = $1",
		target,
	).Scan(&state.Revision, &state.Digest)
	return state, err
}

func (a *postgresNativeFenceAdapter) VerifyAttestation(ctx context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return gaRuntime.ErrAdmissionBinding
	}

	switch {
	case att.Issuer.Equal(nativePolicyIssuer):
		var active bool
		err := a.db.QueryRowContext(
			ctx,
			"SELECT active FROM "+nativeFenceTable("authority")+" WHERE binding_digest = $1",
			expected,
		).Scan(&active)
		if err != nil {
			return err
		}
		if !active {
			return errNativeAuthority
		}

		a.mu.Lock()
		a.policyVerifyCount++
		count := a.policyVerifyCount
		hook := a.afterPolicyVerify
		a.mu.Unlock()
		if hook != nil {
			hook(count)
		}
		return nil

	case att.Issuer.Equal(nativeTakeoverIssuer), att.Issuer.Equal(nativeObserverIssuer):
		return nil

	default:
		return errNativeUntrusted
	}
}

func (a *postgresNativeFenceAdapter) ReserveFencedCustody(ctx context.Context, custody gaRuntime.FencedCustody) error {
	result, err := a.db.ExecContext(
		ctx,
		"INSERT INTO "+nativeFenceTable("custody")+" "+
			"(effect_id, attempt_id, target, owner_id, owner_kind, generation, phase, expected_revision, expected_digest, admission_binding, authority_epoch, authority_generation) "+
			"SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,epoch,generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$10 AND active=TRUE",
		custody.EffectID,
		custody.AttemptID,
		custody.Target,
		custody.Owner.ID,
		custody.Owner.Kind,
		custody.Generation,
		string(custody.Phase),
		a.req.Current.Revision,
		a.req.Current.Digest,
		a.req.Admission.BindingDigest,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errNativeAuthority
	}
	return nil
}

func (a *postgresNativeFenceAdapter) LoadFencedCustody(ctx context.Context, effectID, attemptID string) (gaRuntime.FencedCustody, error) {
	var custody gaRuntime.FencedCustody
	var phase string
	var generation int64
	err := a.db.QueryRowContext(
		ctx,
		"SELECT effect_id, attempt_id, target, owner_id, owner_kind, generation, phase "+
			"FROM "+nativeFenceTable("custody")+" WHERE effect_id = $1 AND attempt_id = $2",
		effectID,
		attemptID,
	).Scan(
		&custody.EffectID,
		&custody.AttemptID,
		&custody.Target,
		&custody.Owner.ID,
		&custody.Owner.Kind,
		&generation,
		&phase,
	)
	if err == nil {
		custody.Generation = uint64(generation)
	}
	custody.Phase = gaRuntime.CustodyPhase(phase)
	return custody, err
}

func (a *postgresNativeFenceAdapter) TransitionFencedCustodyCAS(ctx context.Context, expected, next gaRuntime.FencedCustody) error {
	result, err := a.db.ExecContext(
		ctx,
		"UPDATE "+nativeFenceTable("custody")+" "+
			"SET owner_id=$1, owner_kind=$2, generation=$3, phase=$4 "+
			"WHERE effect_id=$5 AND attempt_id=$6 AND target=$7 "+
			"AND owner_id=$8 AND owner_kind=$9 AND generation=$10 AND phase=$11",
		next.Owner.ID,
		next.Owner.Kind,
		next.Generation,
		string(next.Phase),
		expected.EffectID,
		expected.AttemptID,
		expected.Target,
		expected.Owner.ID,
		expected.Owner.Kind,
		expected.Generation,
		string(expected.Phase),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errNativeCAS
	}
	return nil
}

// ExecuteFenced is the native destination boundary in this proof.
//
// The custody owner/generation, exact target state, and admission authority are
// all read and locked in the same PostgreSQL transaction that inserts the
// externally visible effect and advances target state. A userspace check is not
// sufficient for this proof; stale values must be rejected again here.
func (a *postgresNativeFenceAdapter) ExecuteFenced(
	ctx context.Context,
	transition gaRuntime.Transition,
	custody gaRuntime.FencedCustody,
) (gaRuntime.Acceptance, error) {
	if transition.Operation != a.req.Transition.Operation ||
		!transition.From.Equal(a.req.Transition.From) ||
		!transition.To.Equal(a.req.Transition.To) {
		return gaRuntime.Acceptance{}, errNativeTransition
	}

	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		ownerID, ownerKind, phase                           string
		target, expectedRevision, expectedDigest            string
		admissionBinding                                    string
		generationRaw                                       int64
		expectedAuthorityEpoch, expectedAuthorityGeneration int64
	)
	err = tx.QueryRowContext(
		ctx,
		"SELECT target, owner_id, owner_kind, generation, phase, expected_revision, expected_digest, admission_binding, authority_epoch, authority_generation "+
			"FROM "+nativeFenceTable("custody")+" "+
			"WHERE effect_id=$1 AND attempt_id=$2 FOR UPDATE",
		custody.EffectID,
		custody.AttemptID,
	).Scan(
		&target,
		&ownerID,
		&ownerKind,
		&generationRaw,
		&phase,
		&expectedRevision,
		&expectedDigest,
		&admissionBinding,
		&expectedAuthorityEpoch,
		&expectedAuthorityGeneration,
	)
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	generation := uint64(generationRaw)
	if target != custody.Target ||
		ownerID != custody.Owner.ID ||
		ownerKind != custody.Owner.Kind ||
		generation != custody.Generation ||
		phase != string(gaRuntime.CustodyCrossing) {
		return gaRuntime.Acceptance{}, errNativeFence
	}
	if expectedRevision != transition.From.Revision ||
		expectedDigest != transition.From.Digest ||
		admissionBinding != a.req.Admission.BindingDigest {
		return gaRuntime.Acceptance{}, errNativeFence
	}

	var revision, digest string
	if err := tx.QueryRowContext(
		ctx,
		"SELECT revision, digest FROM "+nativeFenceTable("target_state")+" WHERE target=$1 FOR UPDATE",
		transition.From.Target,
	).Scan(&revision, &digest); err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if revision != transition.From.Revision || digest != transition.From.Digest {
		return gaRuntime.Acceptance{}, errNativeState
	}

	var active bool
	var authorityEpoch, authorityGeneration int64
	if err := tx.QueryRowContext(
		ctx,
		"SELECT active, epoch, generation FROM "+nativeFenceTable("authority")+" WHERE binding_digest=$1 FOR SHARE",
		admissionBinding,
	).Scan(&active, &authorityEpoch, &authorityGeneration); err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if !active || authorityEpoch != expectedAuthorityEpoch || authorityGeneration != expectedAuthorityGeneration {
		return gaRuntime.Acceptance{}, errNativeAuthority
	}

	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO "+nativeFenceTable("effects")+" "+
			"(effect_id, attempt_id, target, owner_id, owner_kind, generation, operation, from_revision, to_revision, from_digest, to_digest, admission_binding, authority_epoch, authority_generation, authority_active) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
		custody.EffectID,
		custody.AttemptID,
		custody.Target,
		custody.Owner.ID,
		custody.Owner.Kind,
		custody.Generation,
		transition.Operation,
		transition.From.Revision,
		transition.To.Revision,
		transition.From.Digest,
		transition.To.Digest,
		admissionBinding,
		authorityEpoch,
		authorityGeneration,
		active,
	); err != nil {
		return gaRuntime.Acceptance{}, fmt.Errorf("native effect insert: %w", err)
	}

	result, err := tx.ExecContext(
		ctx,
		"UPDATE "+nativeFenceTable("target_state")+" SET revision=$1, digest=$2 "+
			"WHERE target=$3 AND revision=$4 AND digest=$5",
		transition.To.Revision,
		transition.To.Digest,
		transition.To.Target,
		transition.From.Revision,
		transition.From.Digest,
	)
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return gaRuntime.Acceptance{}, err
	}
	if rows != 1 {
		return gaRuntime.Acceptance{}, errNativeState
	}

	if err := tx.Commit(); err != nil {
		return gaRuntime.Acceptance{}, err
	}
	return gaRuntime.Acceptance{Reference: "postgres-native:" + custody.EffectID}, nil
}

func (a *postgresNativeFenceAdapter) ObserveFenced(
	ctx context.Context,
	transition gaRuntime.Transition,
	custody gaRuntime.FencedCustody,
) (gaRuntime.Observation, error) {
	var effectCount int
	if err := a.db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM "+nativeFenceTable("effects")+" "+
			"WHERE effect_id=$1 AND attempt_id=$2 AND owner_id=$3 AND generation=$4 "+
			"AND owner_kind=$5 AND target=$6 AND operation=$7 AND from_revision=$8 AND to_revision=$9 "+
			"AND from_digest=$10 AND to_digest=$11 AND admission_binding=$12 AND authority_active=TRUE",
		custody.EffectID,
		custody.AttemptID,
		custody.Owner.ID,
		custody.Generation,
		custody.Owner.Kind,
		custody.Target,
		transition.Operation,
		transition.From.Revision,
		transition.To.Revision,
		transition.From.Digest,
		transition.To.Digest,
		a.req.Admission.BindingDigest,
	).Scan(&effectCount); err != nil {
		return gaRuntime.Observation{}, err
	}
	if effectCount != 1 {
		return gaRuntime.Observation{}, errNativeObservation
	}

	state, err := a.CurrentState(ctx, transition.To.Target)
	if err != nil {
		return gaRuntime.Observation{}, err
	}
	binding := gaRuntime.ObservationBindingDigest(custody.EffectID, state)
	return gaRuntime.Observation{
		State: state,
		Attestation: gaRuntime.Attestation{
			ID:            "observation:native-postgres",
			Issuer:        nativeObserverIssuer,
			BindingDigest: binding,
		},
	}, nil
}

func nativeFenceRequest(t *testing.T) gaRuntime.Request {
	t.Helper()
	from := gaRuntime.State{
		Target:   "native-target:acct-001",
		Revision: "rev:1",
		Digest:   "sha256:native-state-1",
	}
	to := gaRuntime.State{
		Target:   from.Target,
		Revision: "rev:2",
		Digest:   "sha256:native-state-2",
	}
	req := gaRuntime.Request{
		Subject:    gaRuntime.Identity{ID: "subject:native-001", Kind: "service"},
		Executor:   gaRuntime.Identity{ID: "executor:A", Kind: "worker"},
		Current:    from,
		Transition: gaRuntime.Transition{Operation: "native-postgres-update", From: from, To: to},
		AttemptID:  "attempt:native-001",
		Admission: gaRuntime.Attestation{
			ID:     "admission:native-001",
			Issuer: nativePolicyIssuer,
		},
	}
	binding, err := gaRuntime.AdmissionBindingDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Admission.BindingDigest = binding
	return req
}

func setupPostgresNativeFence(t *testing.T) (*postgresNativeFenceAdapter, gaRuntime.Request) {
	t.Helper()
	dsn := os.Getenv("GOSMIG_SIM_ADMIN_DSN")
	if dsn == "" {
		if os.Getenv("NATIVE_FENCE_REQUIRE") == "1" {
			t.Fatal("GOSMIG_SIM_ADMIN_DSN is required for native destination fencing proof")
		}
		t.Skip("GOSMIG_SIM_ADMIN_DSN is not set")
	}

	db, err := openDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA IF EXISTS " + nativeFenceSchema + " CASCADE")
		_ = db.Close()
	})

	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + nativeFenceSchema + " CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE SCHEMA " + nativeFenceSchema); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE TABLE " + nativeFenceTable("target_state") + " (" +
			"target TEXT PRIMARY KEY, revision TEXT NOT NULL, digest TEXT NOT NULL)",
		"CREATE TABLE " + nativeFenceTable("authority") + " (" +
			"binding_digest TEXT PRIMARY KEY, active BOOLEAN NOT NULL, epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0), generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0))",
		"CREATE TABLE " + nativeFenceTable("custody") + " (" +
			"effect_id TEXT NOT NULL, attempt_id TEXT NOT NULL, target TEXT NOT NULL, " +
			"owner_id TEXT NOT NULL, owner_kind TEXT NOT NULL, generation BIGINT NOT NULL CHECK (generation > 0), " +
			"phase TEXT NOT NULL CHECK (phase IN ('RESERVED','CROSSING','UNKNOWN','CLOSED')), " +
			"expected_revision TEXT NOT NULL, expected_digest TEXT NOT NULL, admission_binding TEXT NOT NULL, authority_epoch BIGINT NOT NULL, authority_generation BIGINT NOT NULL, " +
			"PRIMARY KEY (effect_id, attempt_id))",
		"CREATE TABLE " + nativeFenceTable("effects") + " (" +
			"effect_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, target TEXT NOT NULL, " +
			"owner_id TEXT NOT NULL, owner_kind TEXT NOT NULL, generation BIGINT NOT NULL, " +
			"operation TEXT NOT NULL, from_revision TEXT NOT NULL, to_revision TEXT NOT NULL, from_digest TEXT NOT NULL, to_digest TEXT NOT NULL, admission_binding TEXT NOT NULL, authority_epoch BIGINT NOT NULL, authority_generation BIGINT NOT NULL, authority_active BOOLEAN NOT NULL, " +
			"created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	req := nativeFenceRequest(t)
	if _, err := db.Exec(
		"INSERT INTO "+nativeFenceTable("target_state")+" (target, revision, digest) VALUES ($1,$2,$3)",
		req.Current.Target,
		req.Current.Revision,
		req.Current.Digest,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO "+nativeFenceTable("authority")+" (binding_digest, active) VALUES ($1, TRUE)",
		req.Admission.BindingDigest,
	); err != nil {
		t.Fatal(err)
	}

	return &postgresNativeFenceAdapter{db: db, req: req}, req
}

func nativeEffectCount(t *testing.T, adapter *postgresNativeFenceAdapter) int {
	t.Helper()
	var count int
	if err := adapter.db.QueryRow("SELECT COUNT(*) FROM " + nativeFenceTable("effects")).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func nativeTakeoverRequest(
	t *testing.T,
	original gaRuntime.Request,
	current gaRuntime.FencedCustody,
	newOwner gaRuntime.Identity,
) gaRuntime.TakeoverRequest {
	t.Helper()
	return gaRuntime.TakeoverRequest{
		Original: original,
		NewOwner: newOwner,
		Authorization: gaRuntime.Attestation{
			ID:            "takeover:native-postgres",
			Issuer:        nativeTakeoverIssuer,
			BindingDigest: gaRuntime.TakeoverBindingDigest(current, newOwner),
		},
	}
}

func TestPostgresNativeDestinationFenceRejectsStaleOwnerAfterTakeover(t *testing.T) {
	adapter, req := setupPostgresNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	ownerB := gaRuntime.Identity{ID: "executor:B", Kind: "worker"}
	taken, err := gaRuntime.TakeoverReserved(ctx, nativeTakeoverRequest(t, req, prep.Custody, ownerB), adapter)
	if err != nil {
		t.Fatal(err)
	}
	if taken.Current.Generation != 2 || !taken.Current.Owner.Equal(ownerB) {
		t.Fatalf("unexpected takeover: %+v", taken)
	}

	// Simulate a late A bypassing normal runtime sequencing and calling the
	// destination callback with its stale local token. PostgreSQL must reject
	// it from durable state, not from a prior userspace check.
	staleA := prep.Custody
	staleA.Phase = gaRuntime.CustodyCrossing
	if _, err := adapter.ExecuteFenced(ctx, req.Transition, staleA); !errors.Is(err, errNativeFence) {
		t.Fatalf("stale A reached native destination: %v", err)
	}
	if got := nativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("stale A produced %d native effects", got)
	}

	reqB := req
	reqB.Executor = ownerB
	result := gaRuntime.ExecuteReservedFenced(ctx, reqB, taken.Current, adapter)
	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("current owner did not close exact effect: %+v", result)
	}
	if got := nativeEffectCount(t, adapter); got != 1 {
		t.Fatalf("expected one native effect, got %d", got)
	}
	if result.Custody.Generation != 2 || result.Custody.Phase != gaRuntime.CustodyClosed {
		t.Fatalf("unexpected closed custody: %+v", result.Custody)
	}
}

func TestPostgresNativeDestinationFenceRejectsStateDriftAfterRuntimeRevalidation(t *testing.T) {
	adapter, req := setupPostgresNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	adapter.afterPolicyVerify = func(count int) {
		// ReserveFenced performs two policy verifications. ExecuteReservedFenced
		// performs one before custody load and one after RESERVED->CROSSING.
		// Change destination state immediately after that fourth successful
		// userspace verification, before ExecuteFenced begins its transaction.
		if count == 4 {
			if _, err := adapter.db.Exec(
				"UPDATE "+nativeFenceTable("target_state")+" SET revision='rev:drift', digest='sha256:drift' WHERE target=$1",
				req.Current.Target,
			); err != nil {
				panic(err)
			}
		}
	}

	result := gaRuntime.ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
	if !result.BoundaryEntered || result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("native state race was not represented conservatively: %+v", result)
	}
	if !errors.Is(result.EffectError, errNativeState) {
		t.Fatalf("destination did not reject stale state: %+v", result)
	}
	if got := nativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("state race produced %d native effects", got)
	}
	if result.Custody.Phase != gaRuntime.CustodyUnknown {
		t.Fatalf("rejected callback reopened custody: %+v", result.Custody)
	}
}

func TestPostgresNativeDestinationFenceRejectsAuthorityRevocationAfterRuntimeRevalidation(t *testing.T) {
	adapter, req := setupPostgresNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}

	adapter.afterPolicyVerify = func(count int) {
		if count == 4 {
			if _, err := adapter.db.Exec(
				"UPDATE "+nativeFenceTable("authority")+" SET active=FALSE WHERE binding_digest=$1",
				req.Admission.BindingDigest,
			); err != nil {
				panic(err)
			}
		}
	}

	result := gaRuntime.ExecuteReservedFenced(ctx, req, prep.Custody, adapter)
	if !result.BoundaryEntered || result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("native authority race was not represented conservatively: %+v", result)
	}
	if !errors.Is(result.EffectError, errNativeAuthority) {
		t.Fatalf("destination did not reject revoked authority: %+v", result)
	}
	if got := nativeEffectCount(t, adapter); got != 0 {
		t.Fatalf("revoked authority produced %d native effects", got)
	}
	if result.Custody.Phase != gaRuntime.CustodyUnknown {
		t.Fatalf("rejected callback reopened custody: %+v", result.Custody)
	}
}

func TestPostgresNativeDestinationFenceRejectsExactTokenReplay(t *testing.T) {
	adapter, req := setupPostgresNativeFence(t)
	ctx := context.Background()

	prep, err := gaRuntime.ReserveFenced(ctx, req, adapter)
	if err != nil {
		t.Fatal(err)
	}
	crossing := prep.Custody
	crossing.Phase = gaRuntime.CustodyCrossing
	if err := adapter.TransitionFencedCustodyCAS(ctx, prep.Custody, crossing); err != nil {
		t.Fatal(err)
	}

	if _, err := adapter.ExecuteFenced(ctx, req.Transition, crossing); err != nil {
		t.Fatalf("first exact native effect failed: %v", err)
	}
	if _, err := adapter.ExecuteFenced(ctx, req.Transition, crossing); !errors.Is(err, errNativeState) {
		t.Fatalf("exact token replay was not rejected by destination state: %v", err)
	}
	if got := nativeEffectCount(t, adapter); got != 1 {
		t.Fatalf("exact token replay changed cardinality: %d", got)
	}
}
