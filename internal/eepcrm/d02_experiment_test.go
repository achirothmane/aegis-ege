package eepcrm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestD02ObserverOutageRecoversAfterStartPermitExpiryWithoutSecondPatch(t *testing.T) {
	var (
		mu                sync.Mutex
		patched           bool
		observerAvailable bool
		tier              = "standard"
		etag              = testETag
		patchCalls        atomic.Int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			if patched && !observerAvailable {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			if r.Header.Get("If-Match") != etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			patchCalls.Add(1)
			patched = true
			tier = "gold"
			etag = "rv-2"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, err := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	log := &memoryJournal{}
	now := fx.now
	executor, err := NewExecutor(
		DestinationConfig{
			BaseURL:        server.URL,
			DestinationID:  testDestinationID,
			AccountID:      testAccountID,
			AdapterProfile: CRMAdapterProfileVersion,
		},
		server.Client(),
		fx.authority,
		log,
		attempts,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("initial execution error = %v, want outcome unknown", err)
	}
	if outcome.RequestAcceptance != RequestAccepted ||
		outcome.ObservationStatus != ObservationUnavailable ||
		outcome.Result != PostconditionUnknown {
		t.Fatalf("initial unresolved outcome = %+v", outcome)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("PATCH calls before recovery = %d, want 1", patchCalls.Load())
	}

	attemptID := attemptIDForFixture(t, fx)
	record, err := attempts.Load(context.Background(), attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptAccepted {
		t.Fatalf("attempt state before recovery = %s, want ACCEPTED", record.State)
	}

	// Starting authority has now expired. K03 permits observation/reconciliation
	// of the already accepted fixed effect but not a new mutation.
	now = fx.permit.Claims.ValidUntil.Add(time.Second)
	mu.Lock()
	observerAvailable = true
	mu.Unlock()

	closure, err := executor.ReconcileAttempt(context.Background(), fx.packet, fx.permit, fx.plan)
	if err != nil {
		t.Fatalf("ReconcileAttempt returned error: %v", err)
	}
	if err := VerifyClosureEvidence(closure); err != nil {
		t.Fatalf("VerifyClosureEvidence: %v", err)
	}
	if closure.Disposition != ClosureObservedCompleted ||
		closure.StateBefore != AttemptAccepted ||
		closure.StateAfter != AttemptCompleted ||
		closure.Result != PostconditionVerified ||
		closure.RequestAcceptance != RequestAccepted ||
		closure.ObservationStatus != ObservationStable ||
		closure.ResidualCustody ||
		closure.NewMutationDispatched {
		t.Fatalf("unexpected closure evidence: %+v", closure)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("recovery dispatched a second PATCH: %d", patchCalls.Load())
	}

	record, err = attempts.Load(context.Background(), attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptCompleted {
		t.Fatalf("attempt state after recovery = %s, want COMPLETED", record.State)
	}

	if _, err := executor.ReconcileAttempt(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrAttemptClosureState) {
		t.Fatalf("duplicate recovery error = %v, want closed-attempt rejection", err)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("duplicate recovery created a new effect: PATCH calls=%d", patchCalls.Load())
	}
}

func TestD02PermanentObservationGapRetiresUnknownOnlyAfterJournaledCustody(t *testing.T) {
	var (
		mu         sync.Mutex
		patched    bool
		tier       = "standard"
		patchCalls atomic.Int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			if patched {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			patchCalls.Add(1)
			patched = true
			tier = "gold"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, err := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	log := &memoryJournal{}
	executor := newTestExecutor(
		t,
		fx,
		server.URL,
		testDestinationID,
		testAccountID,
		server.Client(),
		log,
		attempts,
	)

	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("initial execution error = %v, want outcome unknown", err)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("PATCH calls = %d, want 1", patchCalls.Load())
	}
	attemptID := attemptIDForFixture(t, fx)

	// A closure-journal outage must not silently retire the attempt.
	log.mu.Lock()
	log.failAt = len(log.events) + 1
	log.mu.Unlock()
	if _, err := executor.RetireAttemptUnknown(
		context.Background(),
		fx.packet,
		fx.permit,
		fx.plan,
		"D02 synthetic observer horizon exhausted",
	); err == nil {
		t.Fatal("journal outage unexpectedly retired UNKNOWN")
	}
	record, err := attempts.Load(context.Background(), attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptAccepted {
		t.Fatalf("journal-outage state = %s, want ACCEPTED", record.State)
	}

	log.mu.Lock()
	log.failAt = 0
	log.mu.Unlock()
	closure, err := executor.RetireAttemptUnknown(
		context.Background(),
		fx.packet,
		fx.permit,
		fx.plan,
		"D02 synthetic observer horizon exhausted",
	)
	if err != nil {
		t.Fatalf("RetireAttemptUnknown returned error: %v", err)
	}
	if err := VerifyClosureEvidence(closure); err != nil {
		t.Fatalf("VerifyClosureEvidence: %v", err)
	}
	if closure.Disposition != ClosureRetiredUnknown ||
		closure.StateAfter != AttemptRetiredUnknown ||
		!closure.ResidualCustody ||
		closure.Result != PostconditionUnknown ||
		closure.NewMutationDispatched {
		t.Fatalf("unexpected UNKNOWN retirement evidence: %+v", closure)
	}

	record, err = attempts.Load(context.Background(), attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptRetiredUnknown {
		t.Fatalf("retired attempt state = %s, want RETIRED_UNKNOWN", record.State)
	}
	if record.ObservationHandle == "" ||
		record.CustomerID != "c-17" ||
		record.DestinationID != testDestinationID ||
		record.AccountID != testAccountID {
		t.Fatalf("residual custody lost identity: %+v", record)
	}

	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrAttemptAlreadyClaimed) {
		t.Fatalf("post-retirement replay error = %v, want already claimed", err)
	}
	if _, err := executor.ReconcileAttempt(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrAttemptRetiredUnknown) {
		t.Fatalf("post-retirement observation error = %v, want retired UNKNOWN", err)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("UNKNOWN retirement/replay created another effect: PATCH calls=%d", patchCalls.Load())
	}
}

func TestD02ExpiredStartPermitCannotCreateNewEffect(t *testing.T) {
	var patchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard"}`)
		case http.MethodPatch:
			patchCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, err := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(
		DestinationConfig{
			BaseURL:        server.URL,
			DestinationID:  testDestinationID,
			AccountID:      testAccountID,
			AdapterProfile: CRMAdapterProfileVersion,
		},
		server.Client(),
		fx.authority,
		&memoryJournal{},
		attempts,
		func() time.Time { return fx.permit.Claims.ValidUntil },
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err == nil ||
		!strings.Contains(err.Error(), "execution permit expired") {
		t.Fatalf("expired permit error = %v", err)
	}
	if patchCalls.Load() != 0 {
		t.Fatalf("expired authority reached PATCH: %d", patchCalls.Load())
	}
}

func TestD02RecoveryRejectsChangedPlanWhileWaitingWithoutNewEffect(t *testing.T) {
	var (
		patched    atomic.Bool
		patchCalls atomic.Int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			if patched.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard"}`)
		case http.MethodPatch:
			patchCalls.Add(1)
			patched.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, err := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := newTestExecutor(
		t,
		fx,
		server.URL,
		testDestinationID,
		testAccountID,
		server.Client(),
		&memoryJournal{},
		attempts,
	)

	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("initial execution error = %v, want outcome unknown", err)
	}
	changed := CustomerUpdatePlan{
		CustomerID: fx.plan.CustomerID,
		Patch:      map[string]any{"tier": "platinum"},
	}
	if _, err := executor.ReconcileAttempt(context.Background(), fx.packet, fx.permit, changed); err == nil ||
		!strings.Contains(err.Error(), "plan digest mismatch") {
		t.Fatalf("changed-plan recovery error = %v", err)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("changed-plan recovery created another effect: PATCH calls=%d", patchCalls.Load())
	}
}
