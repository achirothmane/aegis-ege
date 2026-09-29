package eepcrm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
)

func TestEvaluateCustomerUpdatePostconditionUsesRequestedFieldsOnly(t *testing.T) {
	plan := CustomerUpdatePlan{
		CustomerID: "c-17",
		Patch: map[string]any{
			"region": "EU",
			"tier":   "gold",
		},
	}
	verified, err := EvaluateCustomerUpdatePostcondition(plan, map[string]any{
		"id":         "c-17",
		"region":     "EU",
		"tier":       "gold",
		"updated_at": "2026-09-29T12:00:01Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Result != PostconditionVerified || verified.MatchedFields != 2 {
		t.Fatalf("verified evaluation = %+v", verified)
	}

	partial, err := EvaluateCustomerUpdatePostcondition(plan, map[string]any{
		"id":         "c-17",
		"region":     "US",
		"tier":       "gold",
		"updated_at": "2026-09-29T12:00:02Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Result != PostconditionPartial || partial.MatchedFields != 1 {
		t.Fatalf("partial evaluation = %+v", partial)
	}

	ignored, err := EvaluateCustomerUpdatePostcondition(plan, map[string]any{
		"id":         "c-17",
		"region":     "US",
		"tier":       "standard",
		"updated_at": "2026-09-29T12:00:03Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ignored.Result != PostconditionUnsatisfied || ignored.MatchedFields != 0 {
		t.Fatalf("ignored evaluation = %+v", ignored)
	}
}

func TestUnrelatedTimestampChangeDoesNotAlterPostconditionObservation(t *testing.T) {
	plan := CustomerUpdatePlan{
		CustomerID: "c-17",
		Patch:      map[string]any{"tier": "gold"},
	}
	left, err := EvaluateCustomerUpdatePostcondition(plan, map[string]any{
		"id":         "c-17",
		"tier":       "standard",
		"updated_at": "2026-09-29T12:00:01Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := EvaluateCustomerUpdatePostcondition(plan, map[string]any{
		"id":         "c-17",
		"tier":       "standard",
		"updated_at": "2026-09-29T12:00:02Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !EquivalentPostconditionObservation(left, right) {
		t.Fatalf("unrelated timestamp changed intended-postcondition evidence: left=%+v right=%+v", left, right)
	}
	if right.Result != PostconditionUnsatisfied {
		t.Fatalf("result = %s, want UNSATISFIED", right.Result)
	}
}

func TestExecutorAlreadySatisfiedAvoidsMutation(t *testing.T) {
	var patchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"gold"}`)
		case http.MethodPatch:
			patchCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	log := &memoryJournal{}
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), log, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result != PostconditionAlreadySatisfied {
		t.Fatalf("result = %s, want ALREADY_SATISFIED", outcome.Result)
	}
	if outcome.RequestAcceptance != RequestNotDispatched {
		t.Fatalf("acceptance = %s, want NOT_DISPATCHED", outcome.RequestAcceptance)
	}
	if patchCalls.Load() != 0 {
		t.Fatalf("already-satisfied state caused %d PATCH call(s)", patchCalls.Load())
	}
	if len(log.events) != 2 {
		t.Fatalf("journal entries = %d, want authorization + outcome", len(log.events))
	}
	record, err := attempts.Load(context.Background(), attemptIDForFixture(t, fx))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptCompleted {
		t.Fatalf("attempt state = %s, want COMPLETED", record.State)
	}
}

func TestExecutorPartialApplicationIsNotVerified(t *testing.T) {
	var (
		mu         sync.Mutex
		patchCalls int
		tier       = "standard"
		region     = "US"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`","region":"`+region+`"}`)
		case http.MethodPatch:
			patchCalls++
			tier = "gold"
			// Provider silently ignores region.
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	fx = replaceFixturePlan(t, fx, CustomerUpdatePlan{
		CustomerID: "c-17",
		Patch: map[string]any{
			"tier":   "gold",
			"region": "EU",
		},
	})
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrPostconditionNotVerified) {
		t.Fatalf("error = %v, want postcondition failure", err)
	}
	if outcome.Result != PostconditionPartial {
		t.Fatalf("result = %s, want PARTIAL", outcome.Result)
	}
	if outcome.Postcondition == nil || outcome.Postcondition.MatchedFields != 1 || outcome.Postcondition.TotalFields != 2 {
		t.Fatalf("postcondition evidence = %+v", outcome.Postcondition)
	}
	if patchCalls != 1 {
		t.Fatalf("PATCH calls = %d, want 1", patchCalls)
	}
}

func TestExecutorUnrelatedChangeCannotProduceVerifiedOutcome(t *testing.T) {
	var (
		mu        sync.Mutex
		updatedAt = "t0"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard","updated_at":"`+updatedAt+`"}`)
		case http.MethodPatch:
			updatedAt = "t1"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrPostconditionNotVerified) {
		t.Fatalf("error = %v, want postcondition failure", err)
	}
	if outcome.Result != PostconditionUnsatisfied {
		t.Fatalf("result = %s, want UNSATISFIED", outcome.Result)
	}
	if outcome.BeforeDigest == outcome.AfterDigest {
		t.Fatal("test did not exercise the former digest-difference false-success condition")
	}
}

func TestExecutorAcceptedRequestWithUnavailableObservationRemainsUnknown(t *testing.T) {
	var (
		mu       sync.Mutex
		patched  bool
		getCalls int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			getCalls++
			if patched {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard"}`)
		case http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("error = %v, want mutation outcome unknown", err)
	}
	if outcome.Result != PostconditionUnknown ||
		outcome.RequestAcceptance != RequestAccepted ||
		outcome.ObservationStatus != ObservationUnavailable {
		t.Fatalf("unknown outcome = %+v", outcome)
	}
	record, err := attempts.Load(context.Background(), attemptIDForFixture(t, fx))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptAccepted {
		t.Fatalf("attempt state = %s, want ACCEPTED", record.State)
	}
	if getCalls < 2 {
		t.Fatalf("GET calls = %d, expected attempted post-mutation observation", getCalls)
	}
}

func TestExecutorPostMutationWrongTargetReadRemainsUnknown(t *testing.T) {
	var patched bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			if patched {
				_, _ = io.WriteString(w, `{"id":"c-18","tier":"gold"}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard"}`)
		case http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("error = %v, want outcome unknown", err)
	}
	if outcome.Result != PostconditionUnknown || outcome.ObservationStatus != ObservationWrongTarget {
		t.Fatalf("wrong-target outcome = %+v", outcome)
	}
}

func TestExecutorDelayedCompletionRequiresStableIntendedPostcondition(t *testing.T) {
	var (
		mu       sync.Mutex
		patched  bool
		postRead int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			tier := "standard"
			if patched {
				postRead++
				if postRead >= 2 {
					tier = "gold"
				}
			}
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Result != PostconditionVerified ||
		outcome.ObservationStatus != ObservationStable ||
		outcome.ObservationCount != 3 {
		t.Fatalf("delayed outcome = %+v", outcome)
	}
}

func TestExecutorContradictoryObservationsRemainUnknown(t *testing.T) {
	var (
		mu       sync.Mutex
		patched  bool
		postRead int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", testETag)
			tier := "standard"
			if patched {
				postRead++
				if postRead%2 == 1 {
					tier = "gold"
				}
			}
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	outcome, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("error = %v, want outcome unknown", err)
	}
	if outcome.Result != PostconditionUnknown ||
		outcome.ObservationStatus != ObservationContradictory {
		t.Fatalf("contradictory outcome = %+v", outcome)
	}
}

func TestVerifyOutcomeRejectsImpossibleCombinationEvenWithRecomputedDigest(t *testing.T) {
	evaluation, err := EvaluateCustomerUpdatePostcondition(
		CustomerUpdatePlan{CustomerID: "c-17", Patch: map[string]any{"tier": "gold"}},
		map[string]any{"id": "c-17", "tier": "gold"},
	)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := newOutcomeEvidence(
		"intent-1",
		egeproto.Target{Type: "customer", Name: "c-17"},
		"sha256:evidence",
		"sha256:permit",
		"sha256:plan",
		"sha256:before",
		"sha256:after",
		PostconditionVerified,
		RequestAccepted,
		ObservationStable,
		3,
		&evaluation,
		http.StatusNoContent,
		testNow(),
	)
	if err != nil {
		t.Fatal(err)
	}
	outcome.ObservationStatus = ObservationUnavailable
	outcome.IntegrityDigest, err = digestOutcome(outcome)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOutcome(outcome); err == nil ||
		!strings.Contains(err.Error(), "VERIFIED outcome lacks stable intended-postcondition evidence") {
		t.Fatalf("VerifyOutcome() error = %v", err)
	}
}

func testNow() time.Time {
	return time.Date(2026, 9, 29, 12, 0, 5, 0, time.UTC)
}

func replaceFixturePlan(
	t *testing.T,
	fx executionFixture,
	plan CustomerUpdatePlan,
) executionFixture {
	t.Helper()
	planDigest, err := DigestCustomerUpdatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	claims := fx.permit.Claims
	claims.PlanDigest = planDigest
	permit, err := evidencepipeline.SignEvidenceBoundPermit(
		context.Background(),
		fx.authority,
		fx.packet,
		claims,
	)
	if err != nil {
		t.Fatal(err)
	}
	fx.plan = plan
	fx.permit = permit
	return fx
}
