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

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/evidencepipeline"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

const (
	testDestinationID = "crm-destination-1"
	testAccountID     = "account-1"
	testETag          = "rv-1"
)

type memoryJournal struct {
	mu     sync.Mutex
	events []journal.Event
	failAt int
}

func (j *memoryJournal) Append(_ context.Context, event journal.Event) (journal.Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, event)
	if j.failAt > 0 && len(j.events) == j.failAt {
		return journal.Entry{}, errors.New("journal unavailable")
	}
	return journal.Entry{Event: event}, nil
}

type failingAttemptStore struct{}

func (failingAttemptStore) Claim(context.Context, AttemptRecord) error {
	return errors.New("attempt store unavailable")
}
func (failingAttemptStore) Transition(context.Context, string, AttemptState, AttemptState, int, string, time.Time) (AttemptRecord, error) {
	return AttemptRecord{}, errors.New("attempt store unavailable")
}
func (failingAttemptStore) Load(context.Context, string) (AttemptRecord, error) {
	return AttemptRecord{}, errors.New("attempt store unavailable")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type executionFixture struct {
	now       time.Time
	packet    evidencepipeline.Packet
	permit    egeproto.Permit
	plan      CustomerUpdatePlan
	authority egeproto.PermitAuthority
}

func newExecutionFixture(
	t *testing.T,
	endpoint string,
	destinationID string,
	accountID string,
	expectedVersion string,
) executionFixture {
	t.Helper()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	binding := &evidencepipeline.ExecutionBinding{
		DestinationID:           destinationID,
		AccountID:               accountID,
		Endpoint:                endpoint,
		AdapterProfile:          CRMAdapterProfileVersion,
		ExpectedResourceVersion: expectedVersion,
	}
	packet, err := evidencepipeline.Compile(evidencepipeline.CompileRequest{
		Event: evidencepipeline.RuntimeEvent{
			IntentID: "intent-c06-1",
			EventID:  "event-c06-1",
			Actor: evidencepipeline.Actor{
				PrincipalID: "spiffe://test/c06",
			},
			Action: evidencepipeline.Action{
				Kind:       "crm.customer_update",
				Tool:       "crm.http-json",
				Operation:  "update_customer",
				Target:     "customer/c-17",
				SideEffect: true,
			},
			ObservedAt: now.Add(-time.Second),
			Data:       map[string]any{"ticket": "T-600"},
		},
		Source: evidencepipeline.Source{Name: "test", TrustDomain: "test"},
		Context: evidencepipeline.BootstrapContext{
			AuthorityRef:        "authority://crm/c06",
			PolicyRef:           "policy://crm/c06",
			RedactionProfileRef: "redaction://none",
			ConsequenceClass:    "customer-record-write",
			ExecutionBinding:    binding,
		},
		SensitivePaths: []string{},
		CapturedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := CustomerUpdatePlan{CustomerID: "c-17", Patch: map[string]any{"tier": "gold"}}
	planDigest, err := DigestCustomerUpdatePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := egeproto.NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := evidencepipeline.SignEvidenceBoundPermit(
		context.Background(),
		authority,
		packet,
		egeproto.PermitClaims{
			IntentID:        packet.IntentID,
			Kind:            packet.Action.Kind,
			Target:          egeproto.Target{Type: "customer", Name: "c-17"},
			Action:          packet.Action.Operation,
			ResourceVersion: expectedVersion,
			EvidenceDigest:  packet.Provenance.InputDigest,
			PlanDigest:      planDigest,
			ExecutionBinding: &egeproto.ExecutionBindingClaims{
				DestinationID:           destinationID,
				AccountID:               accountID,
				Endpoint:                endpoint,
				AdapterProfile:          CRMAdapterProfileVersion,
				ExpectedResourceVersion: expectedVersion,
			},
			ValidUntil: now.Add(time.Minute),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return executionFixture{now: now, packet: packet, permit: permit, plan: plan, authority: authority}
}

func newTestExecutor(
	t *testing.T,
	fx executionFixture,
	baseURL string,
	destinationID string,
	accountID string,
	client *http.Client,
	j JournalAppender,
	attempts AttemptStore,
) *Executor {
	t.Helper()
	executor, err := NewExecutor(
		DestinationConfig{
			BaseURL:        baseURL,
			DestinationID:  destinationID,
			AccountID:      accountID,
			AdapterProfile: CRMAdapterProfileVersion,
		},
		client,
		fx.authority,
		j,
		attempts,
		func() time.Time { return fx.now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func attemptIDForFixture(t *testing.T, fx executionFixture) string {
	t.Helper()
	permitDigest, err := journal.DigestPayload(fx.permit)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := DigestCustomerUpdatePlan(fx.plan)
	if err != nil {
		t.Fatal(err)
	}
	id, err := MutationAttemptID(permitDigest, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestExecutorBoundConditionalMutationAndDurableCompletion(t *testing.T) {
	var (
		mu         sync.Mutex
		etag       = testETag
		patchCalls int
		tier       = "standard"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", etag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			if r.Header.Get("If-Match") != etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if r.Header.Get(headerDestinationID) != testDestinationID ||
				r.Header.Get(headerAccountID) != testAccountID {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			patchCalls++
			tier = "gold"
			etag = "rv-2"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	dir := t.TempDir()
	attempts, err := NewFileAttemptStore(filepath.Join(dir, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	log := &memoryJournal{}
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), log, attempts)

	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotCalls := patchCalls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("PATCH calls = %d, want 1", gotCalls)
	}
	record, err := attempts.Load(context.Background(), attemptIDForFixture(t, fx))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptCompleted {
		t.Fatalf("attempt state = %s, want COMPLETED", record.State)
	}
	if len(log.events) != 3 || log.events[1].Type != journal.EventExecution {
		t.Fatalf("journal events = %#v", log.events)
	}
}

func TestExecutorReplayAfterRestartDoesNotDispatchAgain(t *testing.T) {
	var patchCalls atomic.Int32
	server := conditionalCRMServer(t, &patchCalls, testETag, false)
	defer server.Close()

	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "attempts")
	store1, _ := NewFileAttemptStore(storeDir)
	executor1 := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, store1)
	if _, err := executor1.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err != nil {
		t.Fatal(err)
	}

	store2, err := NewFileAttemptStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	executor2 := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, store2)
	if _, err := executor2.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrAttemptAlreadyClaimed) && !strings.Contains(fmt.Sprint(err), ErrAttemptAlreadyClaimed.Error()) {
		t.Fatalf("restart replay error = %v, want already claimed", err)
	}
	if got := patchCalls.Load(); got != 1 {
		t.Fatalf("PATCH calls after restart replay = %d, want 1", got)
	}
}

func TestExecutorConcurrentDuplicateAllowsOnePossibleEffect(t *testing.T) {
	var patchCalls atomic.Int32
	server := conditionalCRMServer(t, &patchCalls, testETag, false)
	defer server.Close()
	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	start := make(chan struct{})
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
			errs <- err
		}()
	}
	close(start)
	err1, err2 := <-errs, <-errs
	successes := 0
	for _, err := range []error{err1, err2} {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful executions = %d, errors=(%v, %v)", successes, err1, err2)
	}
	if got := patchCalls.Load(); got != 1 {
		t.Fatalf("PATCH calls = %d, want 1", got)
	}
}

func TestExecutorStalePreconditionBlocksAtDestination(t *testing.T) {
	var patchCalls atomic.Int32
	server := conditionalCRMServer(t, &patchCalls, "rv-2", false)
	defer server.Close()
	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, attempts)

	_, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if err == nil || !strings.Contains(err.Error(), "precondition is stale") {
		t.Fatalf("error = %v, want stale precondition", err)
	}
	if patchCalls.Load() != 0 {
		t.Fatal("stale precondition reached PATCH")
	}
	record, err := attempts.Load(context.Background(), attemptIDForFixture(t, fx))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptBlocked {
		t.Fatalf("attempt state = %s, want BLOCKED", record.State)
	}
}

func TestExecutorAttemptStoreAndJournalOutagePreventDispatch(t *testing.T) {
	var patchCalls atomic.Int32
	server := conditionalCRMServer(t, &patchCalls, testETag, false)
	defer server.Close()
	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)

	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, failingAttemptStore{})
	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err == nil {
		t.Fatal("attempt-store outage unexpectedly allowed execution")
	}
	if patchCalls.Load() != 0 {
		t.Fatal("attempt-store outage reached PATCH")
	}

	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor = newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{failAt: 1}, attempts)
	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err == nil {
		t.Fatal("journal outage unexpectedly allowed execution")
	}
	if patchCalls.Load() != 0 {
		t.Fatal("journal outage reached PATCH")
	}
}

func TestExecutorLostResponseAfterCommitRemainsPossibleEffectAndNoRetry(t *testing.T) {
	var patchCalls atomic.Int32
	server := conditionalCRMServer(t, &patchCalls, testETag, false)
	defer server.Close()
	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)

	baseTransport := server.Client().Transport
	lostClient := *server.Client()
	lostClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := baseTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if req.Method == http.MethodPatch {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, errors.New("simulated response loss after commit")
		}
		return resp, nil
	})

	dir := t.TempDir()
	storeDir := filepath.Join(dir, "attempts")
	attempts, _ := NewFileAttemptStore(storeDir)
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, &lostClient, &memoryJournal{}, attempts)

	_, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan)
	if !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("error = %v, want outcome unknown", err)
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("PATCH calls = %d, want 1", patchCalls.Load())
	}
	record, err := attempts.Load(context.Background(), attemptIDForFixture(t, fx))
	if err != nil {
		t.Fatal(err)
	}
	if record.State != AttemptPossibleEffect {
		t.Fatalf("attempt state = %s, want POSSIBLE_EFFECT", record.State)
	}

	restarted, _ := NewFileAttemptStore(storeDir)
	retry := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, restarted)
	if _, err := retry.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err == nil {
		t.Fatal("ambiguous attempt was blindly retried")
	}
	if patchCalls.Load() != 1 {
		t.Fatalf("PATCH calls after retry = %d, want 1", patchCalls.Load())
	}
}

func TestExecutorDoesNotFollowRedirectToDifferentDestination(t *testing.T) {
	var redirectedCalls atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			redirectedCalls.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		if r.Method == http.MethodGet {
			w.Header().Set("ETag", testETag)
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"standard"}`)
			return
		}
		http.Redirect(w, r, other.URL+"/customers/c-17", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	fx := newExecutionFixture(t, source.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, source.URL, testDestinationID, testAccountID, source.Client(), &memoryJournal{}, attempts)
	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrMutationOutcomeUnknown) {
		t.Fatalf("redirect error = %v, want outcome unknown", err)
	}
	if redirectedCalls.Load() != 0 {
		t.Fatal("executor followed redirect to another destination")
	}
}

func TestExecutorRejectsWrongConfiguredAccountBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
	attempts, _ := NewFileAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	executor := newTestExecutor(t, fx, server.URL, testDestinationID, "other-account", server.Client(), &memoryJournal{}, attempts)
	if _, err := executor.Execute(context.Background(), fx.packet, fx.permit, fx.plan); err == nil || !strings.Contains(err.Error(), "account identity mismatch") {
		t.Fatalf("error = %v, want account mismatch", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("wrong account made %d network call(s)", calls.Load())
	}
}

func conditionalCRMServer(
	t *testing.T,
	patchCalls *atomic.Int32,
	initialVersion string,
	missingETag bool,
) *httptest.Server {
	t.Helper()
	var (
		mu      sync.Mutex
		etag    = initialVersion
		tier    = "standard"
	)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set(headerDestinationID, testDestinationID)
		w.Header().Set(headerAccountID, testAccountID)
		switch r.Method {
		case http.MethodGet:
			if !missingETag {
				w.Header().Set("ETag", etag)
			}
			_, _ = io.WriteString(w, `{"id":"c-17","tier":"`+tier+`"}`)
		case http.MethodPatch:
			if r.Header.Get("If-Match") != etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			patchCalls.Add(1)
			tier = "gold"
			etag = "rv-2"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}
