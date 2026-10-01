package eepcrm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

type d04CustodyStore struct {
	AttemptStore
	afterWrite func()
	failWrite error
}

func (s d04CustodyStore) Transition(ctx context.Context, id string, from, to AttemptState, status int, detail string, at time.Time) (AttemptRecord, error) {
	if to == AttemptPossibleEffect && s.failWrite != nil { return AttemptRecord{}, s.failWrite }
	record, err := s.AttemptStore.Transition(ctx, id, from, to, status, detail, at)
	if err == nil && to == AttemptPossibleEffect && s.afterWrite != nil { s.afterWrite() }
	return record, err
}

func TestD04CRMRechecksAuthorityAndPlanAroundDurableCustody(t *testing.T) {
	custodyUnavailable := errors.New("fixture custody transition unavailable")
	cases := []struct { name string; state AttemptState; cause error }{
		{"expiry-during-read", AttemptClaimed, ga.ErrExpired},
		{"expiry-during-custody", AttemptPossibleEffect, ga.ErrExpired},
		{"custody-write-fails", AttemptClaimed, custodyUnavailable},
		{"plan-changes-during-custody", AttemptPossibleEffect, ga.ErrBindingChanged},
		{"cancel-during-custody", AttemptPossibleEffect, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var patchCalls atomic.Int32
			var boundaryClock, expiry atomic.Int64
			native := conditionalCRMServer(t, &patchCalls, testETag, false)
			defer native.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.name == "expiry-during-read" && r.Method == http.MethodGet { boundaryClock.Store(expiry.Load()) }
				native.Config.Handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			fx := newExecutionFixture(t, server.URL, testDestinationID, testAccountID, testETag)
			attemptID := attemptIDForFixture(t, fx)
			boundaryClock.Store(fx.now.UnixNano())
			expiry.Store(fx.permit.Claims.ValidUntil.UnixNano())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dir := filepath.Join(t.TempDir(), "custody")
			store, err := NewFileAttemptStore(dir)
			if err != nil { t.Fatal(err) }
			wrapped := d04CustodyStore{AttemptStore: store}
			switch tc.name {
			case "expiry-during-custody": wrapped.afterWrite = func() { boundaryClock.Store(expiry.Load()) }
			case "custody-write-fails": wrapped.failWrite = custodyUnavailable
			case "plan-changes-during-custody": wrapped.afterWrite = func() { fx.plan.Patch["tier"] = "platinum" }
			case "cancel-during-custody": wrapped.afterWrite = cancel
			}
			executor := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, wrapped)
			executor.clock = func() time.Time { return time.Unix(0, boundaryClock.Load()).UTC() }
			if _, err := executor.Execute(ctx, fx.packet, fx.permit, fx.plan); !errors.Is(err, tc.cause) {
				t.Fatalf("error=%v; want %v", err, tc.cause)
			}
			if patchCalls.Load() != 0 { t.Fatalf("invalid boundary sent %d PATCH requests", patchCalls.Load()) }
			reopened, err := NewFileAttemptStore(dir)
			if err != nil { t.Fatal(err) }
			record, err := reopened.Load(context.Background(), attemptID)
			if err != nil || record.State != tc.state { t.Fatalf("retained record=%+v error=%v; want %s", record, err, tc.state) }
			fx.plan.Patch["tier"] = "gold"
			retry := newTestExecutor(t, fx, server.URL, testDestinationID, testAccountID, server.Client(), &memoryJournal{}, reopened)
			if _, err := retry.Execute(context.Background(), fx.packet, fx.permit, fx.plan); !errors.Is(err, ErrAttemptAlreadyClaimed) { t.Fatalf("replay error=%v", err) }
			if patchCalls.Load() != 0 { t.Fatal("restart manufactured a second PATCH") }
		})
	}
}
