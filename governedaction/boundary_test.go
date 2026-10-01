package governedaction_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

func TestExactBindingCannotBeReplacedOrOmitted(t *testing.T) {
	admitted := ga.Binding{ActionRevision: "sha256:plan-a", Target: "scope:account-a/customer-17", Profile: "crm/v1"}
	cases := []struct {
		name string
		current ga.Binding
		field ga.BindingField
		cause error
	}{
		{"exact", admitted, "", nil},
		{"revision", ga.Binding{"sha256:plan-b", admitted.Target, admitted.Profile}, ga.ActionRevisionField, ga.ErrBindingChanged},
		{"account", ga.Binding{admitted.ActionRevision, "scope:account-b/customer-17", admitted.Profile}, ga.TargetField, ga.ErrBindingChanged},
		{"profile", ga.Binding{admitted.ActionRevision, admitted.Target, "crm/v2"}, ga.ProfileField, ga.ErrBindingChanged},
		{"missing-revision", ga.Binding{"", admitted.Target, admitted.Profile}, ga.ActionRevisionField, ga.ErrMissingBinding},
		{"missing-target", ga.Binding{admitted.ActionRevision, "", admitted.Profile}, ga.TargetField, ga.ErrMissingBinding},
		{"missing-profile", ga.Binding{admitted.ActionRevision, admitted.Target, " "}, ga.ProfileField, ga.ErrMissingBinding},
		{"normalization-is-not-authority", ga.Binding{admitted.ActionRevision, " " + admitted.Target, admitted.Profile}, ga.TargetField, ga.ErrBindingChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ga.CheckBinding(admitted, tc.current)
			if tc.cause == nil {
				if err != nil { t.Fatal(err) }
				return
			}
			var bindingErr *ga.BindingError
			if !errors.Is(err, tc.cause) || !errors.As(err, &bindingErr) || bindingErr.Field != tc.field {
				t.Fatalf("error=%v; want field=%s cause=%v", err, tc.field, tc.cause)
			}
		})
	}
	if !errors.Is(ga.CheckBinding(ga.Binding{}, ga.Binding{}), ga.ErrMissingBinding) {
		t.Fatal("two absent references must not agree into authority")
	}
}

func TestFiniteBoundaryValidity(t *testing.T) {
	until := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct { name string; until, at time.Time; cause error }{
		{"before", until, until.Add(-time.Nanosecond), nil},
		{"at-expiry", until, until, ga.ErrExpired},
		{"after", until, until.Add(time.Nanosecond), ga.ErrExpired},
		{"unknown-clock", until, time.Time{}, ga.ErrUnknownTime},
		{"missing-expiry", time.Time{}, until, ga.ErrMissingExpiry},
		{"same-instant-other-zone", until, until.In(time.FixedZone("fixture", 3600)), ga.ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ga.CheckValidity(tc.until, tc.at); !errors.Is(err, tc.cause) {
				t.Fatalf("error=%v; want=%v", err, tc.cause)
			}
		})
	}
}

func TestNoEffectOnFailedAdmissionCustodyOrRevalidation(t *testing.T) {
	fault := errors.New("fixture dependency unavailable")
	cases := []struct {
		name string
		failCheck int
		failRetain, cancelAfterRetain bool
		wantRetained bool
		wantOrder []string
		cause error
	}{
		{"admission-unavailable", 1, false, false, false, []string{"check"}, fault},
		{"custody-unavailable", 0, true, false, false, []string{"check", "retain"}, fault},
		{"authority-changed-during-write", 2, false, false, true, []string{"check", "retain", "check"}, fault},
		{"canceled-after-custody", 0, false, true, true, []string{"check", "retain"}, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var order []string
			checks, effects := 0, 0
			result, err := ga.Dispatch(ctx,
				func(context.Context) error {
					order = append(order, "check"); checks++
					if checks == tc.failCheck { return fault }
					return nil
				},
				func(context.Context) error {
					order = append(order, "retain")
					if tc.failRetain { return fault }
					if tc.cancelAfterRetain { cancel() }
					return nil
				},
				func(context.Context) (int, error) { effects++; return 202, nil },
			)
			if !errors.Is(err, tc.cause) || result.BoundaryEntered || result.CustodyRecorded != tc.wantRetained || effects != 0 || !reflect.DeepEqual(order, tc.wantOrder) {
				t.Fatalf("result=%+v error=%v effects=%d order=%v", result, err, effects, order)
			}
		})
	}
}

func TestDispatchIsUsefulOnceAndNeverRetriesAnAmbiguousResult(t *testing.T) {
	for _, loseReply := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "lost-reply"}[loseReply], func(t *testing.T) {
			var order []string
			committedEffects := 0
			lostReply := errors.New("reply lost after destination commit")
			result, err := ga.Dispatch(context.Background(),
				func(context.Context) error { order = append(order, "check"); return nil },
				func(context.Context) error { order = append(order, "custody"); return nil },
				func(context.Context) (string, error) {
					order = append(order, "effect"); committedEffects++
					if loseReply { return "", lostReply }
					return "native-accepted", nil
				},
			)
			if !result.CustodyRecorded || !result.BoundaryEntered || committedEffects != 1 || !reflect.DeepEqual(order, []string{"check", "custody", "check", "effect"}) {
				t.Fatalf("result=%+v error=%v effects=%d order=%v", result, err, committedEffects, order)
			}
			if loseReply {
				if !errors.Is(err, lostReply) || result.Value != "" { t.Fatalf("ambiguous result=%+v error=%v", result, err) }
			} else if err != nil || result.Value != "native-accepted" { t.Fatalf("normal result=%+v error=%v", result, err) }
		})
	}
}

func TestMissingHooksFailBeforeAnyEffectOrCustody(t *testing.T) {
	for _, missing := range []string{"check", "custody", "effect"} {
		t.Run(missing, func(t *testing.T) {
			calls := 0
			check := func(context.Context) error { calls++; return nil }
			retain := func(context.Context) error { calls++; return nil }
			effect := func(context.Context) (int, error) { calls++; return 1, nil }
			var want error
			switch missing {
			case "check": check = nil; want = ga.ErrMissingCheck
			case "custody": retain = nil; want = ga.ErrMissingCustody
			case "effect": effect = nil; want = ga.ErrMissingEffect
			}
			result, err := ga.Dispatch(context.Background(), check, retain, effect)
			if !errors.Is(err, want) || calls != 0 || result.CustodyRecorded || result.BoundaryEntered { t.Fatalf("result=%+v error=%v calls=%d", result, err, calls) }
		})
	}
}
