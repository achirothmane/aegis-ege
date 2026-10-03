// Package kernelshrink_test tests reductions against the executable runtime.
// These are unit experiments; native constitutional assurance remains in the
// PostgreSQL/Kubernetes corpora, not in this in-memory adapter.
package kernelshrink_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// No separate ActionRef, Authority, EffectIdentity, DecisionBasis object,
// ExecutionAttempt object, ClosureObligation object, history or claim type.
// This removes independent inputs, not the exact binding relations: admission
// is trusted by the adapter, and owner/attempt are retained in one custody tuple.
type effect struct {
	subject    r.Identity
	transition r.Transition
	admission  r.Attestation
}

func (e effect) request(c r.Custody) r.Request {
	return r.Request{Subject: e.subject, Executor: c.Owner, Current: e.transition.From,
		Transition: e.transition, Admission: e.admission, AttemptID: c.AttemptID}
}

func proposal(t *testing.T) (effect, r.Custody) {
	t.Helper()
	e := effect{subject: r.Identity{ID: "subject", Kind: "service"},
		transition: r.Transition{Operation: "apply", From: r.State{Target: "target", Revision: "1", Digest: "before"}, To: r.State{Target: "target", Revision: "2", Digest: "after"}},
		admission:  r.Attestation{ID: "admission", Issuer: r.Identity{ID: "policy", Kind: "issuer"}}}
	c := r.Custody{AttemptID: "attempt", Owner: r.Identity{ID: "executor", Kind: "worker"}, Target: e.transition.From.Target}
	var err error
	e.admission.BindingDigest, err = r.AdmissionBindingDigest(e.request(c))
	if err != nil {
		t.Fatal(err)
	}
	c.EffectID, err = r.EffectIdentity(e.request(c))
	if err != nil {
		t.Fatal(err)
	}
	return e, c
}

type adapter struct {
	effect  effect
	mode    string
	custody r.Custody
	fenced  r.FencedCustody
	calls   []string
	effects int
}

func (a *adapter) CurrentState(context.Context, string) (r.State, error) {
	a.calls = append(a.calls, "state")
	s := a.effect.transition.From
	if a.mode == "stale-state" {
		s.Revision = "changed"
	}
	return s, nil
}

func (a *adapter) VerifyAttestation(_ context.Context, att r.Attestation, binding string) error {
	a.calls = append(a.calls, "verify:"+att.ID)
	if att.BindingDigest != binding {
		return errors.New("adapter binding mismatch")
	}
	if att.Issuer.ID != "policy" && att.Issuer.ID != "observer" {
		return errors.New("untrusted issuer")
	}
	if a.mode == "revoked-admission" && att.ID == "admission" {
		return errors.New("authority revoked")
	}
	if a.mode == "invalid-observation" && att.ID == "observation" {
		return errors.New("observation signature invalid")
	}
	return nil
}

func (a *adapter) RetainCustody(_ context.Context, c r.Custody) error {
	a.calls = append(a.calls, "retain")
	if a.mode == "retention-failure" {
		return errors.New("durable retention failed")
	}
	if a.custody.EffectID != "" {
		return errors.New("duplicate reservation")
	}
	a.custody = c
	return nil
}

func (a *adapter) Execute(context.Context, r.Transition, r.Custody) (r.Acceptance, error) {
	a.calls = append(a.calls, "effect")
	a.effects++
	if a.mode == "lost-ack" || a.mode == "withheld-observation" {
		return r.Acceptance{}, errors.New("acknowledgement lost")
	}
	return r.Acceptance{Reference: "accepted"}, nil
}

func (a *adapter) Observe(_ context.Context, _ r.Transition, c r.Custody) (r.Observation, error) {
	a.calls = append(a.calls, "observe")
	if a.mode == "withheld-observation" {
		return r.Observation{}, errors.New("observation unavailable")
	}
	o := r.Observation{State: a.effect.transition.To,
		Attestation: r.Attestation{ID: "observation", Issuer: r.Identity{ID: "observer", Kind: "issuer"}}}
	if a.mode == "different-state" {
		o.State.Digest = "other"
	}
	o.Attestation.BindingDigest = r.ObservationBindingDigest(c.EffectID, o.State)
	switch a.mode {
	case "incomplete-state":
		o.State = r.State{}
	case "incomplete-attestation":
		o.Attestation.ID = ""
	case "foreign-effect":
		o.Attestation.BindingDigest = r.ObservationBindingDigest("foreign", o.State)
	case "untrusted-observer":
		o.Attestation.Issuer.ID = "producer"
	}
	return o, nil
}

func (a *adapter) LoadCustody(_ context.Context, effect, attempt string) (r.Custody, error) {
	a.calls = append(a.calls, "load")
	if a.custody.EffectID != effect || a.custody.AttemptID != attempt {
		return r.Custody{}, errors.New("custody unavailable")
	}
	return a.custody, nil
}

func (a *adapter) ReserveFencedCustody(_ context.Context, c r.FencedCustody) error {
	a.calls = append(a.calls, "reserve-fenced")
	if a.mode == "retention-failure" {
		return errors.New("durable retention failed")
	}
	a.fenced = c
	return nil
}

func (a *adapter) LoadFencedCustody(context.Context, string, string) (r.FencedCustody, error) {
	a.calls = append(a.calls, "load-fenced")
	return a.fenced, nil
}

func (a *adapter) TransitionFencedCustodyCAS(_ context.Context, before, after r.FencedCustody) error {
	a.calls = append(a.calls, "cas:"+string(before.Phase)+"->"+string(after.Phase))
	if !a.fenced.Equal(before) {
		return errors.New("fenced custody conflict")
	}
	a.fenced = after
	return nil
}

func (a *adapter) ExecuteFenced(ctx context.Context, tr r.Transition, c r.FencedCustody) (r.Acceptance, error) {
	if !a.fenced.Equal(c) || c.Phase != r.CustodyCrossing {
		return r.Acceptance{}, errors.New("destination fence denied")
	}
	return a.Execute(ctx, tr, r.Custody{EffectID: c.EffectID, AttemptID: c.AttemptID, Target: c.Target, Owner: c.Owner})
}

func (a *adapter) ObserveFenced(ctx context.Context, tr r.Transition, c r.FencedCustody) (r.Observation, error) {
	return a.Observe(ctx, tr, r.Custody{EffectID: c.EffectID, AttemptID: c.AttemptID, Target: c.Target, Owner: c.Owner})
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// This trace includes outputs AND externally visible adapter call order. The
// script runs exactly these experiments against pinned #236 and the reduction.
func trace(t *testing.T, name string, result r.Result, a *adapter) {
	t.Helper()
	row := struct {
		Name             string
		Disposition      r.Disposition
		EffectID         string
		AttemptID        string
		CustodyRecorded  bool
		BoundaryEntered  bool
		Acceptance       r.Acceptance
		Observation      r.Observation
		Cause            string
		EffectError      string
		ObservationError string
		Effects          int
		Calls            []string
		Fenced           r.FencedCustody
	}{name, result.Disposition, result.EffectID, result.AttemptID, result.CustodyRecorded, result.BoundaryEntered, result.Acceptance, result.Observation, errorText(result.Cause), errorText(result.EffectError), errorText(result.ObservationError), a.effects, a.calls, a.fenced}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("KERNEL_SHRINK_TRACE %s\n", raw)
}

func TestKernelShrinkReducedInputAndObservationEquivalence(t *testing.T) {
	for _, mode := range []string{"closed", "lost-ack", "withheld-observation", "incomplete-state", "incomplete-attestation", "foreign-effect", "invalid-observation", "untrusted-observer", "different-state", "stale-state", "revoked-admission", "retention-failure"} {
		for _, path := range []string{"run", "fenced", "recover"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				e, c := proposal(t)
				a := &adapter{effect: e, mode: mode}
				var result r.Result
				switch path {
				case "run":
					result = r.Run(context.Background(), e.request(c), a)
				case "fenced":
					result = r.RunFenced(context.Background(), e.request(c), a).Result
				case "recover":
					// Serialize retained custody and reconstruct in a fresh adapter.
					// The native anchor separately proves actual process crashes.
					raw, err := json.Marshal(c)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(raw, &a.custody); err != nil {
						t.Fatal(err)
					}
					observer := r.Identity{ID: "observer", Kind: "issuer"}
					authorization := r.Attestation{ID: "recovery", Issuer: observer, BindingDigest: r.RecoveryBindingDigest(a.custody, observer)}
					result = r.Recover(context.Background(), r.RecoveryRequest{Original: e.request(a.custody), Recoverer: observer, RecoveryAuthorization: authorization}, a)
					if a.effects != 0 || result.BoundaryEntered {
						t.Fatal("observation-only recovery dispatched an effect")
					}
				}
				want := r.DispositionUnknown
				if mode == "closed" || mode == "lost-ack" || path == "recover" && (mode == "stale-state" || mode == "revoked-admission" || mode == "retention-failure") {
					want = r.DispositionClosed
				} else if path != "recover" && (mode == "stale-state" || mode == "revoked-admission" || mode == "retention-failure") {
					want = r.DispositionRejected
				}
				if result.Disposition != want {
					t.Fatalf("reduced input changed closure: want=%s got=%+v", want, result)
				}
				if a.effects > 1 {
					t.Fatal("runtime repeated an effect")
				}
				trace(t, path+"/"+mode, result, a)
			})
		}
	}
}

func TestKernelShrinkBindingProjectionEquivalence(t *testing.T) {
	e, c := proposal(t)
	base := e.request(c)
	values := []string{"", " ", "\t\n", "value", "\x00", "a\x00b", "é", "e\u0301", "字段", "a|b", "\xff", "\xfe", " leading ", "very-long-value"}
	for field := 0; field < 10; field++ {
		for i, value := range values {
			q := base
			switch field {
			case 0:
				q.Subject.ID = value
			case 1:
				q.Subject.Kind = value
			case 2:
				q.Current.Target, q.Transition.From.Target, q.Transition.To.Target = value, value, value
			case 3:
				q.Current.Revision, q.Transition.From.Revision = value, value
			case 4:
				q.Current.Digest, q.Transition.From.Digest = value, value
			case 5:
				q.Transition.Operation = value
			case 6:
				q.Transition.To.Revision = value
			case 7:
				q.Transition.To.Digest = value
			case 8:
				q.Transition.From.Target = value
			case 9:
				q.Transition.To.Target = value
			}
			id, idErr := r.EffectIdentity(q)
			admission, admissionErr := r.AdmissionBindingDigest(q)
			if idErr == nil && admissionErr == nil && id == admission {
				t.Fatal("effect and authority domains collapsed")
			}
			raw, err := json.Marshal([]string{fmt.Sprintf("binding/%d/%d", field, i), id, errorText(idErr), admission, errorText(admissionErr)})
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("KERNEL_SHRINK_TRACE %s\n", raw)
		}
	}
}

func TestKernelShrinkEffectIdentityDoesNotBecomeAttemptOrAuthority(t *testing.T) {
	e, c := proposal(t)
	q := e.request(c)
	q.Executor.ID, q.AttemptID, q.Admission.ID = "successor", "next-attempt", "new-authority-path"
	id, err := r.EffectIdentity(q)
	if err != nil || id != c.EffectID {
		t.Fatalf("attempt or authority minted a new logical effect: id=%s err=%v", id, err)
	}
	// Removing the attempt distinction entirely is also invalid: an exact
	// retained record for one attempt cannot authorize another attempt's recovery.
	a := &adapter{effect: e, custody: c}
	observer := r.Identity{ID: "observer", Kind: "issuer"}
	result := r.Recover(context.Background(), r.RecoveryRequest{Original: q, Recoverer: observer, RecoveryAuthorization: r.Attestation{ID: "recovery", Issuer: observer, BindingDigest: r.RecoveryBindingDigest(c, observer)}}, a)
	if result.Disposition != r.DispositionRejected || a.effects != 0 {
		t.Fatalf("foreign attempt inherited custody: %+v", result)
	}
}

func TestKernelShrinkCustodyCannotDisappearAfterLostAcknowledgement(t *testing.T) {
	e, c := proposal(t)
	first := &adapter{effect: e, mode: "withheld-observation"}
	result := r.Run(context.Background(), e.request(c), first)
	if result.Disposition != r.DispositionUnknown || first.effects != 1 {
		t.Fatalf("expected one unresolved external effect: %+v", result)
	}
	raw, err := json.Marshal(first.custody)
	if err != nil {
		t.Fatal(err)
	}
	fresh := &adapter{effect: e, mode: "withheld-observation"}
	if err := json.Unmarshal(raw, &fresh.custody); err != nil {
		t.Fatal(err)
	}
	retry := r.Run(context.Background(), e.request(c), fresh)
	if retry.Disposition != r.DispositionRejected || fresh.effects != 0 {
		t.Fatalf("lost acknowledgement permitted a second effect after custody removal: first=%+v retry=%+v effects=%d", result, retry, first.effects+fresh.effects)
	}
}
