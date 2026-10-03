package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

var (
	policyIssuer      = gaRuntime.Identity{ID: "policy:reference", Kind: "policy"}
	observerIssuer    = gaRuntime.Identity{ID: "observer:reference", Kind: "observer"}
	defaultSubject    = gaRuntime.Identity{ID: "agent:worker", Kind: "agent"}
	defaultExecutor   = gaRuntime.Identity{ID: "process:executor-1", Kind: "process"}
	errUntrusted      = errors.New("attestation issuer is not trusted")
	errDuplicate      = errors.New("custody already retained for effect attempt")
	errProvider       = errors.New("provider returned transport error after boundary entry")
	errObserve        = errors.New("trusted observation unavailable")
)

type fakeAdapter struct {
	states []gaRuntime.State
	reads  int

	trusted map[string]bool
	retained map[string]gaRuntime.Custody

	retainCalls int
	effectCalls int
	observeCalls int

	acceptance gaRuntime.Acceptance
	effectErr error

	observationState gaRuntime.State
	observationErr error
	observationIssuer gaRuntime.Identity
	observationAttestationID string
}

func newAdapter(current, after gaRuntime.State) *fakeAdapter {
	return &fakeAdapter{
		states: []gaRuntime.State{current, current},
		trusted: map[string]bool{
			policyIssuer.ID:   true,
			observerIssuer.ID: true,
		},
		retained: make(map[string]gaRuntime.Custody),
		acceptance: gaRuntime.Acceptance{Reference: "provider:accepted"},
		observationState: after,
		observationIssuer: observerIssuer,
		observationAttestationID: "observation:exact",
	}
}

func (a *fakeAdapter) CurrentState(context.Context, string) (gaRuntime.State, error) {
	if len(a.states) == 0 {
		return gaRuntime.State{}, errors.New("no current state")
	}
	index := a.reads
	if index >= len(a.states) {
		index = len(a.states) - 1
	}
	a.reads++
	return a.states[index], nil
}

func (a *fakeAdapter) VerifyAttestation(_ context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return errors.New("binding digest mismatch")
	}
	if !a.trusted[att.Issuer.ID] {
		return errUntrusted
	}
	return nil
}

func (a *fakeAdapter) RetainCustody(_ context.Context, custody gaRuntime.Custody) error {
	a.retainCalls++
	key := custody.EffectID + "\x00" + custody.AttemptID
	if _, exists := a.retained[key]; exists {
		return errDuplicate
	}
	a.retained[key] = custody
	return nil
}

func (a *fakeAdapter) Execute(_ context.Context, _ gaRuntime.Transition, _ gaRuntime.Custody) (gaRuntime.Acceptance, error) {
	a.effectCalls++
	return a.acceptance, a.effectErr
}

func (a *fakeAdapter) Observe(_ context.Context, _ gaRuntime.Transition, custody gaRuntime.Custody) (gaRuntime.Observation, error) {
	a.observeCalls++
	if a.observationErr != nil {
		return gaRuntime.Observation{}, a.observationErr
	}
	issuer := a.observationIssuer
	if !issuer.Complete() {
		issuer = observerIssuer
	}
	attestationID := a.observationAttestationID
	if attestationID == "" {
		attestationID = "observation:exact"
	}
	return gaRuntime.Observation{
		State: a.observationState,
		Attestation: gaRuntime.Attestation{
			ID:            attestationID,
			Issuer:        issuer,
			BindingDigest: gaRuntime.ObservationBindingDigest(custody.EffectID, a.observationState),
		},
	}, nil
}

func requestFor(t *testing.T, target, revision, digest, operation, nextRevision, nextDigest string) gaRuntime.Request {
	t.Helper()
	current := gaRuntime.State{
		Target:   target,
		Revision: revision,
		Digest:   digest,
	}
	after := gaRuntime.State{
		Target:   target,
		Revision: nextRevision,
		Digest:   nextDigest,
	}
	req := gaRuntime.Request{
		Subject:    defaultSubject,
		Executor:   defaultExecutor,
		Current:    current,
		Transition: gaRuntime.Transition{Operation: operation, From: current, To: after},
		AttemptID:  "attempt:001",
	}
	binding, err := gaRuntime.AdmissionBindingDigest(req)
	if err != nil {
		t.Fatalf("admission binding: %v", err)
	}
	req.Admission = gaRuntime.Attestation{
		ID:            "admission:001",
		Issuer:        policyIssuer,
		BindingDigest: binding,
	}
	return req
}

func defaultRequest(t *testing.T) gaRuntime.Request {
	return requestFor(
		t,
		"github:achirothmane/aegis-ege#145",
		"head:abc123",
		"sha256:github-current",
		"github.pull_request.merge",
		"merged:def456",
		"sha256:github-after",
	)
}

func TestReferenceRuntimeClosesOnlyOnExactTrustedObservation(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("disposition = %s cause=%v", result.Disposition, result.Cause)
	}
	if !result.CustodyRecorded || !result.BoundaryEntered {
		t.Fatalf("boundary facts not retained: %+v", result)
	}
	if adapter.retainCalls != 1 || adapter.effectCalls != 1 || adapter.observeCalls != 1 {
		t.Fatalf("unexpected callback counts: retain=%d effect=%d observe=%d",
			adapter.retainCalls, adapter.effectCalls, adapter.observeCalls)
	}
	if result.EffectID == "" {
		t.Fatal("effect identity is empty")
	}
}

func TestSameRuntimeAcrossFourDomains(t *testing.T) {
	cases := []struct {
		name, target, currentRevision, currentDigest, operation, nextRevision, nextDigest string
	}{
		{
			name: "github",
			target: "github:repo#pr",
			currentRevision: "head:111",
			currentDigest: "sha256:gh-111",
			operation: "github.pull_request.merge",
			nextRevision: "merged:222",
			nextDigest: "sha256:gh-222",
		},
		{
			name: "kubernetes",
			target: "kubernetes:prod/deployment/payments",
			currentRevision: "resourceVersion:4102",
			currentDigest: "sha256:kube-4102",
			operation: "kubernetes.deployment.delete",
			nextRevision: "tombstone:4103",
			nextDigest: "sha256:kube-4103",
		},
		{
			name: "postgres",
			target: "postgres:billing.public",
			currentRevision: "schema:41",
			currentDigest: "sha256:pg-41",
			operation: "postgres.schema.migrate",
			nextRevision: "schema:42",
			nextDigest: "sha256:pg-42",
		},
		{
			name: "terraform",
			target: "terraform:aws_bedrockagentcore_memory_strategy/semantic",
			currentRevision: "tfstate:absent:plan-001",
			currentDigest: "sha256:tf-before",
			operation: "terraform.resource.create",
			nextRevision: "tfstate:present:strategy-001",
			nextDigest: "sha256:tf-after",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := requestFor(
				t,
				tc.target,
				tc.currentRevision,
				tc.currentDigest,
				tc.operation,
				tc.nextRevision,
				tc.nextDigest,
			)
			adapter := newAdapter(req.Current, req.Transition.To)
			result := gaRuntime.Run(context.Background(), req, adapter)
			if result.Disposition != gaRuntime.DispositionClosed {
				t.Fatalf("same runtime rejected %s: %+v", tc.name, result)
			}
		})
	}
}

func TestStaleStateRejectsBeforeCustodyAndEffect(t *testing.T) {
	req := defaultRequest(t)
	stale := req.Current
	stale.Revision = "head:other"
	stale.Digest = "sha256:other"
	adapter := newAdapter(stale, req.Transition.To)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionRejected || !errors.Is(result.Cause, gaRuntime.ErrStateChanged) {
		t.Fatalf("stale state not rejected: %+v", result)
	}
	if result.CustodyRecorded || result.BoundaryEntered || adapter.effectCalls != 0 || adapter.retainCalls != 0 {
		t.Fatalf("stale request crossed boundary: %+v", result)
	}
}

func TestStateChangeAfterCustodyRejectsBeforeEffectButKeepsCustody(t *testing.T) {
	req := defaultRequest(t)
	changed := req.Current
	changed.Revision = "head:advanced"
	changed.Digest = "sha256:advanced"
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.states = []gaRuntime.State{req.Current, changed}

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionRejected || !errors.Is(result.Cause, gaRuntime.ErrStateChanged) {
		t.Fatalf("post-custody drift not rejected: %+v", result)
	}
	if !result.CustodyRecorded || result.BoundaryEntered {
		t.Fatalf("custody/boundary facts incorrect: %+v", result)
	}
	if adapter.effectCalls != 0 {
		t.Fatalf("effect executed after post-custody revalidation failed: %d", adapter.effectCalls)
	}
}

func TestUntrustedAdmissionRejectsBeforeCustody(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	delete(adapter.trusted, policyIssuer.ID)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionRejected || !errors.Is(result.Cause, errUntrusted) {
		t.Fatalf("untrusted admission not rejected: %+v", result)
	}
	if adapter.retainCalls != 0 || adapter.effectCalls != 0 {
		t.Fatalf("untrusted admission reached effect path")
	}
}

func TestProviderSuccessWithoutExactObservationRemainsUnknown(t *testing.T) {
	req := defaultRequest(t)
	wrong := req.Transition.To
	wrong.Revision = "merged:other"
	wrong.Digest = "sha256:other-after"
	adapter := newAdapter(req.Current, wrong)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionUnknown ||
		!errors.Is(result.Cause, gaRuntime.ErrObservedStateMismatch) {
		t.Fatalf("provider success manufactured closure: %+v", result)
	}
	if !result.BoundaryEntered || result.Acceptance.Reference == "" {
		t.Fatalf("provider call facts missing: %+v", result)
	}
}

func TestProviderErrorCanStillCloseOnExactTrustedObservation(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.effectErr = errProvider

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("exact trusted observation did not close after provider error: %+v", result)
	}
	if !errors.Is(result.EffectError, errProvider) {
		t.Fatalf("provider error history was lost: %+v", result)
	}
}

func TestProviderErrorWithoutObservationRemainsUnknown(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.effectErr = errProvider
	adapter.observationErr = errObserve

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("missing observation did not remain UNKNOWN: %+v", result)
	}
	if !errors.Is(result.EffectError, errProvider) || !errors.Is(result.ObservationError, errObserve) {
		t.Fatalf("failure history not preserved: %+v", result)
	}
}

func TestDuplicateAttemptDoesNotProduceSecondEffect(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)

	first := gaRuntime.Run(context.Background(), req, adapter)
	if first.Disposition != gaRuntime.DispositionClosed {
		t.Fatalf("first attempt did not close: %+v", first)
	}

	second := gaRuntime.Run(context.Background(), req, adapter)
	if second.Disposition != gaRuntime.DispositionRejected || !errors.Is(second.Cause, errDuplicate) {
		t.Fatalf("duplicate custody was not rejected: %+v", second)
	}
	if second.BoundaryEntered {
		t.Fatalf("duplicate attempt entered effect boundary: %+v", second)
	}
	if adapter.effectCalls != 1 {
		t.Fatalf("duplicate attempt produced another effect: %d", adapter.effectCalls)
	}
}

func TestMaterialSubstitutionInvalidatesAdmission(t *testing.T) {
	req := defaultRequest(t)

	cases := map[string]func(*gaRuntime.Request){
		"subject": func(p *gaRuntime.Request) {
			p.Subject.ID = "agent:other"
		},
		"operation": func(p *gaRuntime.Request) {
			p.Transition.Operation = "github.repository.delete"
		},
		"state": func(p *gaRuntime.Request) {
			p.Current.Revision = "head:other"
			p.Current.Digest = "sha256:other"
			p.Transition.From = p.Current
		},
		"target": func(p *gaRuntime.Request) {
			p.Current.Target = "github:other/repo#145"
			p.Transition.From.Target = p.Current.Target
			p.Transition.To.Target = p.Current.Target
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := req
			mutate(&changed)
			adapter := newAdapter(changed.Current, changed.Transition.To)
			result := gaRuntime.Run(context.Background(), changed, adapter)
			if result.Disposition != gaRuntime.DispositionRejected ||
				!errors.Is(result.Cause, gaRuntime.ErrAdmissionBinding) {
				t.Fatalf("%s substitution retained old authority: %+v", name, result)
			}
			if adapter.effectCalls != 0 {
				t.Fatalf("%s substitution reached effect", name)
			}
		})
	}
}

func TestEffectIdentityIgnoresAuthorizationPathButBindsMaterialEffect(t *testing.T) {
	req := defaultRequest(t)
	baseline, err := gaRuntime.EffectIdentity(req)
	if err != nil {
		t.Fatal(err)
	}

	alternate := req
	alternate.Admission.ID = "admission:alternate"
	alternate.Admission.Issuer = gaRuntime.Identity{ID: "policy:alternate", Kind: "policy"}
	if got, err := gaRuntime.EffectIdentity(alternate); err != nil || got != baseline {
		t.Fatalf("authorization path changed logical effect identity: got=%q err=%v", got, err)
	}

	mutations := map[string]func(*gaRuntime.Request){
		"subject": func(p *gaRuntime.Request) {
			p.Subject.ID += ":other"
		},
		"operation": func(p *gaRuntime.Request) {
			p.Transition.Operation = "other.operation"
		},
		"state": func(p *gaRuntime.Request) {
			p.Current.Revision += ":next"
			p.Current.Digest = "sha256:next"
			p.Transition.From = p.Current
		},
		"target": func(p *gaRuntime.Request) {
			p.Current.Target += ":other"
			p.Transition.From.Target = p.Current.Target
			p.Transition.To.Target = p.Current.Target
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := req
			mutate(&changed)
			got, err := gaRuntime.EffectIdentity(changed)
			if err != nil {
				t.Fatalf("effect identity: %v", err)
			}
			if got == baseline {
				t.Fatalf("%s did not change logical effect identity", name)
			}
		})
	}
}

func TestUntrustedObservationCannotClose(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationIssuer = gaRuntime.Identity{ID: "observer:untrusted", Kind: "observer"}

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionUnknown || !errors.Is(result.Cause, errUntrusted) {
		t.Fatalf("untrusted observation closed effect: %+v", result)
	}
}

func TestRequestRequiresExactTransitionBinding(t *testing.T) {
	req := defaultRequest(t)
	req.Transition.From.Revision = "head:stale"
	adapter := newAdapter(req.Current, req.Transition.To)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Disposition != gaRuntime.DispositionRejected ||
		!errors.Is(result.Cause, gaRuntime.ErrTransitionBinding) {
		t.Fatalf("unbound transition not rejected: %+v", result)
	}
	if adapter.retainCalls != 0 || adapter.effectCalls != 0 {
		t.Fatal("unbound transition reached effect path")
	}
}

func TestObservationBindingCannotBeReusedForAnotherEffect(t *testing.T) {
	first := defaultRequest(t)
	second := requestFor(
		t,
		first.Current.Target,
		first.Current.Revision,
		first.Current.Digest,
		"github.pull_request.close",
		"closed:xyz",
		"sha256:closed",
	)
	firstID, err := gaRuntime.EffectIdentity(first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := gaRuntime.EffectIdentity(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("test requires distinct effects")
	}
	if gaRuntime.ObservationBindingDigest(firstID, first.Transition.To) ==
		gaRuntime.ObservationBindingDigest(secondID, first.Transition.To) {
		t.Fatal("observation binding was reusable across logical effects")
	}
}

func TestResultVocabularyDoesNotConflateProviderAcceptanceWithClosure(t *testing.T) {
	req := defaultRequest(t)
	adapter := newAdapter(req.Current, req.Transition.To)
	adapter.observationErr = fmt.Errorf("%w: provider history temporarily unavailable", errObserve)

	result := gaRuntime.Run(context.Background(), req, adapter)

	if result.Acceptance.Reference == "" {
		t.Fatal("test requires provider acceptance")
	}
	if result.Disposition != gaRuntime.DispositionUnknown {
		t.Fatalf("provider acceptance was treated as closure: %+v", result)
	}
}
