package decision

import (
	"context"
	"slices"
	"testing"
	"time"
)

// R01-02 composition proof: a later effect cannot reuse an authorization after
// its validity horizon. This exercises the production authorization validator.
func TestR01CompositionRevokedOrExpiredAuthorityCannotAuthorizeLaterEffect(t *testing.T) {
	now := time.Date(2026, 10, 2, 20, 0, 0, 0, time.UTC)
	auth := Authorization{
		ActionID: "action:r01:fulfill-order-731",
		Action: "shipment.create",
		Target: "provider-b/order-731",
		ResourceVersion: "order-731:v1",
		PlanDigest: "sha256:r01-plan",
		ValidUntil: now,
	}
	attempt := ExecutionAttempt{
		ActionID: auth.ActionID,
		Action: auth.Action,
		Target: auth.Target,
		ResourceVersion: auth.ResourceVersion,
		PlanDigest: auth.PlanDigest,
		Now: now.Add(time.Nanosecond),
	}
	got := ValidateAuthorization(auth, attempt)
	if got.Valid || !slices.Contains(got.ReasonCodes, AuthorizationExpired) {
		t.Fatalf("expired authority authorized later effect: %+v", got)
	}
}

// R01-04 composition proof: callback arrival is merely a later execution
// attempt. Reusing the old permit after expiry cannot authorize a second
// callback-driven effect.
func TestR01CompositionDuplicateCallbackCannotMintAuthority(t *testing.T) {
	now := time.Date(2026, 10, 2, 20, 1, 0, 0, time.UTC)
	auth := Authorization{
		ActionID: "action:r01:fulfill-order-731",
		Action: "shipment.create",
		Target: "provider-b/order-731",
		ResourceVersion: "order-731:v1",
		PlanDigest: "sha256:r01-e3",
		ValidUntil: now.Add(time.Second),
	}
	first := ExecutionAttempt{ActionID: auth.ActionID, Action: auth.Action, Target: auth.Target, ResourceVersion: auth.ResourceVersion, PlanDigest: auth.PlanDigest, Now: now}
	if got := ValidateAuthorization(auth, first); !got.Valid {
		t.Fatalf("control callback should be valid inside authority horizon: %+v", got)
	}
	duplicate := first
	duplicate.Now = auth.ValidUntil.Add(time.Nanosecond)
	if got := ValidateAuthorization(auth, duplicate); got.Valid || !slices.Contains(got.ReasonCodes, AuthorizationExpired) {
		t.Fatalf("duplicate callback silently reused authority: %+v", got)
	}
}

// R01-07 composition proof: contradictory provider observations must not mint
// authorization. This exercises production reconciliation rather than R01's
// experiment adapter.
func TestR01CompositionContradictoryProviderObservationsDoNotMintAuthority(t *testing.T) {
	now := time.Date(2026, 10, 2, 20, 2, 0, 0, time.UTC)
	req := Request{
		ActionID: "action:r01:fulfill-order-731",
		Action: "payment.capture",
		Target: "provider-a/order-731",
		ResourceVersion: "order-731:v1",
		RequestedAt: now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge: 10 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius: 1,
		MaxBlastRadius: 2,
		Evidence: []EvidenceObservation{
			{Claim: "payment_state", Source: "provider-a-api", Value: "captured", ObservedAt: now},
			{Claim: "payment_state", Source: "provider-a-ledger", Value: "not_captured", ObservedAt: now},
		},
	}
	initial := Evaluate(req)
	if initial.Decision != Block || !slices.Contains(initial.ReasonCodes, EvidenceContradicted) || initial.Authorization != nil {
		t.Fatalf("initial contradiction was not fail-closed: %+v", initial)
	}
	got := ReconcileContradiction(context.Background(), req, nil, 0)
	if got.Final.Decision != Block || got.Final.Authorization != nil {
		t.Fatalf("contradiction manufactured authority during reconciliation: %+v", got.Final)
	}
}
