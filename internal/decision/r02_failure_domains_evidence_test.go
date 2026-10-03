package decision

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type r02EvidenceDecision struct {
	SchemaVersion string `json:"schema_version"`
	FailureDomains struct {
		Distinct bool `json:"distinct"`
	} `json:"failure_domains"`
	E2 struct {
		EffectID                string   `json:"effect_id"`
		WebhookEventIDs         []string `json:"webhook_event_ids"`
		WebhookValues           []string `json:"webhook_values"`
		APIValue                string   `json:"api_value"`
		UnrelatedEffectID       string   `json:"unrelated_effect_id"`
		AggregateCapturedAmount int64    `json:"aggregate_captured_amount"`
	} `json:"e2"`
	Amount int64 `json:"amount"`
	E3 struct {
		StaleStatus       int `json:"stale_status"`
		TargetDurableRows int `json:"target_durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

type r02Probe struct {
	name  string
	value string
	at    time.Time
}

func (p r02Probe) Name() string { return p.name }
func (p r02Probe) SafetyClass() ProbeSafetyClass { return ProbeReadOnly }
func (p r02Probe) Supports(Request, Result) bool { return true }
func (p r02Probe) Acquire(context.Context, Request) (ProbeOutcome, error) {
	return ProbeOutcome{Evidence: []EvidenceObservation{{
		Claim:      "payment_effect:effect:r02:e2",
		Source:     p.name,
		Value:      p.value,
		ObservedAt: p.at,
	}}}, nil
}

func TestR02IndependentDomainsStillFailClosedOnProviderContradiction(t *testing.T) {
	path := os.Getenv("GOSMIG_R02_EVIDENCE")
	if path == "" {
		t.Skip("R02 native evidence is produced by the PostgreSQL workflow")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev r02EvidenceDecision
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SchemaVersion != "governed-action.r02-failure-domains/v1" || !ev.FailureDomains.Distinct {
		t.Fatalf("failure-domain evidence missing: %+v", ev)
	}
	if len(ev.E2.WebhookValues) != 2 ||
		ev.E2.WebhookValues[0] != "CAPTURED" ||
		ev.E2.WebhookValues[1] != "CAPTURED" ||
		ev.E2.APIValue != "NOT_CAPTURED" ||
		ev.E2.AggregateCapturedAmount != ev.Amount ||
		ev.E2.UnrelatedEffectID == ev.E2.EffectID ||
		ev.E3.TargetDurableRows != 0 ||
		ev.ExactPostcondition {
		t.Fatalf("R02 falsification facts missing: %+v", ev)
	}

	now := time.Date(2026, 10, 3, 2, 30, 0, 0, time.UTC)
	req := Request{
		ActionID:            "action:r02:fulfill-order-731",
		Action:              "payment.capture",
		Target:              "provider-a/order-731",
		ResourceVersion:     "order-731:r02",
		RequestedAt:         now,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      30 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []EvidenceObservation{
			{Claim: "payment_effect:effect:r02:e2", Source: "provider-a-webhook", Value: "CAPTURED", ObservedAt: now},
			{Claim: "payment_effect:effect:r02:e2", Source: "provider-a-api", Value: "NOT_CAPTURED", ObservedAt: now},
		},
	}
	initial := Evaluate(req)
	if initial.Decision != Block || initial.Authorization != nil || !isContradicted(initial) {
		t.Fatalf("R02 contradictory provider evidence did not fail closed: %+v", initial)
	}

	reconciled := ReconcileContradiction(context.Background(), req, []EvidenceProbe{
		r02Probe{name: "provider-a-webhook-fresh", value: "CAPTURED", at: now.Add(time.Second)},
		r02Probe{name: "provider-a-api-fresh", value: "NOT_CAPTURED", at: now.Add(2 * time.Second)},
	}, 2)
	if reconciled.Final.Decision != Block || reconciled.Final.Authorization != nil || !isContradicted(reconciled.Final) {
		t.Fatalf("R02 fresh same-provider contradiction manufactured authority: %+v", reconciled.Final)
	}
}
