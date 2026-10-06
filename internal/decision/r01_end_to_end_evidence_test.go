package decision

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type r01E2EEvidence struct {
	SchemaVersion string `json:"schema_version"`
	ActionRef     string `json:"action_ref"`
	Amount        int64  `json:"amount"`
	E1 struct {
		EffectID       string `json:"effect_id"`
		InitiallyExact bool   `json:"initially_exact"`
		FinalState     string `json:"final_state"`
	} `json:"e1"`
	E2 struct {
		EffectID                string `json:"effect_id"`
		LostAckWorkerExit       int    `json:"lost_ack_worker_exit"`
		ProviderAcceptanceRows  int    `json:"provider_acceptance_rows"`
		WebhookDeliveries       int    `json:"webhook_deliveries"`
		WebhookValue            string `json:"webhook_value"`
		APIValue                string `json:"api_value"`
		UnrelatedEffectID       string `json:"unrelated_effect_id"`
		AggregateCapturedAmount int64  `json:"aggregate_captured_amount"`
	} `json:"e2"`
	Authority struct {
		OldExpired   bool   `json:"old_expired"`
		CurrentOwner string `json:"current_owner"`
		CurrentFence int64  `json:"current_fence"`
	} `json:"authority"`
	E3 struct {
		EffectID          string `json:"effect_id"`
		StaleAttemptExits []int  `json:"stale_attempt_exits"`
		DurableRows       int    `json:"durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

type r01E2EProbe struct {
	name  string
	value string
	at    time.Time
}

func (p r01E2EProbe) Name() string { return p.name }
func (p r01E2EProbe) SafetyClass() ProbeSafetyClass { return ProbeReadOnly }
func (p r01E2EProbe) Supports(Request, Result) bool { return true }
func (p r01E2EProbe) Acquire(context.Context, Request) (ProbeOutcome, error) {
	return ProbeOutcome{Evidence: []EvidenceObservation{{
		Claim: "payment_effect:effect:r01:e2",
		Source: p.name,
		Value: p.value,
		ObservedAt: p.at,
	}}}, nil
}

func TestR01EndToEndNativeEvidenceReconcilesWithoutFalseAuthority(t *testing.T) {
	path := os.Getenv("GOSMIG_R01_E2E_EVIDENCE")
	if path == "" {
		t.Skip("native R01 end-to-end evidence is produced by the PostgreSQL workflow")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev r01E2EEvidence
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SchemaVersion != "governed-action.r01-end-to-end/v1" {
		t.Fatalf("unexpected evidence schema %q", ev.SchemaVersion)
	}
	if ev.E2.AggregateCapturedAmount != ev.Amount || ev.E2.UnrelatedEffectID == ev.E2.EffectID {
		t.Fatalf("semantic ABA evidence missing: %+v", ev.E2)
	}
	if !ev.Authority.OldExpired || ev.E3.DurableRows != 0 || ev.ExactPostcondition {
		t.Fatalf("native schedule did not retain the required unsafe conditions: %+v", ev)
	}

	now := time.Date(2026, 10, 2, 20, 30, 0, 0, time.UTC)
	req := Request{
		ActionID:            ev.ActionRef,
		Action:              "payment.capture",
		Target:              "provider-a/order-731",
		ResourceVersion:     "order-731:r01-e2e",
		RequestedAt:         now,
		AuthorizationTTL:    5 * time.Second,
		MaxEvidenceAge:      30 * time.Second,
		RequiredSourceCount: 2,
		BlastRadius:         1,
		MaxBlastRadius:      2,
		Evidence: []EvidenceObservation{
			{Claim: "payment_effect:effect:r01:e2", Source: "provider-a-webhook", Value: ev.E2.WebhookValue, ObservedAt: now},
			{Claim: "payment_effect:effect:r01:e2", Source: "provider-a-api", Value: ev.E2.APIValue, ObservedAt: now},
		},
	}
	initial := Evaluate(req)
	if initial.Decision != Block || initial.Authorization != nil || !isContradicted(initial) {
		t.Fatalf("native contradictory lineage did not fail closed: %+v", initial)
	}

	reconciled := ReconcileContradiction(context.Background(), req, []EvidenceProbe{
		r01E2EProbe{name: "provider-a-webhook-fresh", value: ev.E2.WebhookValue, at: now.Add(time.Second)},
		r01E2EProbe{name: "provider-a-api-fresh", value: ev.E2.APIValue, at: now.Add(2 * time.Second)},
	}, 2)
	if reconciled.Final.Decision != Block || reconciled.Final.Authorization != nil || !isContradicted(reconciled.Final) {
		t.Fatalf("fresh contradictory provider evidence manufactured authority: %+v", reconciled.Final)
	}
}
