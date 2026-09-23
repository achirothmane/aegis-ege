//go:build integration

package kubeadapter

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/outcome"
)

func TestKindPostflightOutcomeDetectsMatchThenExternalDivergence(t *testing.T) {
	env := newKindUnmanagedIntegrationEnv(t, "m5-postflight")
	policy := integrationExecutionPolicy()

	preparation, report := executeKindDrainWithFreshAuthorizationRetry(
		t,
		env.adapter,
		"act-kind-m5",
		env.nodeName,
		policy,
	)
	if report.Decision != decision.Allow {
		t.Fatalf("expected successful guarded execution, got %s reasons=%v", report.Decision, report.ReasonCodes)
	}
	if preparation.Authorization == nil || preparation.Plan == nil {
		t.Fatal("expected authorization and execution plan")
	}

	contributors := []outcome.Contributor{
		{Kind: outcome.ContributorSource, ID: "kubernetes-api"},
		{Kind: outcome.ContributorAssumption, ID: "A-DRAIN-SAFE"},
	}
	record, err := env.adapter.ObserveDrainOutcome(
		context.Background(),
		*preparation.Authorization,
		*preparation.Plan,
		contributors,
	)
	if err != nil {
		t.Fatalf("ObserveDrainOutcome returned error: %v", err)
	}
	if record.Verdict != outcome.Match {
		t.Fatalf("expected postflight MATCH after successful execution, got %+v", record)
	}
	if record.EvidenceDigest != preparation.Authorization.EvidenceDigest ||
		record.PlanDigest != preparation.Authorization.PlanDigest {
		t.Fatalf("postflight record lost authorization binding: %+v", record)
	}

	node, err := env.client.CoreV1().Nodes().Get(
		context.Background(),
		env.nodeName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get node before external drift injection: %v", err)
	}
	node.Spec.Unschedulable = false
	if _, err := env.client.CoreV1().Nodes().Update(
		context.Background(),
		node,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("inject external postflight drift: %v", err)
	}

	diverged, err := env.adapter.ObserveDrainOutcome(
		context.Background(),
		*preparation.Authorization,
		*preparation.Plan,
		contributors,
	)
	if err != nil {
		t.Fatalf("ObserveDrainOutcome after drift returned error: %v", err)
	}
	if diverged.Verdict != outcome.Diverged {
		t.Fatalf("expected external state drift to produce DIVERGED, got %+v", diverged)
	}

	ledger := outcome.NewLedger(outcome.AdvisoryPolicy{
		MinResolvedSamples: 1,
		MaxDivergenceRate:  0,
	})

	record.Attribution = outcome.AttributionContributors
	ledger.Record(record)

	// This mismatch was deliberately caused after successful execution, so it is
	// evidence of outcome drift but not evidence that the original contributors
	// were wrong. It must remain unattributed.
	diverged.Attribution = outcome.AttributionUnattributed
	ledger.Record(diverged)

	snapshot := ledger.Snapshot(contributors[0])
	if snapshot.Status != outcome.AdvisoryHealthy {
		t.Fatalf("unattributed external drift must not degrade source advisory, got %+v", snapshot)
	}
	if snapshot.Matches != 1 || snapshot.Divergences != 0 || snapshot.Unattributed != 1 {
		t.Fatalf("unexpected reliability calibration after external drift: %+v", snapshot)
	}
}
