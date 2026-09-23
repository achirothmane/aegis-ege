//go:build integration

package kubeadapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/epistemic"
	"github.com/achirothmane/state-latch/internal/outcome"
	"github.com/achirothmane/state-latch/internal/prometheusprobe"
)

type liveMoatMetrics struct {
	Cases                         int
	BaselineUnsafeAllows          int
	StateLatchUnsafeAllows        int
	BaselineUnknownAllows         int
	StateLatchUnknownAllows       int
	SafeControlAllows             int
	PolicyBlocksBoth              int
	PostflightDivergences         int
	StateLatchDivergencesDetected int
	BaselineDivergencesDetected   int
}

func TestKindMoatFalsificationBenchmarkV2(t *testing.T) {
	ctx := context.Background()
	metrics := liveMoatMetrics{}

	t.Run("safe-request-time-control", func(t *testing.T) {
		metrics.Cases++
		env := newKindIntegrationEnv(t, "v2-safe")
		policy := integrationPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		preparation := prepareKindDrainWithFreshAuthorization(
			t,
			env.adapter,
			"v2-safe",
			env.nodeName,
			policy,
		)
		if baseline != decision.Allow || preparation.Decision != decision.Allow {
			t.Fatalf(
				"safe control must ALLOW in both systems: baseline=%s StateLatch=%s reasons=%v",
				baseline,
				preparation.Decision,
				preparation.ReasonCodes,
			)
		}
		metrics.SafeControlAllows++
	})

	t.Run("ordinary-pdb-policy-denial-control", func(t *testing.T) {
		metrics.Cases++
		env := newKindIntegrationEnv(t, "v2-pdb-block")
		policy := integrationPolicy()

		zero := intstr.FromInt(0)
		pdb, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Create(
			ctx,
			&policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deny-all-v2",
					Namespace: env.namespace,
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MaxUnavailable: &zero,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "state-latch-it"},
					},
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("create PDB: %v", err)
		}
		waitForPDBStatus(t, env.client, env.namespace, pdb.Name, func(current *policyv1.PodDisruptionBudget) bool {
			return current.Status.ObservedGeneration == current.Generation &&
				current.Status.DisruptionsAllowed == 0
		})

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		preparation, err := env.adapter.PrepareNodeDrainExecution(
			ctx,
			"v2-pdb-block",
			env.nodeName,
			policy,
		)
		if err != nil {
			t.Fatalf("PrepareNodeDrainExecution: %v", err)
		}
		if baseline != decision.Block || preparation.Decision != decision.Block {
			t.Fatalf(
				"ordinary policy denial must be caught by both systems: baseline=%s StateLatch=%s reasons=%v",
				baseline,
				preparation.Decision,
				preparation.ReasonCodes,
			)
		}
		metrics.PolicyBlocksBoth++
	})

	t.Run("pdb-becomes-restrictive-after-request-time-allow", func(t *testing.T) {
		metrics.Cases++
		env := newKindIntegrationEnv(t, "v2-pdb-drift")
		policy := integrationPolicy()

		one := intstr.FromInt(1)
		pdb, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Create(
			ctx,
			&policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mutable-budget-v2",
					Namespace: env.namespace,
				},
				Spec: policyv1.PodDisruptionBudgetSpec{
					MaxUnavailable: &one,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "state-latch-it"},
					},
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			t.Fatalf("create PDB: %v", err)
		}
		waitForPDBStatus(t, env.client, env.namespace, pdb.Name, func(current *policyv1.PodDisruptionBudget) bool {
			return current.Status.ObservedGeneration == current.Generation &&
				current.Status.DisruptionsAllowed >= 1
		})

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("baseline must initially ALLOW before PDB drift, got %s", baseline)
		}

		events := make(chan epistemic.ResourceEvent, 16)
		synced := make(chan struct{})
		watchCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		errCh := make(chan error, 1)
		watcher := &PDBInvalidationWatcher{
			Client:    env.client,
			Namespace: env.namespace,
			Name:      pdb.Name,
		}
		go func() {
			errCh <- watcher.Run(watchCtx, events, synced)
		}()
		select {
		case <-synced:
		case <-time.After(10 * time.Second):
			t.Fatal("PDB watcher did not sync")
		}

		current, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Get(
			ctx,
			pdb.Name,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatalf("get PDB after sync: %v", err)
		}

		tracker := epistemic.NewTracker()
		tracker.PutAssumption(epistemic.Assumption{
			ID:     "A-PDB-V2",
			Status: epistemic.AssumptionSupported,
			Dependencies: []epistemic.ResourceRef{{
				APIVersion:      "policy/v1",
				Kind:            "PodDisruptionBudget",
				Namespace:       current.Namespace,
				Name:            current.Name,
				UID:             string(current.UID),
				ResourceVersion: current.ResourceVersion,
			}},
			EvaluatedAt: time.Now().UTC(),
		})
		tracker.PutAssumption(epistemic.Assumption{
			ID:                     "A-DRAIN-V2",
			Status:                 epistemic.AssumptionSupported,
			AssumptionDependencies: []string{"A-PDB-V2"},
			EvaluatedAt:            time.Now().UTC(),
		})

		patch := []byte("{\"spec\":{\"maxUnavailable\":0}}")
		after, err := env.client.PolicyV1().PodDisruptionBudgets(env.namespace).Patch(
			ctx,
			pdb.Name,
			types.MergePatchType,
			patch,
			metav1.PatchOptions{},
		)
		if err != nil {
			t.Fatalf("make PDB restrictive: %v", err)
		}

		event := waitForResourceVersionEvent(t, events, after.ResourceVersion)
		tracker.Handle(event)
		drainAssumption, ok := tracker.GetAssumption("A-DRAIN-V2")
		if !ok || drainAssumption.Status != epistemic.AssumptionInvalidated {
			t.Fatalf("expected propagated drain invalidation, got %+v ok=%v", drainAssumption, ok)
		}

		metrics.BaselineUnsafeAllows++
		if drainAssumption.Status != epistemic.AssumptionInvalidated {
			metrics.StateLatchUnsafeAllows++
		}

		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("PDB watcher returned error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("PDB watcher did not stop")
		}
	})

	t.Run("independent-prometheus-contradicts-kubernetes", func(t *testing.T) {
		metrics.Cases++
		env, node, observedAt := prepareM2ReadyNode(t, "v2-conflict")
		policy := integrationPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("request-time Kubernetes baseline should ALLOW, got %s", baseline)
		}

		server := prometheusHealthServer(t, observedAt.Add(time.Second), "0")
		defer server.Close()

		req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
		probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
		resolved := decision.ResolveUnknown(ctx, req, []decision.EvidenceProbe{probe}, 1)
		if resolved.Final.Decision != decision.Block ||
			!hasReason(resolved.Final.ReasonCodes, decision.EvidenceContradicted) {
			t.Fatalf(
				"StateLatch must BLOCK independent contradiction, got %s reasons=%v",
				resolved.Final.Decision,
				resolved.Final.ReasonCodes,
			)
		}

		metrics.BaselineUnsafeAllows++
		if resolved.Final.Decision == decision.Allow {
			metrics.StateLatchUnsafeAllows++
		}
	})

	t.Run("independent-safe-probe-confirms-kubernetes", func(t *testing.T) {
		metrics.Cases++
		env, node, observedAt := prepareM2ReadyNode(t, "v2-confirm")
		policy := integrationPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("baseline safe control should ALLOW, got %s", baseline)
		}

		server := prometheusHealthServer(t, observedAt.Add(time.Second), "1")
		defer server.Close()

		req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
		probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
		resolved := decision.ResolveUnknown(ctx, req, []decision.EvidenceProbe{probe}, 1)
		if resolved.Final.Decision != decision.Allow {
			t.Fatalf(
				"agreeing independent evidence should preserve ALLOW, got %s reasons=%v",
				resolved.Final.Decision,
				resolved.Final.ReasonCodes,
			)
		}
		metrics.SafeControlAllows++
	})

	t.Run("required-independent-source-unavailable", func(t *testing.T) {
		metrics.Cases++
		env, node, observedAt := prepareM2ReadyNode(t, "v2-unknown")
		policy := integrationPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("request-time baseline should ALLOW on primary Kubernetes evidence, got %s", baseline)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		req := m2Request(env.nodeName, node.ResourceVersion, observedAt, "healthy")
		probe := prometheusprobe.NewBinaryNodeHealthProbe(server.URL, server.Client())
		resolved := decision.ResolveUnknown(ctx, req, []decision.EvidenceProbe{probe}, 1)
		if resolved.Final.Decision != decision.Escalate {
			t.Fatalf(
				"missing required independent evidence must ESCALATE, got %s reasons=%v",
				resolved.Final.Decision,
				resolved.Final.ReasonCodes,
			)
		}

		metrics.BaselineUnknownAllows++
		if resolved.Final.Decision == decision.Allow {
			metrics.StateLatchUnknownAllows++
		}
	})

	t.Run("pod-semantic-drift-after-request-time-allow", func(t *testing.T) {
		metrics.Cases++
		env := newKindIntegrationEnv(t, "v2-pod-drift")
		policy := integrationPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("request-time baseline must initially ALLOW, got %s", baseline)
		}

		preparation := prepareKindDrainWithFreshAuthorization(
			t,
			env.adapter,
			"v2-pod-drift",
			env.nodeName,
			policy,
		)
		if preparation.Decision != decision.Allow || preparation.Authorization == nil {
			t.Fatalf(
				"expected StateLatch initial ALLOW, got %s reasons=%v",
				preparation.Decision,
				preparation.ReasonCodes,
			)
		}

		_, err := env.client.CoreV1().Pods(env.namespace).Patch(
			ctx,
			env.podName,
			types.MergePatchType,
			[]byte("{\"metadata\":{\"labels\":{\"state-latch.dev/v2-drift\":\"changed\"}}}"),
			metav1.PatchOptions{},
		)
		if err != nil {
			t.Fatalf("inject semantic pod drift: %v", err)
		}

		revalidation, err := env.adapter.RevalidateNodeDrainAuthorization(
			ctx,
			*preparation.Authorization,
			env.nodeName,
			policy,
		)
		if err != nil {
			t.Fatalf("RevalidateNodeDrainAuthorization: %v", err)
		}
		if revalidation.Decision != decision.Escalate ||
			!hasReason(revalidation.ReasonCodes, decision.ExecutionPlanChanged) {
			t.Fatalf(
				"StateLatch must stop semantic plan drift, got %s reasons=%v",
				revalidation.Decision,
				revalidation.ReasonCodes,
			)
		}

		metrics.BaselineUnsafeAllows++
		if revalidation.Decision == decision.Allow {
			metrics.StateLatchUnsafeAllows++
		}
	})

	t.Run("postflight-external-drift", func(t *testing.T) {
		metrics.Cases++
		env := newKindUnmanagedIntegrationEnv(t, "v2-postflight")
		policy := integrationExecutionPolicy()

		baseline := liveBaselineRequestTimeDecision(ctx, env, policy)
		if baseline != decision.Allow {
			t.Fatalf("request-time baseline must ALLOW pre-execution, got %s", baseline)
		}

		preparation, report := executeKindDrainWithFreshAuthorizationRetry(
			t,
			env.adapter,
			"v2-postflight",
			env.nodeName,
			policy,
		)
		if report.Decision != decision.Allow ||
			preparation.Authorization == nil ||
			preparation.Plan == nil {
			t.Fatalf(
				"expected successful guarded execution, decision=%s reasons=%v",
				report.Decision,
				report.ReasonCodes,
			)
		}

		node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node after execution: %v", err)
		}
		node.Spec.Unschedulable = false
		if _, err := env.client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("inject postflight drift: %v", err)
		}

		record, err := env.adapter.ObserveDrainOutcome(
			ctx,
			*preparation.Authorization,
			*preparation.Plan,
			[]outcome.Contributor{
				{Kind: outcome.ContributorSource, ID: "kubernetes-api"},
			},
		)
		if err != nil {
			t.Fatalf("ObserveDrainOutcome: %v", err)
		}
		if record.Verdict != outcome.Diverged {
			t.Fatalf("expected StateLatch postflight divergence, got %+v", record)
		}

		metrics.PostflightDivergences++
		metrics.StateLatchDivergencesDetected++
	})

	if metrics.Cases != 8 {
		t.Fatalf("expected 8 live v2 cases, got %+v", metrics)
	}
	if metrics.BaselineUnsafeAllows != 3 {
		t.Fatalf("expected 3 live unsafe baseline allows, got %+v", metrics)
	}
	if metrics.StateLatchUnsafeAllows != 0 {
		t.Fatalf("StateLatch live unsafe allow detected: %+v", metrics)
	}
	if metrics.BaselineUnknownAllows != 1 || metrics.StateLatchUnknownAllows != 0 {
		t.Fatalf("unexpected live unknown handling: %+v", metrics)
	}
	if metrics.SafeControlAllows != 2 {
		t.Fatalf("expected two safe controls to remain usable, got %+v", metrics)
	}
	if metrics.PolicyBlocksBoth != 1 {
		t.Fatalf("baseline control no longer catches ordinary policy block: %+v", metrics)
	}
	if metrics.PostflightDivergences != 1 ||
		metrics.StateLatchDivergencesDetected != 1 ||
		metrics.BaselineDivergencesDetected != 0 {
		t.Fatalf("unexpected postflight detection metrics: %+v", metrics)
	}

	t.Logf(
		"MOAT_BENCH_V2 cases=%d baseline_unsafe_allows=%d statelatch_unsafe_allows=%d baseline_unknown_allows=%d statelatch_unknown_allows=%d safe_controls=%d policy_blocks_both=%d postflight_detected=%d/%d baseline_postflight_detected=%d/%d",
		metrics.Cases,
		metrics.BaselineUnsafeAllows,
		metrics.StateLatchUnsafeAllows,
		metrics.BaselineUnknownAllows,
		metrics.StateLatchUnknownAllows,
		metrics.SafeControlAllows,
		metrics.PolicyBlocksBoth,
		metrics.StateLatchDivergencesDetected,
		metrics.PostflightDivergences,
		metrics.BaselineDivergencesDetected,
		metrics.PostflightDivergences,
	)
}

func liveBaselineRequestTimeDecision(
	ctx context.Context,
	env kindIntegrationEnv,
	policy NodeDrainPolicy,
) decision.Decision {
	if _, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{}); err != nil {
		return decision.Escalate
	}
	report, err := env.adapter.PreflightNodeDrain(ctx, env.nodeName, policy)
	if err != nil {
		return decision.Escalate
	}
	return report.Decision
}

func waitForResourceVersionEvent(
	t *testing.T,
	events <-chan epistemic.ResourceEvent,
	resourceVersion string,
) epistemic.ResourceEvent {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Resource.ResourceVersion == resourceVersion {
				return event
			}
		case <-deadline:
			t.Fatalf("watch did not observe resourceVersion %q", resourceVersion)
		}
	}
}
