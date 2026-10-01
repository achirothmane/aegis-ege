//go:build integration

package kubeadapter

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

func TestKindSharedBoundaryExpiresDuringNativeCustody(t *testing.T) {
	for _, phase := range []string{"cordon", "eviction"} {
		t.Run(phase, func(t *testing.T) {
			env := newKindUnmanagedIntegrationEnv(t, "shared-expiry-"+phase)
			ctx := context.Background()
			now := time.Now().UTC()
			reader := NewClientGoReader(env.client)
			adapter := NewWithClockAndExperimentalMutations(reader, reader, func() time.Time { return now })
			policy := integrationExecutionPolicy()
			policy.ExecutionLockNamespace = env.namespace
			durable, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
			if err != nil {
				t.Fatal(err)
			}
			store := &boundaryHookStore{DrainCheckpointStore: durable}
			// Detect a pre-effect retention by an unchanged Cordoned value
			// across two acknowledged saves. This survives native pre-mutation
			// resourceVersion drift and preserves the original test oracle.
			previousCordoned := false
			consecutive := 0
			injected := false
			store.hook = func(_ int, c DrainExecutionCheckpoint) error {
				if c.Cordoned == previousCordoned {
					consecutive++
				} else {
					consecutive = 1
				}
				previousCordoned = c.Cordoned
				if !injected && c.Status == DrainExecutionRunning && consecutive >= 2 && c.Cordoned == (phase == "eviction") {
					now = now.Add(policy.AuthorizationTTL)
					injected = true
				}
				return nil
			}
			// Each fresh pre-mutation authorization has a distinct custody
			// identity. An existing ConfigMap must never be overwritten with a
			// new empty StoreVersion after native resourceVersion drift.
			var report GuardedDrainExecutionReport
			var actionID string
			for attempt := 0; attempt < 12; attempt++ {
				actionID = fmt.Sprintf("shared-native-expiry-%s-%d", phase, attempt)
				previousCordoned = false
				consecutive = 0
				prepared := prepareKindDrainWithFreshAuthorization(t, adapter, actionID, env.nodeName, policy)
				report, err = adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(ctx, *prepared.Authorization, env.nodeName, policy, store)
				if err != nil {
					t.Fatal(err)
				}
				applied := false
				for _, step := range report.Steps {
					applied = applied || step.Applied
				}
				if !injected && !applied && hasReason(report.ReasonCodes, decision.ResourceVersionChanged) {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				break
			}
			if !injected || report.Decision != decision.Escalate || !hasReason(report.ReasonCodes, decision.AuthorizationExpired) {
				t.Fatalf("native expiry injection not observed: injected=%v report=%+v", injected, report)
			}
			node, err := env.client.CoreV1().Nodes().Get(ctx, env.nodeName, metav1.GetOptions{})
			if err != nil || node.Spec.Unschedulable != (phase == "eviction") {
				t.Fatalf("unauthorized cordon or missing preceding cordon: node=%+v err=%v", node, err)
			}
			if _, err := env.client.CoreV1().Pods(env.namespace).Get(ctx, env.podName, metav1.GetOptions{}); err != nil {
				t.Fatalf("Pod was evicted after expiry: %v", err)
			}
			reopened, err := NewKubernetesDrainCheckpointStore(env.client, env.namespace)
			if err != nil {
				t.Fatal(err)
			}
			c, err := reopened.Load(ctx, actionID)
			if err != nil || len(c.CompletedPodUIDs) != 0 || len(c.AuthorizedPods) != 1 {
				t.Fatalf("native custody missing or false completion: %+v, %v", c, err)
			}
			t.Logf("native expiry evidence: phase=%s action=%s node_uid=%s original_plan=%s authorized_pod_uid=%s cordoned=%v completed=%v", phase, c.ActionID, c.NodeUID, c.OriginalPlanDigest, c.AuthorizedPods[0].UID, c.Cordoned, c.CompletedPodUIDs)
		})
	}
}
