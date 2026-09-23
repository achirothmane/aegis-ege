package kubeadapter

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achirothmane/state-latch/internal/decision"
)

func TestPreflightBlocksDaemonSetUnlessExplicitlyIgnored(t *testing.T) {
	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{daemonSetPod("metrics-agent")},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", report.Decision)
	}
	if !hasFinding(report.Findings, FindingDaemonSetRequiresIgnore) {
		t.Fatalf("expected %s, got %+v", FindingDaemonSetRequiresIgnore, report.Findings)
	}

	report, err = adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{IgnoreDaemonSets: true})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected ALLOW with ignore-daemonsets, got %s", report.Decision)
	}
	if report.SkippedDaemonSetPods != 1 || report.EvictablePods != 0 {
		t.Fatalf("expected one skipped daemonset and zero evictable pods, got skipped=%d evictable=%d", report.SkippedDaemonSetPods, report.EvictablePods)
	}
}

func TestPreflightBlocksUnmanagedPodUnlessForceEnabled(t *testing.T) {
	unmanaged := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{unmanaged},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Block || !hasFinding(report.Findings, FindingUnmanagedPodRequiresForce) {
		t.Fatalf("expected unmanaged-pod BLOCK, got decision=%s findings=%+v", report.Decision, report.Findings)
	}

	report, err = adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{ForceUnmanagedPods: true})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected ALLOW with force policy, got %s findings=%+v", report.Decision, report.Findings)
	}
}

func TestPreflightBlocksEmptyDirDataUnlessDeletionAccepted(t *testing.T) {
	p := managedPod("cache", corev1.PodRunning)
	p.Spec.Volumes = []corev1.Volume{
		{
			Name: "cache",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}
	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{p},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Block || !hasFinding(report.Findings, FindingEmptyDirRequiresDelete) {
		t.Fatalf("expected emptyDir BLOCK, got decision=%s findings=%+v", report.Decision, report.Findings)
	}

	report, err = adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{DeleteEmptyDirData: true})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected ALLOW when emptyDir deletion is accepted, got %s", report.Decision)
	}
}

func TestPreflightSkipsMirrorPods(t *testing.T) {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "kube-apiserver-node-7",
			Namespace:   "kube-system",
			Annotations: map[string]string{mirrorPodAnnotationKey: "mirror-hash"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{p},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected mirror pod to be skipped, got %s", report.Decision)
	}
	if report.SkippedMirrorPods != 1 || report.EvictablePods != 0 {
		t.Fatalf("expected mirror skipped=1 evictable=0, got skipped=%d evictable=%d", report.SkippedMirrorPods, report.EvictablePods)
	}
	if !hasFinding(report.Findings, FindingMirrorPodSkipped) {
		t.Fatalf("expected informational %s finding", FindingMirrorPodSkipped)
	}
}

func TestPreflightBlocksWhenPDBAllowsFewerDisruptionsThanTargetPods(t *testing.T) {
	p1 := managedPod("api-1", corev1.PodRunning)
	p1.Labels = map[string]string{"app": "api"}
	p2 := managedPod("api-2", corev1.PodRunning)
	p2.Labels = map[string]string{"app": "api"}

	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{p1, p2},
		pdbs: []PodDisruptionBudgetView{
			{
				Namespace:          "default",
				Name:               "api-budget",
				Generation:         4,
				ObservedGeneration: 4,
				DisruptionsAllowed: 1,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
			},
		},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Block {
		t.Fatalf("expected PDB BLOCK, got %s", report.Decision)
	}
	if !hasFinding(report.Findings, FindingPDBDisruptionBlocked) {
		t.Fatalf("expected %s, got %+v", FindingPDBDisruptionBlocked, report.Findings)
	}
}

func TestPreflightEscalatesWhenMatchingPDBStatusIsStale(t *testing.T) {
	p := managedPod("api-1", corev1.PodRunning)
	p.Labels = map[string]string{"app": "api"}

	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{p},
		pdbs: []PodDisruptionBudgetView{
			{
				Namespace:          "default",
				Name:               "api-budget",
				Generation:         5,
				ObservedGeneration: 4,
				DisruptionsAllowed: 1,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
			},
		},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE for stale PDB status, got %s", report.Decision)
	}
	if !hasFinding(report.Findings, FindingPDBStatusStale) {
		t.Fatalf("expected %s, got %+v", FindingPDBStatusStale, report.Findings)
	}
}

func TestPreflightEscalatesWhenPDBEvidenceCannotBeRead(t *testing.T) {
	reader := stubReader{
		node:   readyNode("node-7", "1", corev1.ConditionTrue),
		pods:   []corev1.Pod{managedPod("api-1", corev1.PodRunning)},
		pdbErr: errors.New("forbidden"),
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("expected evidence failure to become ESCALATE, got error: %v", err)
	}
	if report.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE, got %s", report.Decision)
	}
	if !hasFinding(report.Findings, FindingPDBEvidenceUnavailable) {
		t.Fatalf("expected %s, got %+v", FindingPDBEvidenceUnavailable, report.Findings)
	}
}

func TestPreflightAllowsManagedPodWhenPDBHasCapacity(t *testing.T) {
	p := managedPod("api-1", corev1.PodRunning)
	p.Labels = map[string]string{"app": "api"}

	reader := stubReader{
		node: readyNode("node-7", "1", corev1.ConditionTrue),
		pods: []corev1.Pod{p},
		pdbs: []PodDisruptionBudgetView{
			{
				Namespace:          "default",
				Name:               "api-budget",
				Generation:         2,
				ObservedGeneration: 2,
				DisruptionsAllowed: 1,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
			},
		},
	}
	adapter := New(reader)

	report, err := adapter.PreflightNodeDrain(context.Background(), "node-7", NodeDrainPolicy{})
	if err != nil {
		t.Fatalf("PreflightNodeDrain returned error: %v", err)
	}
	if report.Decision != decision.Allow {
		t.Fatalf("expected ALLOW, got %s findings=%+v", report.Decision, report.Findings)
	}
	if report.EvictablePods != 1 {
		t.Fatalf("expected one evictable pod, got %d", report.EvictablePods)
	}
}

func hasFinding(findings []DrainFinding, want DrainFindingCode) bool {
	for _, finding := range findings {
		if finding.Code == want {
			return true
		}
	}
	return false
}
