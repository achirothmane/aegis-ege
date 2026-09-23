package kubeadapter

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/achirothmane/state-latch/internal/decision"
)

const (
	nodeHealthClaim  = "node_health"
	kubernetesSource = "kubernetes-api"
)

type Reader interface {
	GetNode(ctx context.Context, name string) (*corev1.Node, error)
	ListPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error)
	ListPodDisruptionBudgets(ctx context.Context) ([]PodDisruptionBudgetView, error)
}

type DryRunExecutor interface {
	DryRunCordonNode(ctx context.Context, nodeName, resourceVersion string) error
	DryRunEvictPod(ctx context.Context, pod PodStateRef) error
}

type Clock func() time.Time

type Adapter struct {
	reader            Reader
	executor          DryRunExecutor
	now               Clock
	mutationsEnabled  bool
}

type NodeDrainPolicy struct {
	MaxEvidenceAge      time.Duration
	RequiredSourceCount int
	MaxBlastRadius      int
	AuthorizationTTL          time.Duration
	EvictionObservationTimeout time.Duration

	IgnoreDaemonSets   bool
	ForceUnmanagedPods bool
	DeleteEmptyDirData bool
}

type NodeDrainSnapshot struct {
	NodeName        string
	NodeUID         string
	ResourceVersion string
	NodeHealth      string
	Unschedulable   bool
	ActivePods      int
	ObservedAt      time.Time
}

func New(reader Reader) *Adapter {
	return NewWithClock(reader, time.Now)
}

func NewWithClock(reader Reader, now Clock) *Adapter {
	return NewWithClockAndExecutor(reader, nil, now)
}

func NewWithExecutor(reader Reader, executor DryRunExecutor) *Adapter {
	return NewWithClockAndExecutor(reader, executor, time.Now)
}

func NewWithExperimentalMutations(reader Reader, executor DryRunExecutor) *Adapter {
	return NewWithClockAndExperimentalMutations(reader, executor, time.Now)
}

func NewWithClockAndExperimentalMutations(reader Reader, executor DryRunExecutor, now Clock) *Adapter {
	adapter := NewWithClockAndExecutor(reader, executor, now)
	adapter.mutationsEnabled = true
	return adapter
}

func NewWithClockAndExecutor(reader Reader, executor DryRunExecutor, now Clock) *Adapter {
	if now == nil {
		now = time.Now
	}
	return &Adapter{
		reader:   reader,
		executor: executor,
		now:      now,
	}
}

func (a *Adapter) InspectNodeDrain(ctx context.Context, nodeName string) (NodeDrainSnapshot, error) {
	snapshot, _, err := a.inspectNodeDrainState(ctx, nodeName)
	return snapshot, err
}

func (a *Adapter) inspectNodeDrainState(ctx context.Context, nodeName string) (NodeDrainSnapshot, []corev1.Pod, error) {
	if nodeName == "" {
		return NodeDrainSnapshot{}, nil, fmt.Errorf("node name is required")
	}

	node, err := a.reader.GetNode(ctx, nodeName)
	if err != nil {
		return NodeDrainSnapshot{}, nil, fmt.Errorf("get node %q: %w", nodeName, err)
	}

	pods, err := a.reader.ListPodsOnNode(ctx, nodeName)
	if err != nil {
		return NodeDrainSnapshot{}, nil, fmt.Errorf("list pods on node %q: %w", nodeName, err)
	}

	activePods := 0
	for _, pod := range pods {
		if isTerminalPod(pod) {
			continue
		}
		activePods++
	}

	return NodeDrainSnapshot{
		NodeName:        node.Name,
		NodeUID:         string(node.UID),
		ResourceVersion: node.ResourceVersion,
		NodeHealth:      nodeHealth(node),
		Unschedulable:   node.Spec.Unschedulable,
		ActivePods:      activePods,
		ObservedAt:      a.now().UTC(),
	}, pods, nil
}

func (a *Adapter) EvaluateNodeDrain(
	ctx context.Context,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
) (decision.Result, NodeDrainSnapshot, error) {
	snapshot, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return decision.Result{}, NodeDrainSnapshot{}, err
	}

	preflight := a.preflightNodeDrain(ctx, pods, policy)
	if preflight.Decision != decision.Allow {
		return decision.Result{
			Decision:    preflight.Decision,
			ReasonCodes: preflightDecisionReasons(preflight),
		}, snapshot, nil
	}

	result := evaluateNodeDrainKernel(actionID, snapshot, preflight, policy)
	return result, snapshot, nil
}

func evaluateNodeDrainKernel(
	actionID string,
	snapshot NodeDrainSnapshot,
	preflight DrainPreflightReport,
	policy NodeDrainPolicy,
) decision.Result {
	return decision.Evaluate(decision.Request{
		ActionID:            actionID,
		Action:              "drain",
		Target:              "node/" + snapshot.NodeName,
		ResourceVersion:     snapshot.ResourceVersion,
		RequestedAt:         snapshot.ObservedAt,
		AuthorizationTTL:    policy.AuthorizationTTL,
		MaxEvidenceAge:      policy.MaxEvidenceAge,
		RequiredSourceCount: policy.RequiredSourceCount,
		BlastRadius:         preflight.EvictablePods,
		MaxBlastRadius:      policy.MaxBlastRadius,
		Evidence: []decision.EvidenceObservation{
			{
				Claim:      nodeHealthClaim,
				Source:     kubernetesSource,
				Value:      snapshot.NodeHealth,
				ObservedAt: snapshot.ObservedAt,
			},
		},
	})
}

func preflightDecisionReasons(report DrainPreflightReport) []decision.ReasonCode {
	seen := make(map[DrainFindingCode]struct{})
	reasons := make([]decision.ReasonCode, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if finding.Severity == FindingInfo {
			continue
		}
		if _, ok := seen[finding.Code]; ok {
			continue
		}
		seen[finding.Code] = struct{}{}
		reasons = append(reasons, decision.ReasonCode(finding.Code))
	}
	return reasons
}

func nodeHealth(node *corev1.Node) string {
	for _, condition := range node.Status.Conditions {
		if condition.Type != corev1.NodeReady {
			continue
		}

		switch condition.Status {
		case corev1.ConditionTrue:
			return "healthy"
		case corev1.ConditionFalse:
			return "unhealthy"
		default:
			return "unknown"
		}
	}

	return "unknown"
}

func isTerminalPod(pod corev1.Pod) bool {
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return true
	default:
		return false
	}
}
