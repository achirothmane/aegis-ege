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
}

type Clock func() time.Time

type Adapter struct {
	reader Reader
	now    Clock
}

type NodeDrainPolicy struct {
	MaxEvidenceAge      time.Duration
	RequiredSourceCount int
	MaxBlastRadius      int
	AuthorizationTTL    time.Duration
}

type NodeDrainSnapshot struct {
	NodeName        string
	ResourceVersion string
	NodeHealth      string
	ActivePods      int
	ObservedAt      time.Time
}

func New(reader Reader) *Adapter {
	return NewWithClock(reader, time.Now)
}

func NewWithClock(reader Reader, now Clock) *Adapter {
	if now == nil {
		now = time.Now
	}
	return &Adapter{
		reader: reader,
		now:    now,
	}
}

func (a *Adapter) InspectNodeDrain(ctx context.Context, nodeName string) (NodeDrainSnapshot, error) {
	if nodeName == "" {
		return NodeDrainSnapshot{}, fmt.Errorf("node name is required")
	}

	node, err := a.reader.GetNode(ctx, nodeName)
	if err != nil {
		return NodeDrainSnapshot{}, fmt.Errorf("get node %q: %w", nodeName, err)
	}

	pods, err := a.reader.ListPodsOnNode(ctx, nodeName)
	if err != nil {
		return NodeDrainSnapshot{}, fmt.Errorf("list pods on node %q: %w", nodeName, err)
	}

	activePods := 0
	for _, pod := range pods {
		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			continue
		default:
			activePods++
		}
	}

	return NodeDrainSnapshot{
		NodeName:        node.Name,
		ResourceVersion: node.ResourceVersion,
		NodeHealth:      nodeHealth(node),
		ActivePods:      activePods,
		ObservedAt:      a.now().UTC(),
	}, nil
}

func (a *Adapter) EvaluateNodeDrain(
	ctx context.Context,
	actionID string,
	nodeName string,
	policy NodeDrainPolicy,
) (decision.Result, NodeDrainSnapshot, error) {
	snapshot, err := a.InspectNodeDrain(ctx, nodeName)
	if err != nil {
		return decision.Result{}, NodeDrainSnapshot{}, err
	}

	result := decision.Evaluate(decision.Request{
		ActionID:            actionID,
		Action:              "drain",
		Target:              "node/" + snapshot.NodeName,
		ResourceVersion:     snapshot.ResourceVersion,
		RequestedAt:         snapshot.ObservedAt,
		AuthorizationTTL:    policy.AuthorizationTTL,
		MaxEvidenceAge:      policy.MaxEvidenceAge,
		RequiredSourceCount: policy.RequiredSourceCount,
		BlastRadius:         snapshot.ActivePods,
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

	return result, snapshot, nil
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
