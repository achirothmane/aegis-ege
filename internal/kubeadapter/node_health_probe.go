package kubeadapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

const liveNodeHealthProbeSource = "kubernetes-api-live-probe"

type NodeHealthProbe struct {
	reader Reader
	now    Clock
}

func NewNodeHealthProbe(reader Reader, now Clock) *NodeHealthProbe {
	if now == nil {
		now = time.Now
	}
	return &NodeHealthProbe{reader: reader, now: now}
}

func (p *NodeHealthProbe) Name() string {
	return "kubernetes-live-node-health"
}

func (p *NodeHealthProbe) SafetyClass() decision.ProbeSafetyClass {
	return decision.ProbeReadOnly
}

func (p *NodeHealthProbe) Supports(req decision.Request, result decision.Result) bool {
	if p == nil || p.reader == nil {
		return false
	}
	if !strings.HasPrefix(req.Target, "node/") {
		return false
	}
	for _, reason := range result.ReasonCodes {
		if result.Decision == decision.Escalate && reason == decision.InsufficientEvidence {
			return true
		}
		if result.Decision == decision.Block && reason == decision.EvidenceContradicted {
			return true
		}
	}
	return false
}

func (p *NodeHealthProbe) Acquire(
	ctx context.Context,
	req decision.Request,
) (decision.ProbeOutcome, error) {
	nodeName := strings.TrimPrefix(req.Target, "node/")
	if nodeName == "" || nodeName == req.Target {
		return decision.ProbeOutcome{}, fmt.Errorf("target %q is not a node target", req.Target)
	}

	node, err := p.reader.GetNode(ctx, nodeName)
	if err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("read live node %q: %w", nodeName, err)
	}

	return decision.ProbeOutcome{
		ResourceVersion: node.ResourceVersion,
		Evidence: []decision.EvidenceObservation{{
			Claim:      nodeHealthClaim,
			Source:     liveNodeHealthProbeSource,
			Value:      nodeHealth(node),
			ObservedAt: p.now().UTC(),
		}},
	}, nil
}
