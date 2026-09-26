package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/prometheusprobe"
)

const (
	egePrometheusNodeHealthEvidenceSource = "prometheus.node_health"
	egePrometheusNodeHealthEvidenceClass  = "prometheus.node-health"
)

type prometheusNodeHealthEvidenceContributor struct {
	probe       *prometheusprobe.BinaryNodeHealthProbe
	trustDomain string
	maxAge      time.Duration
	now         func() time.Time
}

func newPrometheusNodeHealthEvidenceContributor(
	baseURL string,
	trustDomain string,
	maxAge time.Duration,
	client *http.Client,
	now func() time.Time,
) (*prometheusNodeHealthEvidenceContributor, error) {
	baseURL = strings.TrimSpace(baseURL)
	trustDomain = strings.TrimSpace(trustDomain)
	if baseURL == "" {
		return nil, errors.New("Prometheus node-health URL is required")
	}
	if trustDomain == "" {
		return nil, errors.New("Prometheus evidence trust domain is required")
	}
	if trustDomain == egeNodeDrainTrustDomain {
		return nil, errors.New("Prometheus evidence trust domain must differ from the Kubernetes control-plane trust domain")
	}
	if maxAge <= 0 {
		return nil, errors.New("Prometheus evidence max age must be positive")
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	if now == nil {
		now = time.Now
	}

	probe := prometheusprobe.NewBinaryNodeHealthProbe(baseURL, client)
	probe.Source = egePrometheusNodeHealthEvidenceSource

	return &prometheusNodeHealthEvidenceContributor{
		probe:       probe,
		trustDomain: trustDomain,
		maxAge:      maxAge,
		now:         now,
	}, nil
}

func (*prometheusNodeHealthEvidenceContributor) Name() string {
	return egePrometheusNodeHealthEvidenceSource
}

func (c *prometheusNodeHealthEvidenceContributor) TrustDomain() string {
	return c.trustDomain
}

func (*prometheusNodeHealthEvidenceContributor) Kind() string {
	return egeNodeDrainKind
}

func (*prometheusNodeHealthEvidenceContributor) TargetType() string {
	return egeNodeTarget
}

func (c *prometheusNodeHealthEvidenceContributor) Contribute(
	ctx context.Context,
	_ string,
	target egeTargetDTO,
	primary egeEvidenceProduction,
) (egeEvidenceContribution, error) {
	if primary.Decision != decision.Allow || primary.PermitBinding == nil {
		return egeEvidenceContribution{}, errors.New("Prometheus contributor requires an ALLOW primary evidence production")
	}
	if primary.Snapshot == nil || strings.TrimSpace(primary.Snapshot.NodeHealth) == "" {
		return egeEvidenceContribution{}, errors.New("Prometheus contributor requires primary node-health state")
	}

	outcome, err := c.probe.Acquire(ctx, decision.Request{
		Target: "node/" + target.Name,
	})
	if err != nil {
		return egeEvidenceContribution{}, err
	}
	if len(outcome.Evidence) != 1 {
		return egeEvidenceContribution{}, errors.New("Prometheus node-health contributor requires exactly one observation")
	}

	observation := outcome.Evidence[0]
	now := c.now().UTC()
	if observation.ObservedAt.After(now.Add(5 * time.Second)) {
		return egeEvidenceContribution{
			Decision:    decision.Escalate,
			ReasonCodes: []decision.ReasonCode{decision.InsufficientEvidence},
		}, nil
	}
	if now.Sub(observation.ObservedAt) > c.maxAge {
		return egeEvidenceContribution{
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{decision.EvidenceStale},
		}, nil
	}
	if observation.Value != primary.Snapshot.NodeHealth {
		return egeEvidenceContribution{
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{decision.EvidenceContradicted},
		}, nil
	}

	return egeEvidenceContribution{
		Decision:        decision.Allow,
		ObservedAt:      observation.ObservedAt.UTC(),
		EvidenceDigest:  decision.DigestEvidence(outcome.Evidence),
		EvidenceClasses: []string{egePrometheusNodeHealthEvidenceClass},
	}, nil
}
