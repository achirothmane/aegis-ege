package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type compositionPrimaryProducer struct {
	name        string
	trustDomain string
	kind        string
	targetType  string
	production  egeEvidenceProduction
	err         error
}

func (p *compositionPrimaryProducer) Name() string        { return p.name }
func (p *compositionPrimaryProducer) TrustDomain() string { return p.trustDomain }
func (p *compositionPrimaryProducer) Kind() string        { return p.kind }
func (p *compositionPrimaryProducer) TargetType() string  { return p.targetType }
func (p *compositionPrimaryProducer) Produce(
	context.Context,
	string,
	egeTargetDTO,
) (egeEvidenceProduction, error) {
	return p.production, p.err
}

type compositionContributor struct {
	name         string
	trustDomain  string
	kind         string
	targetType   string
	contribution egeEvidenceContribution
	err          error
}

func (c *compositionContributor) Name() string        { return c.name }
func (c *compositionContributor) TrustDomain() string { return c.trustDomain }
func (c *compositionContributor) Kind() string        { return c.kind }
func (c *compositionContributor) TargetType() string  { return c.targetType }
func (c *compositionContributor) Contribute(
	context.Context,
	string,
	egeTargetDTO,
	egeEvidenceProduction,
) (egeEvidenceContribution, error) {
	return c.contribution, c.err
}

func compositionAllowProduction(observedAt time.Time) egeEvidenceProduction {
	return egeEvidenceProduction{
		Decision:        decision.Allow,
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"state"},
		PermitBinding: &egePermitBinding{
			Action:          "drain",
			ResourceVersion: "100",
			EvidenceDigest:  "sha256:primary",
			PlanDigest:      "sha256:plan",
			ValidUntil:      observedAt.Add(time.Minute),
		},
	}
}

func TestEGEEvidenceComposerAllowsWhenIndependentSourcePolicyIsSatisfied(t *testing.T) {
	observedAt := time.Date(2026, 9, 26, 20, 0, 0, 0, time.UTC)
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "control-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	second := &compositionContributor{
		name:        "telemetry",
		trustDomain: "telemetry-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:        decision.Allow,
			ObservedAt:      observedAt.Add(-time.Second),
			EvidenceDigest:  "sha256:telemetry",
			EvidenceClasses: []string{"telemetry"},
		},
	}
	third := &compositionContributor{
		name:        "simulation",
		trustDomain: "simulation-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:        decision.Allow,
			ObservedAt:      observedAt.Add(-2 * time.Second),
			EvidenceDigest:  "sha256:simulation",
			EvidenceClasses: []string{"simulation"},
		},
	}

	producers, err := newEGEEvidenceProducerRegistry(primary)
	if err != nil {
		t.Fatal(err)
	}
	contributors, err := newEGEEvidenceContributorRegistry(second, third)
	if err != nil {
		t.Fatal(err)
	}
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": {
				MinSources:      3,
				MinTrustDomains: 3,
				RequiredSources: []string{"primary", "telemetry", "simulation"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := composer.Compose(
		context.Background(),
		"intent-1",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Allow || result.PermitBinding == nil {
		t.Fatalf("expected composed ALLOW, got %+v", result)
	}
	if len(result.EvidenceSources) != 3 {
		t.Fatalf("expected three evidence sources, got %d", len(result.EvidenceSources))
	}
	if !result.ObservedAt.Equal(observedAt.Add(-2 * time.Second)) {
		t.Fatalf("expected oldest composed observation, got %s", result.ObservedAt)
	}
	if len(result.EvidenceClasses) != 3 {
		t.Fatalf("expected union of evidence classes, got %v", result.EvidenceClasses)
	}
}

func TestEGEEvidenceComposerEscalatesWhenTrustDomainsAreNotIndependent(t *testing.T) {
	observedAt := time.Now().UTC()
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "shared-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	second := &compositionContributor{
		name:        "secondary",
		trustDomain: "shared-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:        decision.Allow,
			ObservedAt:      observedAt,
			EvidenceDigest:  "sha256:secondary",
			EvidenceClasses: []string{"telemetry"},
		},
	}

	producers, _ := newEGEEvidenceProducerRegistry(primary)
	contributors, _ := newEGEEvidenceContributorRegistry(second)
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": {MinSources: 2, MinTrustDomains: 2},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := composer.Compose(
		context.Background(),
		"intent-2",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-2"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE, got %s", result.Decision)
	}
	if result.PermitBinding != nil {
		t.Fatal("insufficient trust-domain independence must not preserve permit binding")
	}
	if len(result.ReasonCodes) != 1 || result.ReasonCodes[0] != decision.InsufficientEvidence {
		t.Fatalf("unexpected reasons: %v", result.ReasonCodes)
	}
}

func TestEGEEvidenceComposerBlocksWhenContributorContradicts(t *testing.T) {
	observedAt := time.Now().UTC()
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "control-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	second := &compositionContributor{
		name:        "telemetry",
		trustDomain: "telemetry-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{decision.EvidenceContradicted},
		},
	}

	producers, _ := newEGEEvidenceProducerRegistry(primary)
	contributors, _ := newEGEEvidenceContributorRegistry(second)
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": {MinSources: 2, MinTrustDomains: 2},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := composer.Compose(
		context.Background(),
		"intent-3",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-3"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Block {
		t.Fatalf("expected BLOCK, got %s", result.Decision)
	}
	if result.PermitBinding != nil {
		t.Fatal("contradicted composition must not preserve permit binding")
	}
	if len(result.ReasonCodes) != 1 || result.ReasonCodes[0] != decision.EvidenceContradicted {
		t.Fatalf("unexpected reasons: %v", result.ReasonCodes)
	}
}

func TestEGEEvidenceComposerEscalatesWhenRequiredSourceIsMissing(t *testing.T) {
	observedAt := time.Now().UTC()
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "control-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}

	producers, _ := newEGEEvidenceProducerRegistry(primary)
	contributors, _ := newEGEEvidenceContributorRegistry()
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": {
				MinSources:      1,
				MinTrustDomains: 1,
				RequiredSources: []string{"primary", "required-independent-source"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := composer.Compose(
		context.Background(),
		"intent-4",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-4"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Escalate {
		t.Fatalf("expected ESCALATE, got %s", result.Decision)
	}
	if result.PermitBinding != nil {
		t.Fatal("missing required source must not preserve permit binding")
	}
}

func TestEGEEvidenceComposerEscalatesWhenContributorFails(t *testing.T) {
	observedAt := time.Now().UTC()
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "control-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	second := &compositionContributor{
		name:        "telemetry",
		trustDomain: "telemetry-plane",
		kind:        "test.mutate",
		targetType:  "test.resource",
		err:         errors.New("telemetry unavailable"),
	}

	producers, _ := newEGEEvidenceProducerRegistry(primary)
	contributors, _ := newEGEEvidenceContributorRegistry(second)
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": {MinSources: 2, MinTrustDomains: 2},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := composer.Compose(
		context.Background(),
		"intent-5",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-5"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Escalate || result.PermitBinding != nil {
		t.Fatalf("failed contributor must fail closed: %+v", result)
	}
}
