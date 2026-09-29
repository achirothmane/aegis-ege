package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
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


func declaredCompositionPolicy(
	required egeproto.EvidenceIndependenceStatus,
	assurance egeproto.EvidenceDeclarationAssurance,
) egeEvidenceCompositionPolicy {
	refPrimary := []string(nil)
	refTelemetry := []string(nil)
	if assurance == egeproto.EvidenceDeclarationCorroborated {
		refPrimary = []string{"inventory://kubernetes-primary/v1"}
		refTelemetry = []string{"inventory://telemetry-primary/v1"}
	}
	return egeEvidenceCompositionPolicy{
		MinSources:              2,
		MinTrustDomains:         2,
		RequiredSources:         []string{"primary", "telemetry"},
		MinIndependentSources:   2,
		RequiredIndependence:    required,
		RequiredDependencyKinds: []string{"administrative", "credential", "upstream"},
		SourceDeclarations: map[string]EvidenceSourceDeclarationConfig{
			"primary": {
				ProducerID:         "producer:kubernetes-primary",
				ObservationPath:    "path:kubernetes-api-live",
				DependencyCoverage: []string{"administrative", "credential", "platform", "upstream"},
				Dependencies: []egeproto.EvidenceDependency{
					{Kind: "administrative", ID: "admin:kubernetes", Material: true},
					{Kind: "credential", ID: "credential:kubernetes-reader", Material: true},
					{Kind: "platform", ID: "facility:shared", Material: false},
					{Kind: "upstream", ID: "upstream:kubernetes-api", Material: true},
				},
				Assurance:         assurance,
				CorroborationRefs: refPrimary,
			},
			"telemetry": {
				ProducerID:         "producer:telemetry",
				ObservationPath:    "path:prometheus-query",
				DependencyCoverage: []string{"administrative", "credential", "platform", "upstream"},
				Dependencies: []egeproto.EvidenceDependency{
					{Kind: "administrative", ID: "admin:observability", Material: true},
					{Kind: "credential", ID: "credential:prometheus-reader", Material: true},
					{Kind: "platform", ID: "facility:shared", Material: false},
					{Kind: "upstream", ID: "upstream:prometheus-store", Material: true},
				},
				Assurance:         assurance,
				CorroborationRefs: refTelemetry,
			},
		},
	}
}

func composeTwoSourcePolicy(
	t *testing.T,
	policy egeEvidenceCompositionPolicy,
) egeEvidenceProduction {
	t.Helper()
	observedAt := time.Date(2026, 9, 29, 20, 0, 0, 0, time.UTC)
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "label-control",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	telemetry := &compositionContributor{
		name:        "telemetry",
		trustDomain: "label-observability",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:        decision.Allow,
			ObservedAt:      observedAt.Add(-time.Second),
			EvidenceDigest:  "sha256:telemetry",
			EvidenceClasses: []string{"telemetry"},
		},
	}
	producers, err := newEGEEvidenceProducerRegistry(primary)
	if err != nil {
		t.Fatal(err)
	}
	contributors, err := newEGEEvidenceContributorRegistry(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{"test.mutate": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := composer.Compose(
		context.Background(),
		"intent-c09",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-c09"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEGEEvidenceIndependenceDifferentLabelsDoNotHideSharedMaterialDependency(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	telemetry := policy.SourceDeclarations["telemetry"]
	telemetry.Dependencies = append(
		telemetry.Dependencies,
		egeproto.EvidenceDependency{
			Kind: "upstream",
			ID: "upstream:kubernetes-api",
			Material: true,
		},
	)
	policy.SourceDeclarations["telemetry"] = telemetry

	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Escalate || result.PermitBinding != nil {
		t.Fatalf("shared material dependency must not satisfy independence: %+v", result)
	}
	if result.EvidenceComposition == nil {
		t.Fatal("missing evidence-composition assessment")
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceDependent {
		t.Fatalf("overall independence = %s, want DEPENDENT", result.EvidenceComposition.OverallIndependence)
	}
	if result.EvidenceComposition.IndependentSourceCount != 1 {
		t.Fatalf("independent source count = %d, want 1", result.EvidenceComposition.IndependentSourceCount)
	}
	if len(result.EvidenceComposition.PairAssessments) != 1 ||
		result.EvidenceComposition.PairAssessments[0].Status != egeproto.EvidenceIndependenceDependent {
		t.Fatalf("pair assessment = %+v", result.EvidenceComposition.PairAssessments)
	}
}

func TestEGEEvidenceIndependenceIgnoresDeclaredNonMaterialCommonDependency(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Allow || result.PermitBinding == nil {
		t.Fatalf("expected asserted independent ALLOW, got %+v", result)
	}
	if result.EvidenceComposition == nil ||
		result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceAsserted ||
		result.EvidenceComposition.IndependentSourceCount != 2 {
		t.Fatalf("unexpected independence assessment: %+v", result.EvidenceComposition)
	}
}

func TestEGEEvidenceIndependenceUnknownDeclarationCannotSatisfyRequirement(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	delete(policy.SourceDeclarations, "telemetry")

	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Escalate || result.PermitBinding != nil {
		t.Fatalf("missing declaration must fail closed: %+v", result)
	}
	if result.EvidenceComposition == nil ||
		result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceUnknown {
		t.Fatalf("missing declaration did not remain UNKNOWN: %+v", result.EvidenceComposition)
	}
}

func TestEGEEvidenceIndependenceSameProducerCannotBeMultipliedByLabels(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	telemetry := policy.SourceDeclarations["telemetry"]
	telemetry.ProducerID = policy.SourceDeclarations["primary"].ProducerID
	policy.SourceDeclarations["telemetry"] = telemetry

	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Escalate {
		t.Fatalf("same producer under different labels must not satisfy independence: %+v", result)
	}
	pair := result.EvidenceComposition.PairAssessments[0]
	if pair.Status != egeproto.EvidenceIndependenceDependent ||
		len(pair.ReasonCodes) != 1 || pair.ReasonCodes[0] != "SHARED_PRODUCER" {
		t.Fatalf("same-producer assessment = %+v", pair)
	}
}

func TestEGEEvidenceIndependenceCorroboratedProfileRequiresCorroboratedDeclarations(t *testing.T) {
	asserted := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceCorroborated,
		egeproto.EvidenceDeclarationAsserted,
	)
	result := composeTwoSourcePolicy(t, asserted)
	if result.Decision != decision.Escalate {
		t.Fatalf("asserted declarations must not satisfy corroborated requirement: %+v", result)
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceAsserted {
		t.Fatalf("overall independence = %s, want ASSERTED", result.EvidenceComposition.OverallIndependence)
	}

	corroborated := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceCorroborated,
		egeproto.EvidenceDeclarationCorroborated,
	)
	result = composeTwoSourcePolicy(t, corroborated)
	if result.Decision != decision.Allow || result.PermitBinding == nil {
		t.Fatalf("corroborated declarations should satisfy corroborated policy: %+v", result)
	}
	if result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceCorroborated ||
		result.EvidenceComposition.IndependentSourceCount != 2 {
		t.Fatalf("corroborated assessment = %+v", result.EvidenceComposition)
	}
}

func TestEGEEvidenceCompositionWithoutIndependenceRequirementKeepsNarrowerClaim(t *testing.T) {
	policy := egeEvidenceCompositionPolicy{
		MinSources:      2,
		MinTrustDomains: 2,
		RequiredSources: []string{"primary", "telemetry"},
	}
	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Allow || result.PermitBinding == nil {
		t.Fatalf("two-source corroboration should remain usable without independence claim: %+v", result)
	}
	if result.EvidenceComposition == nil ||
		result.EvidenceComposition.RequiredIndependence != egeproto.EvidenceIndependenceUnknown ||
		result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceUnknown ||
		result.EvidenceComposition.IndependentSourceCount != 0 {
		t.Fatalf("narrow composition claim was over-promoted: %+v", result.EvidenceComposition)
	}
}

func TestEGEEvidenceContradictionKeepsBlockMeaningWithIndependenceProfile(t *testing.T) {
	observedAt := time.Date(2026, 9, 29, 20, 0, 0, 0, time.UTC)
	primary := &compositionPrimaryProducer{
		name:        "primary",
		trustDomain: "label-control",
		kind:        "test.mutate",
		targetType:  "test.resource",
		production:  compositionAllowProduction(observedAt),
	}
	telemetry := &compositionContributor{
		name:        "telemetry",
		trustDomain: "label-observability",
		kind:        "test.mutate",
		targetType:  "test.resource",
		contribution: egeEvidenceContribution{
			Decision:    decision.Block,
			ReasonCodes: []decision.ReasonCode{decision.EvidenceContradicted},
		},
	}
	producers, _ := newEGEEvidenceProducerRegistry(primary)
	contributors, _ := newEGEEvidenceContributorRegistry(telemetry)
	composer, err := newEGEEvidenceComposer(
		producers,
		contributors,
		map[string]egeEvidenceCompositionPolicy{
			"test.mutate": declaredCompositionPolicy(
				egeproto.EvidenceIndependenceAsserted,
				egeproto.EvidenceDeclarationAsserted,
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := composer.Compose(
		context.Background(),
		"intent-contradiction",
		"test.mutate",
		egeTargetDTO{Type: "test.resource", Name: "r-contradiction"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != decision.Block ||
		len(result.ReasonCodes) != 1 ||
		result.ReasonCodes[0] != decision.EvidenceContradicted ||
		result.PermitBinding != nil {
		t.Fatalf("contradiction meaning changed: %+v", result)
	}
}


func TestEGEEvidenceIndependenceMissingRequiredDependencyCoverageIsUnknown(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	telemetry := policy.SourceDeclarations["telemetry"]
	telemetry.DependencyCoverage = []string{"credential", "upstream"}
	policy.SourceDeclarations["telemetry"] = telemetry

	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Escalate || result.PermitBinding != nil {
		t.Fatalf("incomplete dependency coverage must fail closed: %+v", result)
	}
	if result.EvidenceComposition == nil ||
		result.EvidenceComposition.OverallIndependence != egeproto.EvidenceIndependenceUnknown {
		t.Fatalf("incomplete coverage must remain UNKNOWN: %+v", result.EvidenceComposition)
	}
	pair := result.EvidenceComposition.PairAssessments[0]
	if pair.Status != egeproto.EvidenceIndependenceUnknown ||
		len(pair.ReasonCodes) != 1 ||
		pair.ReasonCodes[0] != "DEPENDENCY_COVERAGE_UNKNOWN" {
		t.Fatalf("unexpected incomplete-coverage assessment: %+v", pair)
	}
}

func TestEGEEvidenceIndependenceSharedObservationPathIsDependent(t *testing.T) {
	policy := declaredCompositionPolicy(
		egeproto.EvidenceIndependenceAsserted,
		egeproto.EvidenceDeclarationAsserted,
	)
	telemetry := policy.SourceDeclarations["telemetry"]
	telemetry.ObservationPath = policy.SourceDeclarations["primary"].ObservationPath
	policy.SourceDeclarations["telemetry"] = telemetry

	result := composeTwoSourcePolicy(t, policy)
	if result.Decision != decision.Escalate {
		t.Fatalf("shared observation path must not satisfy independence: %+v", result)
	}
	pair := result.EvidenceComposition.PairAssessments[0]
	if pair.Status != egeproto.EvidenceIndependenceDependent ||
		len(pair.ReasonCodes) != 1 ||
		pair.ReasonCodes[0] != "SHARED_OBSERVATION_PATH" {
		t.Fatalf("unexpected observation-path assessment: %+v", pair)
	}
}

func TestEGEEvidenceContributorRegistryRejectsDuplicateSourceName(t *testing.T) {
	first := &compositionContributor{
		name:        "duplicate",
		trustDomain: "label-a",
		kind:        "test.mutate",
		targetType:  "test.resource",
	}
	second := &compositionContributor{
		name:        "duplicate",
		trustDomain: "label-b",
		kind:        "test.mutate",
		targetType:  "test.resource",
	}
	if _, err := newEGEEvidenceContributorRegistry(first, second); err == nil {
		t.Fatal("duplicate source name unexpectedly accepted")
	}
}


func TestEGEEvidenceIndependenceSharedMaterialFailureDomainsRemainDependent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*egeEvidenceCompositionPolicy)
	}{
		{
			name: "shared upstream",
			mutate: func(policy *egeEvidenceCompositionPolicy) {
				telemetry := policy.SourceDeclarations["telemetry"]
				telemetry.Dependencies = append(
					telemetry.Dependencies,
					egeproto.EvidenceDependency{
						Kind: "upstream",
						ID: "upstream:kubernetes-api",
						Material: true,
					},
				)
				policy.SourceDeclarations["telemetry"] = telemetry
			},
		},
		{
			name: "shared credential",
			mutate: func(policy *egeEvidenceCompositionPolicy) {
				telemetry := policy.SourceDeclarations["telemetry"]
				for i := range telemetry.Dependencies {
					if telemetry.Dependencies[i].Kind == "credential" {
						telemetry.Dependencies[i].ID = "credential:kubernetes-reader"
					}
				}
				policy.SourceDeclarations["telemetry"] = telemetry
			},
		},
		{
			name: "shared cache",
			mutate: func(policy *egeEvidenceCompositionPolicy) {
				primary := policy.SourceDeclarations["primary"]
				telemetry := policy.SourceDeclarations["telemetry"]
				primary.DependencyCoverage = append(primary.DependencyCoverage, "cache")
				telemetry.DependencyCoverage = append(telemetry.DependencyCoverage, "cache")
				primary.Dependencies = append(
					primary.Dependencies,
					egeproto.EvidenceDependency{
						Kind: "cache",
						ID: "cache:shared-observation",
						Material: true,
					},
				)
				telemetry.Dependencies = append(
					telemetry.Dependencies,
					egeproto.EvidenceDependency{
						Kind: "cache",
						ID: "cache:shared-observation",
						Material: true,
					},
				)
				policy.SourceDeclarations["primary"] = primary
				policy.SourceDeclarations["telemetry"] = telemetry
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := declaredCompositionPolicy(
				egeproto.EvidenceIndependenceAsserted,
				egeproto.EvidenceDeclarationAsserted,
			)
			tt.mutate(&policy)
			result := composeTwoSourcePolicy(t, policy)
			if result.Decision != decision.Escalate || result.PermitBinding != nil {
				t.Fatalf("shared material failure domain must fail closed: %+v", result)
			}
			pair := result.EvidenceComposition.PairAssessments[0]
			if pair.Status != egeproto.EvidenceIndependenceDependent ||
				len(pair.SharedDependencies) == 0 {
				t.Fatalf("shared failure domain not recorded: %+v", pair)
			}
		})
	}
}
