package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const maxEvidenceCompositionSources = 16

type egeEvidenceContribution struct {
	Decision        decision.Decision
	ReasonCodes     []decision.ReasonCode
	ObservedAt      time.Time
	EvidenceDigest  string
	EvidenceClasses []string
}

type egeEvidenceContributor interface {
	Name() string
	TrustDomain() string
	Kind() string
	TargetType() string
	Contribute(context.Context, string, egeTargetDTO, egeEvidenceProduction) (egeEvidenceContribution, error)
}

type EvidenceSourceDeclarationConfig struct {
	ProducerID         string                                 `json:"producer_id"`
	ObservationPath    string                                 `json:"observation_path"`
	DependencyCoverage []string                               `json:"dependency_coverage,omitempty"`
	Dependencies       []egeproto.EvidenceDependency          `json:"dependencies,omitempty"`
	Assurance          egeproto.EvidenceDeclarationAssurance  `json:"assurance"`
	CorroborationRefs  []string                               `json:"corroboration_refs,omitempty"`
}

type EvidenceIndependenceProfileConfig struct {
	RequiredIndependence    egeproto.EvidenceIndependenceStatus           `json:"required_independence"`
	MinIndependentSources   int                                            `json:"min_independent_sources"`
	RequiredDependencyKinds []string                                       `json:"required_dependency_kinds"`
	SourceDeclarations      map[string]EvidenceSourceDeclarationConfig     `json:"source_declarations"`
}

type egeEvidenceContributorSet struct {
	targetType   string
	contributors []egeEvidenceContributor
	names        map[string]struct{}
}

type egeEvidenceContributorRegistry struct {
	byKind map[string]*egeEvidenceContributorSet
}

func newEGEEvidenceContributorRegistry(
	contributors ...egeEvidenceContributor,
) (*egeEvidenceContributorRegistry, error) {
	registry := &egeEvidenceContributorRegistry{
		byKind: make(map[string]*egeEvidenceContributorSet),
	}

	for _, contributor := range contributors {
		if contributor == nil {
			return nil, errors.New("EGE evidence contributor is required")
		}
		name := strings.TrimSpace(contributor.Name())
		trustDomain := strings.TrimSpace(contributor.TrustDomain())
		kind := strings.TrimSpace(contributor.Kind())
		targetType := strings.TrimSpace(contributor.TargetType())
		if name == "" || trustDomain == "" || kind == "" || targetType == "" {
			return nil, errors.New("EGE evidence contributor name, trust domain, kind, and target type are required")
		}

		set := registry.byKind[kind]
		if set == nil {
			set = &egeEvidenceContributorSet{
				targetType: targetType,
				names:      make(map[string]struct{}),
			}
			registry.byKind[kind] = set
		}
		if set.targetType != targetType {
			return nil, fmt.Errorf(
				"EGE evidence contributors for kind %q disagree on target type: %q != %q",
				kind,
				set.targetType,
				targetType,
			)
		}
		if _, exists := set.names[name]; exists {
			return nil, fmt.Errorf("duplicate EGE evidence contributor %q for kind %q", name, kind)
		}

		set.names[name] = struct{}{}
		set.contributors = append(set.contributors, contributor)
	}

	return registry, nil
}

func (r *egeEvidenceContributorRegistry) Resolve(
	kind string,
	targetType string,
) ([]egeEvidenceContributor, error) {
	if r == nil {
		return nil, errors.New("EGE evidence contributor registry is unavailable")
	}
	set := r.byKind[strings.TrimSpace(kind)]
	if set == nil {
		return nil, nil
	}
	if set.targetType != strings.TrimSpace(targetType) {
		return nil, fmt.Errorf(
			"%w: kind %s requires target type %s",
			errEGETargetTypeMismatch,
			kind,
			set.targetType,
		)
	}
	return append([]egeEvidenceContributor(nil), set.contributors...), nil
}

type egeEvidenceCompositionPolicy struct {
	MinSources              int
	MinTrustDomains         int
	RequiredSources         []string
	MinIndependentSources   int
	RequiredIndependence    egeproto.EvidenceIndependenceStatus
	RequiredDependencyKinds []string
	SourceDeclarations      map[string]EvidenceSourceDeclarationConfig
}

type egeEvidenceComposer struct {
	producers    *egeEvidenceProducerRegistry
	contributors *egeEvidenceContributorRegistry
	policies     map[string]egeEvidenceCompositionPolicy
}

func newEGEEvidenceComposer(
	producers *egeEvidenceProducerRegistry,
	contributors *egeEvidenceContributorRegistry,
	policies map[string]egeEvidenceCompositionPolicy,
) (*egeEvidenceComposer, error) {
	if producers == nil {
		return nil, errors.New("EGE evidence producer registry is required")
	}
	if contributors == nil {
		return nil, errors.New("EGE evidence contributor registry is required")
	}

	clonedPolicies := make(map[string]egeEvidenceCompositionPolicy, len(policies))
	for kind, policy := range policies {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			return nil, errors.New("EGE evidence composition policy kind is required")
		}
		if policy.MinSources < 0 || policy.MinTrustDomains < 0 || policy.MinIndependentSources < 0 {
			return nil, fmt.Errorf("EGE evidence composition policy for %q has negative minimums", kind)
		}
		switch policy.RequiredIndependence {
		case "":
			if policy.MinIndependentSources > 0 {
				return nil, fmt.Errorf(
					"EGE evidence composition policy for %q requires an independence threshold",
					kind,
				)
			}
		case egeproto.EvidenceIndependenceAsserted, egeproto.EvidenceIndependenceCorroborated:
			if policy.MinIndependentSources <= 0 {
				return nil, fmt.Errorf(
					"EGE evidence composition policy for %q has an independence class without a minimum source count",
					kind,
				)
			}
		default:
			return nil, fmt.Errorf(
				"EGE evidence composition policy for %q has unsupported required independence %q",
				kind,
				policy.RequiredIndependence,
			)
		}

		for _, source := range policy.RequiredSources {
			if strings.TrimSpace(source) == "" {
				return nil, fmt.Errorf("EGE evidence composition policy for %q has empty required source", kind)
			}
		}
		policy.RequiredSources = normalizedUniqueStrings(policy.RequiredSources)
		for _, dependencyKind := range policy.RequiredDependencyKinds {
			if strings.TrimSpace(dependencyKind) == "" {
				return nil, fmt.Errorf(
					"EGE evidence composition policy for %q has empty required dependency kind",
					kind,
				)
			}
		}
		policy.RequiredDependencyKinds = normalizedUniqueStrings(policy.RequiredDependencyKinds)
		if policy.MinIndependentSources > 0 && len(policy.RequiredDependencyKinds) == 0 {
			return nil, fmt.Errorf(
				"EGE evidence composition policy for %q requires independence without dependency coverage classes",
				kind,
			)
		}

		clonedDeclarations := make(map[string]EvidenceSourceDeclarationConfig, len(policy.SourceDeclarations))
		for sourceName, declaration := range policy.SourceDeclarations {
			sourceName = strings.TrimSpace(sourceName)
			if sourceName == "" {
				return nil, fmt.Errorf("EGE evidence composition policy for %q has an empty declaration source name", kind)
			}
			normalized, err := normalizeEvidenceSourceDeclaration(declaration)
			if err != nil {
				return nil, fmt.Errorf(
					"EGE evidence composition policy for %q source %q: %w",
					kind,
					sourceName,
					err,
				)
			}
			clonedDeclarations[sourceName] = normalized
		}
		policy.SourceDeclarations = clonedDeclarations
		clonedPolicies[kind] = policy
	}

	return &egeEvidenceComposer{
		producers:    producers,
		contributors: contributors,
		policies:     clonedPolicies,
	}, nil
}

func (c *egeEvidenceComposer) Compose(
	ctx context.Context,
	intentID string,
	kind string,
	target egeTargetDTO,
) (egeEvidenceProduction, error) {
	producer, err := c.producers.Resolve(kind, target.Type)
	if err != nil {
		return egeEvidenceProduction{}, err
	}

	production, err := producer.Produce(ctx, intentID, target)
	if err != nil {
		return egeEvidenceProduction{}, err
	}
	if err := validateEGEEvidenceProduction(production); err != nil {
		return egeEvidenceProduction{}, fmt.Errorf("validate primary evidence producer %q: %w", producer.Name(), err)
	}
	if production.Decision != decision.Allow {
		return production, nil
	}

	policy := c.policies[kind]
	binding := production.PermitBinding
	sources := []egeproto.EvidenceSource{
		buildEvidenceSource(
			producer.Name(),
			producer.TrustDomain(),
			binding.EvidenceDigest,
			production.ObservedAt.UTC(),
			production.EvidenceClasses,
			target,
			policy.SourceDeclarations[producer.Name()],
		),
	}

	contributors, err := c.contributors.Resolve(kind, target.Type)
	if err != nil {
		return egeEvidenceProduction{}, err
	}
	for _, contributor := range contributors {
		contribution, err := contributor.Contribute(ctx, intentID, target, production)
		if err != nil {
			return failEvidenceComposition(production, decision.Escalate, decision.InsufficientEvidence), nil
		}
		if err := validateEGEEvidenceContribution(contribution); err != nil {
			return egeEvidenceProduction{}, fmt.Errorf(
				"validate evidence contributor %q: %w",
				contributor.Name(),
				err,
			)
		}
		if contribution.Decision != decision.Allow {
			reasons := append([]decision.ReasonCode(nil), contribution.ReasonCodes...)
			if len(reasons) == 0 {
				reasons = []decision.ReasonCode{decision.InsufficientEvidence}
			}
			return failEvidenceComposition(production, contribution.Decision, reasons...), nil
		}

		sources = append(sources, buildEvidenceSource(
			contributor.Name(),
			contributor.TrustDomain(),
			contribution.EvidenceDigest,
			contribution.ObservedAt.UTC(),
			contribution.EvidenceClasses,
			target,
			policy.SourceDeclarations[contributor.Name()],
		))
	}

	if err := validateDistinctEvidenceSources(sources); err != nil {
		return egeEvidenceProduction{}, err
	}
	if len(sources) > maxEvidenceCompositionSources {
		return egeEvidenceProduction{}, fmt.Errorf(
			"composed evidence source count %d exceeds bounded profile limit %d",
			len(sources),
			maxEvidenceCompositionSources,
		)
	}

	if policy.MinSources == 0 {
		policy.MinSources = 1
	}
	if policy.MinTrustDomains == 0 {
		policy.MinTrustDomains = 1
	}

	assessment := assessEvidenceIndependence(sources, policy)
	if !evidenceCompositionSatisfiesPolicy(sources, policy, assessment) {
		result := failEvidenceComposition(production, decision.Escalate, decision.InsufficientEvidence)
		result.EvidenceSources = append([]egeproto.EvidenceSource(nil), sources...)
		result.EvidenceClasses = unionEvidenceClasses(sources)
		result.ObservedAt = oldestEvidenceObservation(sources)
		result.EvidenceComposition = &assessment
		return result, nil
	}

	production.EvidenceSources = append([]egeproto.EvidenceSource(nil), sources...)
	production.EvidenceClasses = unionEvidenceClasses(sources)
	production.ObservedAt = oldestEvidenceObservation(sources)
	production.EvidenceComposition = &assessment
	return production, nil
}

func buildEvidenceSource(
	name string,
	trustDomain string,
	digest string,
	observedAt time.Time,
	classes []string,
	target egeTargetDTO,
	declaration EvidenceSourceDeclarationConfig,
) egeproto.EvidenceSource {
	source := egeproto.EvidenceSource{
		Name:        name,
		TrustDomain: trustDomain,
		Digest:      digest,
		ObservedAt:  observedAt.UTC(),
		Classes:     append([]string(nil), classes...),
	}
	if hasEvidenceSourceDeclaration(declaration) {
		source.Declaration = &egeproto.EvidenceSourceDeclaration{
			ProducerID:         declaration.ProducerID,
			Subject:            target.Type + "/" + target.Name,
			ObservationPath:    declaration.ObservationPath,
			DependencyCoverage: append([]string(nil), declaration.DependencyCoverage...),
			Dependencies:       append([]egeproto.EvidenceDependency(nil), declaration.Dependencies...),
			Assurance:          declaration.Assurance,
			CorroborationRefs:  append([]string(nil), declaration.CorroborationRefs...),
		}
	}
	return source
}

func validateEGEEvidenceContribution(contribution egeEvidenceContribution) error {
	switch contribution.Decision {
	case decision.Allow:
		if contribution.ObservedAt.IsZero() {
			return errors.New("ALLOW evidence contribution requires observed_at")
		}
		if strings.TrimSpace(contribution.EvidenceDigest) == "" {
			return errors.New("ALLOW evidence contribution requires evidence digest")
		}
		if len(contribution.EvidenceClasses) == 0 {
			return errors.New("ALLOW evidence contribution requires at least one evidence class")
		}
	case decision.Block, decision.Escalate:
		if len(contribution.ReasonCodes) == 0 {
			return errors.New("non-ALLOW evidence contribution requires a reason code")
		}
	default:
		return fmt.Errorf("unsupported evidence contribution decision %q", contribution.Decision)
	}
	return nil
}

func validateDistinctEvidenceSources(sources []egeproto.EvidenceSource) error {
	names := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		name := strings.TrimSpace(source.Name)
		trustDomain := strings.TrimSpace(source.TrustDomain)
		if name == "" || trustDomain == "" || strings.TrimSpace(source.Digest) == "" || source.ObservedAt.IsZero() {
			return errors.New("composed evidence source has incomplete identity or evidence binding")
		}
		if len(source.Classes) == 0 {
			return fmt.Errorf("composed evidence source %q has no evidence classes", name)
		}
		if _, exists := names[name]; exists {
			return fmt.Errorf("duplicate composed evidence source %q", name)
		}
		names[name] = struct{}{}
	}
	return nil
}

func evidenceCompositionSatisfiesPolicy(
	sources []egeproto.EvidenceSource,
	policy egeEvidenceCompositionPolicy,
	assessment egeproto.EvidenceCompositionAssessment,
) bool {
	if len(sources) < policy.MinSources {
		return false
	}

	names := make(map[string]struct{}, len(sources))
	trustDomains := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		names[source.Name] = struct{}{}
		trustDomains[source.TrustDomain] = struct{}{}
	}
	if len(trustDomains) < policy.MinTrustDomains {
		return false
	}
	for _, required := range policy.RequiredSources {
		if _, ok := names[required]; !ok {
			return false
		}
	}
	if policy.MinIndependentSources > 0 &&
		assessment.IndependentSourceCount < policy.MinIndependentSources {
		return false
	}
	return true
}

func assessEvidenceIndependence(
	sources []egeproto.EvidenceSource,
	policy egeEvidenceCompositionPolicy,
) egeproto.EvidenceCompositionAssessment {
	return egeproto.AssessEvidenceIndependence(
		sources,
		egeproto.EvidenceIndependenceRequirement{
			RequiredIndependence:    policy.RequiredIndependence,
			MinIndependentSources:   policy.MinIndependentSources,
			RequiredDependencyKinds: append([]string(nil), policy.RequiredDependencyKinds...),
		},
	)
}

func normalizeEvidenceSourceDeclaration(
	declaration EvidenceSourceDeclarationConfig,
) (EvidenceSourceDeclarationConfig, error) {
	declaration.ProducerID = strings.TrimSpace(declaration.ProducerID)
	declaration.ObservationPath = strings.TrimSpace(declaration.ObservationPath)
	declaration.DependencyCoverage = normalizedUniqueStrings(declaration.DependencyCoverage)
	declaration.CorroborationRefs = normalizedUniqueStrings(declaration.CorroborationRefs)

	switch declaration.Assurance {
	case "":
		declaration.Assurance = egeproto.EvidenceDeclarationUnknown
	case egeproto.EvidenceDeclarationUnknown:
	case egeproto.EvidenceDeclarationAsserted:
		if declaration.ProducerID == "" || declaration.ObservationPath == "" {
			return EvidenceSourceDeclarationConfig{}, errors.New(
				"ASSERTED declaration requires producer_id and observation_path",
			)
		}
	case egeproto.EvidenceDeclarationCorroborated:
		if declaration.ProducerID == "" || declaration.ObservationPath == "" {
			return EvidenceSourceDeclarationConfig{}, errors.New(
				"CORROBORATED declaration requires producer_id and observation_path",
			)
		}
		if len(declaration.CorroborationRefs) == 0 {
			return EvidenceSourceDeclarationConfig{}, errors.New(
				"CORROBORATED declaration requires at least one corroboration reference",
			)
		}
	default:
		return EvidenceSourceDeclarationConfig{}, fmt.Errorf(
			"unsupported declaration assurance %q",
			declaration.Assurance,
		)
	}

	seenDependencies := make(map[string]struct{}, len(declaration.Dependencies))
	normalizedDependencies := make([]egeproto.EvidenceDependency, 0, len(declaration.Dependencies))
	coverage := make(map[string]struct{}, len(declaration.DependencyCoverage))
	for _, kind := range declaration.DependencyCoverage {
		coverage[kind] = struct{}{}
	}
	for _, dependency := range declaration.Dependencies {
		dependency.Kind = strings.TrimSpace(dependency.Kind)
		dependency.ID = strings.TrimSpace(dependency.ID)
		if dependency.Kind == "" || dependency.ID == "" {
			return EvidenceSourceDeclarationConfig{}, errors.New(
				"dependency kind and id are required",
			)
		}
		if _, ok := coverage[dependency.Kind]; !ok {
			return EvidenceSourceDeclarationConfig{}, fmt.Errorf(
				"dependency kind %q is not present in dependency coverage",
				dependency.Kind,
			)
		}
		key := dependency.Kind + "\x00" + dependency.ID
		if _, exists := seenDependencies[key]; exists {
			continue
		}
		seenDependencies[key] = struct{}{}
		normalizedDependencies = append(normalizedDependencies, dependency)
	}
	sort.Slice(normalizedDependencies, func(i, j int) bool {
		if normalizedDependencies[i].Kind != normalizedDependencies[j].Kind {
			return normalizedDependencies[i].Kind < normalizedDependencies[j].Kind
		}
		if normalizedDependencies[i].ID != normalizedDependencies[j].ID {
			return normalizedDependencies[i].ID < normalizedDependencies[j].ID
		}
		return !normalizedDependencies[i].Material && normalizedDependencies[j].Material
	})
	declaration.Dependencies = normalizedDependencies
	return declaration, nil
}

func hasEvidenceSourceDeclaration(declaration EvidenceSourceDeclarationConfig) bool {
	return declaration.ProducerID != "" ||
		declaration.ObservationPath != "" ||
		len(declaration.DependencyCoverage) > 0 ||
		len(declaration.Dependencies) > 0 ||
		declaration.Assurance != "" ||
		len(declaration.CorroborationRefs) > 0
}

func normalizedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func failEvidenceComposition(
	base egeEvidenceProduction,
	result decision.Decision,
	reasons ...decision.ReasonCode,
) egeEvidenceProduction {
	base.Decision = result
	base.ReasonCodes = append([]decision.ReasonCode(nil), reasons...)
	base.PermitBinding = nil
	return base
}

func unionEvidenceClasses(sources []egeproto.EvidenceSource) []string {
	seen := make(map[string]struct{})
	for _, source := range sources {
		for _, class := range source.Classes {
			class = strings.TrimSpace(class)
			if class != "" {
				seen[class] = struct{}{}
			}
		}
	}
	classes := make([]string, 0, len(seen))
	for class := range seen {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	return classes
}

func oldestEvidenceObservation(sources []egeproto.EvidenceSource) time.Time {
	if len(sources) == 0 {
		return time.Time{}
	}
	oldest := sources[0].ObservedAt.UTC()
	for _, source := range sources[1:] {
		observedAt := source.ObservedAt.UTC()
		if observedAt.Before(oldest) {
			oldest = observedAt
		}
	}
	return oldest
}
