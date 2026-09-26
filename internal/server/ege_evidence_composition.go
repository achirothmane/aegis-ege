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
	MinSources      int
	MinTrustDomains int
	RequiredSources []string
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
		if policy.MinSources < 0 || policy.MinTrustDomains < 0 {
			return nil, fmt.Errorf("EGE evidence composition policy for %q has negative minimums", kind)
		}
		required := make([]string, 0, len(policy.RequiredSources))
		seen := make(map[string]struct{}, len(policy.RequiredSources))
		for _, source := range policy.RequiredSources {
			source = strings.TrimSpace(source)
			if source == "" {
				return nil, fmt.Errorf("EGE evidence composition policy for %q has empty required source", kind)
			}
			if _, exists := seen[source]; exists {
				continue
			}
			seen[source] = struct{}{}
			required = append(required, source)
		}
		sort.Strings(required)
		policy.RequiredSources = required
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

	binding := production.PermitBinding
	sources := []egeproto.EvidenceSource{{
		Name:        producer.Name(),
		TrustDomain: producer.TrustDomain(),
		Digest:      binding.EvidenceDigest,
		ObservedAt:  production.ObservedAt.UTC(),
		Classes:     append([]string(nil), production.EvidenceClasses...),
	}}

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

		sources = append(sources, egeproto.EvidenceSource{
			Name:        contributor.Name(),
			TrustDomain: contributor.TrustDomain(),
			Digest:      contribution.EvidenceDigest,
			ObservedAt:  contribution.ObservedAt.UTC(),
			Classes:     append([]string(nil), contribution.EvidenceClasses...),
		})
	}

	if err := validateDistinctEvidenceSources(sources); err != nil {
		return egeEvidenceProduction{}, err
	}

	policy := c.policies[kind]
	if policy.MinSources == 0 {
		policy.MinSources = 1
	}
	if policy.MinTrustDomains == 0 {
		policy.MinTrustDomains = 1
	}
	if !evidenceCompositionSatisfiesPolicy(sources, policy) {
		result := failEvidenceComposition(production, decision.Escalate, decision.InsufficientEvidence)
		result.EvidenceSources = append([]egeproto.EvidenceSource(nil), sources...)
		result.EvidenceClasses = unionEvidenceClasses(sources)
		result.ObservedAt = oldestEvidenceObservation(sources)
		return result, nil
	}

	production.EvidenceSources = append([]egeproto.EvidenceSource(nil), sources...)
	production.EvidenceClasses = unionEvidenceClasses(sources)
	production.ObservedAt = oldestEvidenceObservation(sources)
	return production, nil
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
	return true
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
