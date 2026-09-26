package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type egePermitBinding struct {
	Action          string
	ResourceVersion string
	EvidenceDigest  string
	PlanDigest      string
	ValidUntil      time.Time
}

type egeEvidenceProduction struct {
	Decision        decision.Decision
	ReasonCodes     []decision.ReasonCode
	PlanDigest      string
	ObservedAt      time.Time
	EvidenceClasses []string
	PermitBinding   *egePermitBinding
	Snapshot        *snapshotDTO
	Plan            *planDTO
}

type egeEvidenceProducer interface {
	Kind() string
	TargetType() string
	Produce(context.Context, string, egeTargetDTO) (egeEvidenceProduction, error)
}

type egeEvidenceProducerRegistry struct {
	byKind map[string]egeEvidenceProducer
}

func newEGEEvidenceProducerRegistry(producers ...egeEvidenceProducer) (*egeEvidenceProducerRegistry, error) {
	registry := &egeEvidenceProducerRegistry{byKind: make(map[string]egeEvidenceProducer, len(producers))}
	for _, producer := range producers {
		if producer == nil {
			return nil, errors.New("EGE evidence producer is required")
		}
		kind := strings.TrimSpace(producer.Kind())
		targetType := strings.TrimSpace(producer.TargetType())
		if kind == "" || targetType == "" {
			return nil, errors.New("EGE evidence producer kind and target type are required")
		}
		if _, exists := registry.byKind[kind]; exists {
			return nil, fmt.Errorf("duplicate EGE evidence producer kind %q", kind)
		}
		registry.byKind[kind] = producer
	}
	return registry, nil
}

func (r *egeEvidenceProducerRegistry) Resolve(kind, targetType string) (egeEvidenceProducer, error) {
	if r == nil {
		return nil, errors.New("EGE evidence producer registry is unavailable")
	}
	producer, ok := r.byKind[strings.TrimSpace(kind)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnsupportedEGEIntentKind, kind)
	}
	if producer.TargetType() != strings.TrimSpace(targetType) {
		return nil, fmt.Errorf(
			"%w: kind %s requires target type %s",
			errEGETargetTypeMismatch,
			producer.Kind(),
			producer.TargetType(),
		)
	}
	return producer, nil
}
