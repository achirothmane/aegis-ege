package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

var (
	errUnsupportedEGEIntentKind = errors.New("unsupported EGE intent kind")
	errEGETargetTypeMismatch    = errors.New("EGE target type mismatch")
)

type egeAdapterExecution struct {
	Decision    decision.Decision
	ReasonCodes []decision.ReasonCode
	PlanDigest  string
	Steps       []mutationStepDTO
}

type egeExecutionAdapter interface {
	Kind() string
	TargetType() string
	AuthorizationFromPermit(string, egeTargetDTO, egeproto.PermitClaims) (decision.Authorization, error)
	Execute(context.Context, decision.Authorization, egeTargetDTO) (egeAdapterExecution, error)
}

type egeAdapterRegistry struct {
	byKind map[string]egeExecutionAdapter
}

func newEGEAdapterRegistry(adapters ...egeExecutionAdapter) (*egeAdapterRegistry, error) {
	registry := &egeAdapterRegistry{byKind: make(map[string]egeExecutionAdapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, errors.New("EGE adapter is required")
		}
		kind := strings.TrimSpace(adapter.Kind())
		targetType := strings.TrimSpace(adapter.TargetType())
		if kind == "" || targetType == "" {
			return nil, errors.New("EGE adapter kind and target type are required")
		}
		if _, exists := registry.byKind[kind]; exists {
			return nil, fmt.Errorf("duplicate EGE adapter kind %q", kind)
		}
		registry.byKind[kind] = adapter
	}
	return registry, nil
}

func (r *egeAdapterRegistry) Resolve(kind, targetType string) (egeExecutionAdapter, error) {
	if r == nil {
		return nil, errors.New("EGE adapter registry is unavailable")
	}
	adapter, ok := r.byKind[strings.TrimSpace(kind)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnsupportedEGEIntentKind, kind)
	}
	if adapter.TargetType() != strings.TrimSpace(targetType) {
		return nil, fmt.Errorf(
			"%w: kind %s requires target type %s",
			errEGETargetTypeMismatch,
			adapter.Kind(),
			adapter.TargetType(),
		)
	}
	return adapter, nil
}
