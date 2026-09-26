package server

import (
	"context"
	"errors"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

type registryTestAdapter struct {
	kind       string
	targetType string
}

func (a registryTestAdapter) Kind() string       { return a.kind }
func (a registryTestAdapter) TargetType() string { return a.targetType }

func (registryTestAdapter) AuthorizationFromPermit(
	string,
	egeTargetDTO,
	egeproto.PermitClaims,
) (decision.Authorization, error) {
	return decision.Authorization{}, nil
}

func (registryTestAdapter) Execute(
	context.Context,
	decision.Authorization,
	egeTargetDTO,
) (egeAdapterExecution, error) {
	return egeAdapterExecution{}, nil
}

func TestEGEAdapterRegistryResolvesByKindAndTargetType(t *testing.T) {
	expected := registryTestAdapter{kind: "kubernetes.node_drain", targetType: "kubernetes.node"}
	registry, err := newEGEAdapterRegistry(expected)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := registry.Resolve("kubernetes.node_drain", "kubernetes.node")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Kind() != expected.kind || resolved.TargetType() != expected.targetType {
		t.Fatalf("resolved wrong adapter: kind=%s target=%s", resolved.Kind(), resolved.TargetType())
	}
}

func TestEGEAdapterRegistryRejectsUnknownKind(t *testing.T) {
	registry, err := newEGEAdapterRegistry(
		registryTestAdapter{kind: "kubernetes.node_drain", targetType: "kubernetes.node"},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = registry.Resolve("aws.ec2.terminate", "aws.ec2.instance")
	if !errors.Is(err, errUnsupportedEGEIntentKind) {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}
}

func TestEGEAdapterRegistryRejectsTargetTypeMismatch(t *testing.T) {
	registry, err := newEGEAdapterRegistry(
		registryTestAdapter{kind: "kubernetes.node_drain", targetType: "kubernetes.node"},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = registry.Resolve("kubernetes.node_drain", "kubernetes.pod")
	if !errors.Is(err, errEGETargetTypeMismatch) {
		t.Fatalf("expected target type mismatch, got %v", err)
	}
}

func TestEGEAdapterRegistryRejectsDuplicateKind(t *testing.T) {
	_, err := newEGEAdapterRegistry(
		registryTestAdapter{kind: "same.kind", targetType: "target.one"},
		registryTestAdapter{kind: "same.kind", targetType: "target.two"},
	)
	if err == nil {
		t.Fatal("expected duplicate adapter kind to fail")
	}
}
