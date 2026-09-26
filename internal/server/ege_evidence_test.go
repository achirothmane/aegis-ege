package server

import (
	"context"
	"errors"
	"testing"
)

type registryTestEvidenceProducer struct {
	kind       string
	targetType string
	calls      int
}

func (p *registryTestEvidenceProducer) Kind() string       { return p.kind }
func (p *registryTestEvidenceProducer) TargetType() string { return p.targetType }

func (p *registryTestEvidenceProducer) Produce(
	context.Context,
	string,
	egeTargetDTO,
) (egeEvidenceProduction, error) {
	p.calls++
	return egeEvidenceProduction{}, nil
}

func TestEGEEvidenceProducerRegistryResolvesByKindAndTargetType(t *testing.T) {
	expected := &registryTestEvidenceProducer{
		kind:       "kubernetes.node_drain",
		targetType: "kubernetes.node",
	}
	registry, err := newEGEEvidenceProducerRegistry(expected)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := registry.Resolve("kubernetes.node_drain", "kubernetes.node")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Kind() != expected.kind || resolved.TargetType() != expected.targetType {
		t.Fatalf("resolved wrong producer: kind=%s target=%s", resolved.Kind(), resolved.TargetType())
	}
}

func TestEGEEvidenceProducerRegistryRejectsUnknownKind(t *testing.T) {
	registry, err := newEGEEvidenceProducerRegistry(
		&registryTestEvidenceProducer{kind: "kubernetes.node_drain", targetType: "kubernetes.node"},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = registry.Resolve("aws.ec2.terminate", "aws.ec2.instance")
	if !errors.Is(err, errUnsupportedEGEIntentKind) {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}
}

func TestEGEEvidenceProducerRegistryRejectsTargetTypeMismatch(t *testing.T) {
	registry, err := newEGEEvidenceProducerRegistry(
		&registryTestEvidenceProducer{kind: "kubernetes.node_drain", targetType: "kubernetes.node"},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = registry.Resolve("kubernetes.node_drain", "kubernetes.pod")
	if !errors.Is(err, errEGETargetTypeMismatch) {
		t.Fatalf("expected target type mismatch, got %v", err)
	}
}

func TestEGEEvidenceProducerRegistryRejectsDuplicateKind(t *testing.T) {
	_, err := newEGEEvidenceProducerRegistry(
		&registryTestEvidenceProducer{kind: "same.kind", targetType: "target.one"},
		&registryTestEvidenceProducer{kind: "same.kind", targetType: "target.two"},
	)
	if err == nil {
		t.Fatal("expected duplicate evidence producer kind to fail")
	}
}
