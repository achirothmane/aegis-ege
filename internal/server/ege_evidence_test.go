package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type registryTestEvidenceProducer struct {
	name        string
	trustDomain string
	kind        string
	targetType  string
	calls       int
}

func (p *registryTestEvidenceProducer) Name() string {
	if p.name != "" {
		return p.name
	}
	return "test.primary"
}

func (p *registryTestEvidenceProducer) TrustDomain() string {
	if p.trustDomain != "" {
		return p.trustDomain
	}
	return "test-control-plane"
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


func TestValidateEGEEvidenceProductionRequiresBindingForAllow(t *testing.T) {
	err := validateEGEEvidenceProduction(egeEvidenceProduction{
		Decision:        decision.Allow,
		PlanDigest:      "sha256:plan",
		ObservedAt:      time.Now().UTC(),
		EvidenceClasses: []string{"state"},
	})
	if err == nil {
		t.Fatal("expected ALLOW without permit binding to fail")
	}
}

func TestValidateEGEEvidenceProductionRejectsBindingForBlock(t *testing.T) {
	err := validateEGEEvidenceProduction(egeEvidenceProduction{
		Decision: decision.Block,
		PermitBinding: &egePermitBinding{
			Action:          "drain",
			ResourceVersion: "100",
			EvidenceDigest:  "sha256:evidence",
			PlanDigest:      "sha256:plan",
			ValidUntil:      time.Now().UTC().Add(time.Minute),
		},
	})
	if err == nil {
		t.Fatal("expected non-ALLOW with permit binding to fail")
	}
}

func TestValidateEGEEvidenceProductionAcceptsBoundAllow(t *testing.T) {
	observedAt := time.Now().UTC()
	err := validateEGEEvidenceProduction(egeEvidenceProduction{
		Decision:        decision.Allow,
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"state", "dry-run"},
		PermitBinding: &egePermitBinding{
			Action:          "drain",
			ResourceVersion: "100",
			EvidenceDigest:  "sha256:evidence",
			PlanDigest:      "sha256:plan",
			ValidUntil:      observedAt.Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("valid evidence production rejected: %v", err)
	}
}
