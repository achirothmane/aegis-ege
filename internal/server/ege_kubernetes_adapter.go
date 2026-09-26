package server

import (
	"context"
	"errors"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
)

const (
	egeNodeDrainKind           = "kubernetes.node_drain"
	egeNodeTarget              = "kubernetes.node"
	egeNodeDrainEvidenceSource = "statelatch.kubernetes.node_drain"
	egeNodeDrainTrustDomain    = "kubernetes-control-plane"
)

type kubernetesNodeDrainEvidenceProducer struct {
	controller NodeDrainController
	policy     kubeadapter.NodeDrainPolicy
}

func newKubernetesNodeDrainEvidenceProducer(
	controller NodeDrainController,
	policy kubeadapter.NodeDrainPolicy,
) *kubernetesNodeDrainEvidenceProducer {
	return &kubernetesNodeDrainEvidenceProducer{
		controller: controller,
		policy:     policy,
	}
}

func (*kubernetesNodeDrainEvidenceProducer) Name() string        { return egeNodeDrainEvidenceSource }
func (*kubernetesNodeDrainEvidenceProducer) TrustDomain() string { return egeNodeDrainTrustDomain }
func (*kubernetesNodeDrainEvidenceProducer) Kind() string        { return egeNodeDrainKind }
func (*kubernetesNodeDrainEvidenceProducer) TargetType() string  { return egeNodeTarget }

func (p *kubernetesNodeDrainEvidenceProducer) Produce(
	ctx context.Context,
	intentID string,
	target egeTargetDTO,
) (egeEvidenceProduction, error) {
	preparation, err := p.controller.PrepareNodeDrainExecution(ctx, intentID, target.Name, p.policy)
	if err != nil {
		return egeEvidenceProduction{}, err
	}

	result := egeEvidenceProduction{
		Decision:    preparation.Decision,
		ReasonCodes: append([]decision.ReasonCode(nil), preparation.ReasonCodes...),
		PlanDigest:  preparation.PlanDigest,
		ObservedAt:  preparation.Snapshot.ObservedAt,
		EvidenceClasses: []string{
			"kubernetes.authoritative-state",
			"kubernetes.pdb-preflight",
			"kubernetes.server-dry-run",
		},
	}

	if preparation.Snapshot.NodeName != "" {
		result.Snapshot = &snapshotDTO{
			NodeUID:         preparation.Snapshot.NodeUID,
			ResourceVersion: preparation.Snapshot.ResourceVersion,
			NodeHealth:      preparation.Snapshot.NodeHealth,
			Unschedulable:   preparation.Snapshot.Unschedulable,
			ActivePods:      preparation.Snapshot.ActivePods,
			ObservedAt:      preparation.Snapshot.ObservedAt,
		}
	}
	if preparation.Plan != nil {
		result.Plan = planToDTO(*preparation.Plan)
	}
	if preparation.Authorization != nil {
		auth := *preparation.Authorization
		result.PermitBinding = &egePermitBinding{
			Action:          auth.Action,
			ResourceVersion: auth.ResourceVersion,
			EvidenceDigest:  auth.EvidenceDigest,
			PlanDigest:      auth.PlanDigest,
			ValidUntil:      auth.ValidUntil,
		}
	}
	return result, nil
}

type kubernetesNodeDrainEGEAdapter struct {
	controller NodeDrainController
	policy     kubeadapter.NodeDrainPolicy
	store      kubeadapter.DrainCheckpointStore
}

func newKubernetesNodeDrainEGEAdapter(
	controller NodeDrainController,
	policy kubeadapter.NodeDrainPolicy,
	store kubeadapter.DrainCheckpointStore,
) *kubernetesNodeDrainEGEAdapter {
	return &kubernetesNodeDrainEGEAdapter{
		controller: controller,
		policy:     policy,
		store:      store,
	}
}

func (*kubernetesNodeDrainEGEAdapter) Kind() string       { return egeNodeDrainKind }
func (*kubernetesNodeDrainEGEAdapter) TargetType() string { return egeNodeTarget }

func (a *kubernetesNodeDrainEGEAdapter) AuthorizationFromPermit(
	intentID string,
	target egeTargetDTO,
	claims egeproto.PermitClaims,
) (decision.Authorization, error) {
	if claims.Action != "drain" {
		return decision.Authorization{}, errors.New("kubernetes node-drain permit must authorize drain")
	}
	if claims.ResourceVersion == "" ||
		claims.EvidenceDigest == "" ||
		claims.EvidenceManifestDigest == "" ||
		claims.PlanDigest == "" {
		return decision.Authorization{}, errors.New("kubernetes node-drain permit is missing required state bindings")
	}

	return decision.Authorization{
		ActionID:        intentID,
		Action:          claims.Action,
		Target:          "node/" + target.Name,
		ResourceVersion: claims.ResourceVersion,
		EvidenceDigest:  claims.EvidenceDigest,
		PlanDigest:      claims.PlanDigest,
		ValidUntil:      claims.ValidUntil,
	}, nil
}

func (a *kubernetesNodeDrainEGEAdapter) Execute(
	ctx context.Context,
	auth decision.Authorization,
	target egeTargetDTO,
) (egeAdapterExecution, error) {
	report, err := a.controller.ExecuteAuthorizedNodeDrainWithCheckpointStore(
		ctx,
		auth,
		target.Name,
		a.policy,
		a.store,
	)
	if err != nil {
		return egeAdapterExecution{}, err
	}

	result := egeAdapterExecution{
		Decision:    report.Decision,
		ReasonCodes: append([]decision.ReasonCode(nil), report.ReasonCodes...),
		PlanDigest:  report.PlanDigest,
		Steps:       make([]mutationStepDTO, 0, len(report.Steps)),
	}
	for _, step := range report.Steps {
		result.Steps = append(result.Steps, mutationStepDTO{
			Kind:    step.Step.Kind,
			Applied: step.Applied,
			Error:   step.Error,
		})
	}
	return result, nil
}
