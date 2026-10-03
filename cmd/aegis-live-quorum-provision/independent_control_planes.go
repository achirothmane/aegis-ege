package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type independentControlPlaneTarget struct {
	member     memberMaterial
	config     *rest.Config
	client     kubernetes.Interface
	chaosPath  string
	domainID   string
}

func runIndependentControlPlanes(ctx context.Context) error {
	bundlePath := requireEnv("LIVE_QUORUM_CLIENT_BUNDLE")
	specs := []struct {
		memberSpec
		adminEnv string
		chaosEnv string
		domainID string
	}{
		{
			memberSpec: memberSpec{
				ID:       "witness-a",
				Suffix:   "a",
				NodePort: 30445,
			},
			adminEnv: "LIVE_QUORUM_WITNESS_A_ADMIN_KUBECONFIG",
			chaosEnv: "LIVE_QUORUM_WITNESS_A_CHAOS_KUBECONFIG",
			domainID: "witness-control-plane-a",
		},
		{
			memberSpec: memberSpec{
				ID:       "witness-b",
				Suffix:   "b",
				NodePort: 30446,
			},
			adminEnv: "LIVE_QUORUM_WITNESS_B_ADMIN_KUBECONFIG",
			chaosEnv: "LIVE_QUORUM_WITNESS_B_CHAOS_KUBECONFIG",
			domainID: "witness-control-plane-b",
		},
		{
			memberSpec: memberSpec{
				ID:       "witness-c",
				Suffix:   "c",
				NodePort: 30447,
			},
			adminEnv: "LIVE_QUORUM_WITNESS_C_ADMIN_KUBECONFIG",
			chaosEnv: "LIVE_QUORUM_WITNESS_C_CHAOS_KUBECONFIG",
			domainID: "witness-control-plane-c",
		},
	}

	workloadPublic, workloadPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	workloadKeyID, err := kernelfabric.BootstrapKeyID(workloadPublic)
	if err != nil {
		return err
	}

	targets := make([]independentControlPlaneTarget, 0, len(specs))
	for _, spec := range specs {
		config, err := clientcmd.BuildConfigFromFlags("", requireEnv(spec.adminEnv))
		if err != nil {
			return fmt.Errorf("%s admin config: %w", spec.domainID, err)
		}
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("%s client: %w", spec.domainID, err)
		}
		if err := ensureNamespace(ctx, client, namespace); err != nil {
			return fmt.Errorf("%s namespace: %w", spec.domainID, err)
		}
		material, err := newMemberMaterial(
			spec.memberSpec,
			workloadKeyID,
			workloadPrivate,
		)
		if err != nil {
			return fmt.Errorf("%s material: %w", spec.domainID, err)
		}
		targets = append(targets, independentControlPlaneTarget{
			member:    material,
			config:    config,
			client:    client,
			chaosPath: requireEnv(spec.chaosEnv),
			domainID:  spec.domainID,
		})
	}

	if err := requireDistinctControlPlanes(targets); err != nil {
		return err
	}

	policy := journal.QuorumTrustPolicy{
		Protocol:  journal.QuorumTrustPolicyVersion,
		Threshold: 2,
		Members:   make([]journal.QuorumTrustPolicyMember, 0, len(targets)),
	}
	for _, target := range targets {
		policy.Members = append(
			policy.Members,
			journal.QuorumTrustPolicyMember{
				ID:                target.member.spec.ID,
				TrustManifestHash: target.member.manifestHash,
			},
		)
	}
	envelope, err := json.Marshal(capabilityEnvelope{
		ExternalWitnessQuorum: policy,
	})
	if err != nil {
		return err
	}
	envelopeHash := sha256Digest(envelope)
	binding, err := journal.ParseGenesisQuorumBinding(envelope, envelopeHash)
	if err != nil {
		return err
	}
	activePolicy, err := binding.ActivePolicy(genesisEpoch)
	if err != nil {
		return err
	}

	for i := range targets {
		target := &targets[i]
		if err := provisionMember(
			ctx,
			target.client,
			&target.member,
			activePolicy,
		); err != nil {
			return fmt.Errorf("%s provision member: %w", target.domainID, err)
		}
	}
	for i := range targets {
		target := &targets[i]
		if err := waitDeployment(
			ctx,
			target.client,
			target.member.signerDeployment,
		); err != nil {
			return fmt.Errorf("%s signer readiness: %w", target.domainID, err)
		}
		if err := waitDeployment(
			ctx,
			target.client,
			target.member.deploymentName,
		); err != nil {
			return fmt.Errorf("%s witness readiness: %w", target.domainID, err)
		}

		token, err := provisionChaosServiceAccount(
			ctx,
			target.client,
			[]memberMaterial{target.member},
		)
		if err != nil {
			return fmt.Errorf("%s availability credential: %w", target.domainID, err)
		}
		if err := writeRuntimeKubeconfig(
			target.chaosPath,
			target.config,
			token,
			namespace,
		); err != nil {
			return fmt.Errorf("%s write availability kubeconfig: %w", target.domainID, err)
		}
	}

	output := liveQuorumBundle{
		Version:                  bundleVersion,
		GenesisEpoch:             genesisEpoch,
		CapabilityEnvelopeBase64: base64.StdEncoding.EncodeToString(envelope),
		CapabilityEnvelopeHash:   envelopeHash,
		JournalID:                journalID,
		WorkloadSignerKeyID:      workloadKeyID,
		WorkloadSignerPublicKey:  base64.StdEncoding.EncodeToString(workloadPublic),
		Members:                  make([]liveQuorumMember, 0, len(targets)),
	}
	for _, target := range targets {
		member := target.member
		output.Members = append(output.Members, liveQuorumMember{
			ID:                    member.spec.ID,
			StateName:             member.stateName,
			DeploymentName:        member.deploymentName,
			SignerDeploymentName:  member.signerDeployment,
			Endpoint:              member.externalEndpoint,
			TLSServerName:         member.witnessTLSServerName,
			CAPEM:                 string(member.witnessCertPEM),
			WitnessOwnerKeyID:     member.ownerKeyID,
			WitnessOwnerPublicKey: base64.StdEncoding.EncodeToString(member.ownerPublic),
			SignedTrust:           member.signedTrust,
		})
	}
	return writeJSONFile(bundlePath, output, 0o600)
}

func requireDistinctControlPlanes(
	targets []independentControlPlaneTarget,
) error {
	seen := make(map[string]string, len(targets))
	for _, target := range targets {
		host := target.config.Host
		if previous, ok := seen[host]; ok {
			return fmt.Errorf(
				"independent quorum members %s and %s resolve to the same Kubernetes API server %s",
				previous,
				target.domainID,
				host,
			)
		}
		seen[host] = target.domainID
	}
	if len(seen) != len(targets) {
		return fmt.Errorf(
			"independent quorum requires %d distinct Kubernetes API servers, got %d",
			len(targets),
			len(seen),
		)
	}
	return nil
}
