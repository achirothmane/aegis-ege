package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	independentGenesisEpoch         = uint64(7)
	independentMinimumDoctrineEpoch = uint64(3)
)

type independentControlPlaneSpec struct {
	memberSpec
	adminEnv string
	chaosEnv string
	domainID string
}

type independentControlPlaneTarget struct {
	member    memberMaterial
	config    *rest.Config
	client    kubernetes.Interface
	chaosPath string
	domainID  string
}

type independentPreparedQuorum struct {
	genesisEpoch uint64
	workloadKeyID string
	workloadPublic ed25519.PublicKey
	members       []memberMaterial
	envelope      []byte
	envelopeHash  string
	specs         []independentControlPlaneSpec
}

func independentControlPlaneSpecs() []independentControlPlaneSpec {
	return []independentControlPlaneSpec{
		{
			memberSpec: memberSpec{ID: "witness-a", Suffix: "a", NodePort: 30445},
			adminEnv:   "LIVE_QUORUM_WITNESS_A_ADMIN_KUBECONFIG",
			chaosEnv:   "LIVE_QUORUM_WITNESS_A_CHAOS_KUBECONFIG",
			domainID:   "witness-control-plane-a",
		},
		{
			memberSpec: memberSpec{ID: "witness-b", Suffix: "b", NodePort: 30446},
			adminEnv:   "LIVE_QUORUM_WITNESS_B_ADMIN_KUBECONFIG",
			chaosEnv:   "LIVE_QUORUM_WITNESS_B_CHAOS_KUBECONFIG",
			domainID:   "witness-control-plane-b",
		},
		{
			memberSpec: memberSpec{ID: "witness-c", Suffix: "c", NodePort: 30447},
			adminEnv:   "LIVE_QUORUM_WITNESS_C_ADMIN_KUBECONFIG",
			chaosEnv:   "LIVE_QUORUM_WITNESS_C_CHAOS_KUBECONFIG",
			domainID:   "witness-control-plane-c",
		},
	}
}

func runIndependentControlPlanes(ctx context.Context) error {
	prepared, err := prepareIndependentQuorum()
	if err != nil {
		return err
	}
	pin, err := loadVerifiedIndependentGenesisPin(ctx)
	if err != nil {
		return err
	}
	return activateIndependentControlPlanesWithPin(ctx, prepared, pin)
}

func prepareIndependentQuorum() (independentPreparedQuorum, error) {
	specs := independentControlPlaneSpecs()
	workloadPublic, workloadPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return independentPreparedQuorum{}, err
	}
	workloadKeyID, err := kernelfabric.BootstrapKeyID(workloadPublic)
	if err != nil {
		return independentPreparedQuorum{}, err
	}

	members := make([]memberMaterial, 0, len(specs))
	for _, spec := range specs {
		material, err := newMemberMaterial(
			spec.memberSpec,
			workloadKeyID,
			workloadPrivate,
		)
		if err != nil {
			return independentPreparedQuorum{}, fmt.Errorf("%s material: %w", spec.domainID, err)
		}
		members = append(members, material)
	}

	policy := journal.QuorumTrustPolicy{
		Protocol:  journal.QuorumTrustPolicyVersion,
		Threshold: 2,
		Members:   make([]journal.QuorumTrustPolicyMember, 0, len(members)),
	}
	for _, member := range members {
		policy.Members = append(policy.Members, journal.QuorumTrustPolicyMember{
			ID:                member.spec.ID,
			TrustManifestHash: member.manifestHash,
		})
	}
	envelope, err := json.Marshal(capabilityEnvelope{
		ExternalWitnessQuorum: policy,
	})
	if err != nil {
		return independentPreparedQuorum{}, err
	}
	return independentPreparedQuorum{
		genesisEpoch:   independentGenesisEpoch,
		workloadKeyID:  workloadKeyID,
		workloadPublic: append(ed25519.PublicKey(nil), workloadPublic...),
		members:        members,
		envelope:       envelope,
		envelopeHash:   sha256Digest(envelope),
		specs:          specs,
	}, nil
}

func loadVerifiedIndependentGenesisPin(
	ctx context.Context,
) (genesisbootstrap.VerifiedGenesisPin, error) {
	manifestPath := strings.TrimSpace(os.Getenv("LIVE_QUORUM_GENESIS_MANIFEST"))
	bundlePath := strings.TrimSpace(os.Getenv("LIVE_QUORUM_GENESIS_VERIFICATION_BUNDLE"))
	if manifestPath == "" || bundlePath == "" {
		return genesisbootstrap.VerifiedGenesisPin{}, fmt.Errorf(
			"independent live quorum requires LIVE_QUORUM_GENESIS_MANIFEST and LIVE_QUORUM_GENESIS_VERIFICATION_BUNDLE",
		)
	}
	subject, err := genesisbootstrap.CurrentProductionSubject(
		"/proc/sys/kernel/random/boot_id",
	)
	if err != nil {
		return genesisbootstrap.VerifiedGenesisPin{}, fmt.Errorf(
			"capture live quorum Genesis subject: %w",
			err,
		)
	}
	_, result, pin, err := genesisbootstrap.BootstrapProductionWithSubjectPin(
		ctx,
		manifestPath,
		bundlePath,
		independentGenesisEpoch,
		independentMinimumDoctrineEpoch,
		genesis.ConformanceC3,
		subject,
		time.Now().UTC(),
	)
	if err != nil {
		return genesisbootstrap.VerifiedGenesisPin{}, fmt.Errorf(
			"verify independent live quorum Genesis: state=%s failures=%v: %w",
			result.State,
			result.Failures,
			err,
		)
	}
	if pin.GenesisEpoch() != independentGenesisEpoch {
		return genesisbootstrap.VerifiedGenesisPin{}, fmt.Errorf(
			"verified live quorum Genesis epoch=%d want=%d",
			pin.GenesisEpoch(),
			independentGenesisEpoch,
		)
	}
	return pin, nil
}

func activateIndependentControlPlanesWithPin(
	ctx context.Context,
	prepared independentPreparedQuorum,
	pin genesisbootstrap.VerifiedGenesisPin,
) error {
	if pin.GenesisEpoch() == 0 {
		return fmt.Errorf("verified Genesis pin is required for independent live quorum activation")
	}
	if pin.GenesisEpoch() != prepared.genesisEpoch {
		return fmt.Errorf(
			"verified Genesis epoch=%d prepared quorum epoch=%d",
			pin.GenesisEpoch(),
			prepared.genesisEpoch,
		)
	}
	if pin.CapabilityEnvelopeHash() != prepared.envelopeHash {
		return fmt.Errorf(
			"verified Genesis capability envelope hash=%q prepared=%q",
			pin.CapabilityEnvelopeHash(),
			prepared.envelopeHash,
		)
	}
	binding, err := pin.ParseQuorumBinding(prepared.envelope)
	if err != nil {
		return fmt.Errorf("bind live quorum to verified Genesis: %w", err)
	}
	activePolicy, err := binding.ActivePolicy(pin.GenesisEpoch())
	if err != nil {
		return err
	}

	targets := make([]independentControlPlaneTarget, 0, len(prepared.specs))
	for i, spec := range prepared.specs {
		if i >= len(prepared.members) {
			return fmt.Errorf("prepared live quorum member count mismatch")
		}
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
		member := prepared.members[i]
		if member.spec.ID != spec.ID {
			return fmt.Errorf(
				"prepared live quorum member[%d]=%q want=%q",
				i,
				member.spec.ID,
				spec.ID,
			)
		}
		targets = append(targets, independentControlPlaneTarget{
			member:    member,
			config:    config,
			client:    client,
			chaosPath: requireEnv(spec.chaosEnv),
			domainID:  spec.domainID,
		})
	}
	if err := requireDistinctControlPlanes(targets); err != nil {
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
		GenesisEpoch:             pin.GenesisEpoch(),
		CapabilityEnvelopeBase64: base64.StdEncoding.EncodeToString(prepared.envelope),
		CapabilityEnvelopeHash:   pin.CapabilityEnvelopeHash(),
		JournalID:                journalID,
		WorkloadSignerKeyID:      prepared.workloadKeyID,
		WorkloadSignerPublicKey:  base64.StdEncoding.EncodeToString(prepared.workloadPublic),
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
	return writeJSONFile(requireEnv("LIVE_QUORUM_CLIENT_BUNDLE"), output, 0o600)
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
