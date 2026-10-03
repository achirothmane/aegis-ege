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
	independentPreparedBundleVersion = "aegis-ege/live-independent-quorum-prepared/v1"
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
	genesisEpoch   uint64
	workloadKeyID  string
	workloadPublic ed25519.PublicKey
	members        []memberMaterial
	envelope       []byte
	envelopeHash   string
	specs          []independentControlPlaneSpec
}

type independentPreparedQuorumFile struct {
	Version                  string                   `json:"version"`
	GenesisEpoch             uint64                   `json:"genesis_epoch"`
	WorkloadSignerKeyID      string                   `json:"workload_signer_key_id"`
	WorkloadSignerPublicKey  string                   `json:"workload_signer_public_key"`
	CapabilityEnvelopeBase64 string                   `json:"capability_envelope_base64"`
	CapabilityEnvelopeHash   string                   `json:"capability_envelope_hash"`
	Members                  []preparedMemberMaterial `json:"members"`
}

type preparedMemberMaterial struct {
	ID                    string                             `json:"id"`
	Suffix                string                             `json:"suffix"`
	NodePort              int32                              `json:"node_port"`
	StateName             string                             `json:"state_name"`
	DeploymentName        string                             `json:"deployment_name"`
	ServiceName           string                             `json:"service_name"`
	ServiceAccount        string                             `json:"service_account"`
	WitnessTLSSecretName  string                             `json:"witness_tls_secret_name"`
	WitnessConfigName     string                             `json:"witness_config_name"`
	WitnessTLSServerName  string                             `json:"witness_tls_server_name"`
	ExternalEndpoint      string                             `json:"external_endpoint"`
	WitnessCertPEM        string                             `json:"witness_cert_pem"`
	WitnessKeyPEM         string                             `json:"witness_key_pem"`
	SignerSecretName      string                             `json:"signer_secret_name"`
	SignerDeployment      string                             `json:"signer_deployment"`
	SignerService         string                             `json:"signer_service"`
	SignerTLSServerName   string                             `json:"signer_tls_server_name"`
	SignerEndpoint        string                             `json:"signer_endpoint"`
	SignerCertPEM         string                             `json:"signer_cert_pem"`
	SignerKeyPEM          string                             `json:"signer_key_pem"`
	SignerPublic          string                             `json:"signer_public"`
	SignerPrivate         string                             `json:"signer_private"`
	SignerKeyID           string                             `json:"signer_key_id"`
	OwnerPublic           string                             `json:"owner_public"`
	OwnerPrivate          string                             `json:"owner_private"`
	OwnerKeyID            string                             `json:"owner_key_id"`
	Manifest              journal.WitnessTrustManifest       `json:"manifest"`
	SignedTrust           journal.SignedWitnessTrustManifest `json:"signed_trust"`
	ManifestHash          string                             `json:"manifest_hash"`
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
	phase := strings.TrimSpace(os.Getenv("LIVE_QUORUM_PROVISION_PHASE"))
	preparedPath := strings.TrimSpace(os.Getenv("LIVE_QUORUM_PREPARED_BUNDLE"))
	if preparedPath == "" {
		return fmt.Errorf("LIVE_QUORUM_PREPARED_BUNDLE is required")
	}
	switch phase {
	case "prepare":
		prepared, err := prepareIndependentQuorum()
		if err != nil {
			return err
		}
		return writeIndependentPreparedQuorum(preparedPath, prepared)
	case "activate":
		prepared, err := loadIndependentPreparedQuorum(preparedPath)
		if err != nil {
			return err
		}
		pin, err := loadVerifiedIndependentGenesisPin(ctx)
		if err != nil {
			return err
		}
		return activateIndependentControlPlanesWithPin(ctx, prepared, pin)
	default:
		return fmt.Errorf("LIVE_QUORUM_PROVISION_PHASE must be prepare or activate")
	}
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
		GovernedHistories: journal.GovernedHistoryTrustPolicy{
			Protocol: journal.GovernedHistoryTrustPolicyVersion,
			Histories: []journal.GovernedHistoryIdentity{{
				Purpose:   historyPurpose,
				JournalID: journalID,
			}},
		},
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


func writeIndependentPreparedQuorum(
	path string,
	prepared independentPreparedQuorum,
) error {
	file := independentPreparedQuorumFile{
		Version:                  independentPreparedBundleVersion,
		GenesisEpoch:             prepared.genesisEpoch,
		WorkloadSignerKeyID:      prepared.workloadKeyID,
		WorkloadSignerPublicKey:  base64.StdEncoding.EncodeToString(prepared.workloadPublic),
		CapabilityEnvelopeBase64: base64.StdEncoding.EncodeToString(prepared.envelope),
		CapabilityEnvelopeHash:   prepared.envelopeHash,
		Members:                  make([]preparedMemberMaterial, 0, len(prepared.members)),
	}
	for _, member := range prepared.members {
		file.Members = append(file.Members, preparedMemberFromMaterial(member))
	}
	return writeJSONFile(path, file, 0o600)
}

func loadIndependentPreparedQuorum(
	path string,
) (independentPreparedQuorum, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return independentPreparedQuorum{}, fmt.Errorf("read prepared live quorum: %w", err)
	}
	var file independentPreparedQuorumFile
	if err := json.Unmarshal(payload, &file); err != nil {
		return independentPreparedQuorum{}, fmt.Errorf("decode prepared live quorum: %w", err)
	}
	if file.Version != independentPreparedBundleVersion ||
		file.GenesisEpoch != independentGenesisEpoch ||
		file.WorkloadSignerKeyID == "" ||
		file.CapabilityEnvelopeHash == "" ||
		len(file.Members) != 3 {
		return independentPreparedQuorum{}, fmt.Errorf("prepared live quorum metadata is invalid")
	}
	workloadRaw, err := base64.StdEncoding.DecodeString(file.WorkloadSignerPublicKey)
	if err != nil || len(workloadRaw) != ed25519.PublicKeySize {
		return independentPreparedQuorum{}, fmt.Errorf("prepared workload signer public key is invalid")
	}
	workloadPublic := ed25519.PublicKey(workloadRaw)
	workloadKeyID, err := kernelfabric.BootstrapKeyID(workloadPublic)
	if err != nil || workloadKeyID != file.WorkloadSignerKeyID {
		return independentPreparedQuorum{}, fmt.Errorf("prepared workload signer identity mismatch")
	}
	envelope, err := base64.StdEncoding.DecodeString(file.CapabilityEnvelopeBase64)
	if err != nil || len(envelope) == 0 {
		return independentPreparedQuorum{}, fmt.Errorf("prepared capability envelope is invalid")
	}
	if sha256Digest(envelope) != file.CapabilityEnvelopeHash {
		return independentPreparedQuorum{}, fmt.Errorf("prepared capability envelope hash mismatch")
	}

	specs := independentControlPlaneSpecs()
	members := make([]memberMaterial, 0, len(file.Members))
	for i, encoded := range file.Members {
		member, err := materialFromPreparedMember(encoded)
		if err != nil {
			return independentPreparedQuorum{}, fmt.Errorf("prepared member %d: %w", i, err)
		}
		if i >= len(specs) ||
			member.spec.ID != specs[i].ID ||
			member.spec.Suffix != specs[i].Suffix ||
			member.spec.NodePort != specs[i].NodePort {
			return independentPreparedQuorum{}, fmt.Errorf("prepared member ordering or identity mismatch")
		}
		members = append(members, member)
	}

	return independentPreparedQuorum{
		genesisEpoch:   file.GenesisEpoch,
		workloadKeyID:  file.WorkloadSignerKeyID,
		workloadPublic: append(ed25519.PublicKey(nil), workloadPublic...),
		members:        members,
		envelope:       envelope,
		envelopeHash:   file.CapabilityEnvelopeHash,
		specs:          specs,
	}, nil
}

func preparedMemberFromMaterial(member memberMaterial) preparedMemberMaterial {
	return preparedMemberMaterial{
		ID:                   member.spec.ID,
		Suffix:               member.spec.Suffix,
		NodePort:             member.spec.NodePort,
		StateName:            member.stateName,
		DeploymentName:       member.deploymentName,
		ServiceName:          member.serviceName,
		ServiceAccount:       member.serviceAccount,
		WitnessTLSSecretName: member.witnessTLSSecretName,
		WitnessConfigName:    member.witnessConfigName,
		WitnessTLSServerName: member.witnessTLSServerName,
		ExternalEndpoint:     member.externalEndpoint,
		WitnessCertPEM:       string(member.witnessCertPEM),
		WitnessKeyPEM:        string(member.witnessKeyPEM),
		SignerSecretName:     member.signerSecretName,
		SignerDeployment:     member.signerDeployment,
		SignerService:        member.signerService,
		SignerTLSServerName:  member.signerTLSServerName,
		SignerEndpoint:       member.signerEndpoint,
		SignerCertPEM:        string(member.signerCertPEM),
		SignerKeyPEM:         string(member.signerKeyPEM),
		SignerPublic:         base64.StdEncoding.EncodeToString(member.signerPublic),
		SignerPrivate:        base64.StdEncoding.EncodeToString(member.signerPrivate),
		SignerKeyID:          member.signerKeyID,
		OwnerPublic:          base64.StdEncoding.EncodeToString(member.ownerPublic),
		OwnerPrivate:         base64.StdEncoding.EncodeToString(member.ownerPrivate),
		OwnerKeyID:           member.ownerKeyID,
		Manifest:             member.manifest,
		SignedTrust:          member.signedTrust,
		ManifestHash:         member.manifestHash,
	}
}

func materialFromPreparedMember(
	prepared preparedMemberMaterial,
) (memberMaterial, error) {
	signerPublicRaw, err := base64.StdEncoding.DecodeString(prepared.SignerPublic)
	if err != nil || len(signerPublicRaw) != ed25519.PublicKeySize {
		return memberMaterial{}, fmt.Errorf("signer public key is invalid")
	}
	signerPrivateRaw, err := base64.StdEncoding.DecodeString(prepared.SignerPrivate)
	if err != nil || len(signerPrivateRaw) != ed25519.PrivateKeySize {
		return memberMaterial{}, fmt.Errorf("signer private key is invalid")
	}
	ownerPublicRaw, err := base64.StdEncoding.DecodeString(prepared.OwnerPublic)
	if err != nil || len(ownerPublicRaw) != ed25519.PublicKeySize {
		return memberMaterial{}, fmt.Errorf("owner public key is invalid")
	}
	ownerPrivateRaw, err := base64.StdEncoding.DecodeString(prepared.OwnerPrivate)
	if err != nil || len(ownerPrivateRaw) != ed25519.PrivateKeySize {
		return memberMaterial{}, fmt.Errorf("owner private key is invalid")
	}
	manifestHash, err := journal.WitnessTrustManifestDigest(prepared.Manifest)
	if err != nil || manifestHash != prepared.ManifestHash {
		return memberMaterial{}, fmt.Errorf("witness trust manifest hash mismatch")
	}
	signerPublic := ed25519.PublicKey(signerPublicRaw)
	signerKeyID, err := kernelfabric.BootstrapKeyID(signerPublic)
	if err != nil || signerKeyID != prepared.SignerKeyID {
		return memberMaterial{}, fmt.Errorf("signer identity mismatch")
	}
	ownerPublic := ed25519.PublicKey(ownerPublicRaw)
	ownerKeyID, err := kernelfabric.BootstrapKeyID(ownerPublic)
	if err != nil || ownerKeyID != prepared.OwnerKeyID {
		return memberMaterial{}, fmt.Errorf("owner identity mismatch")
	}
	return memberMaterial{
		spec:                 memberSpec{ID: prepared.ID, Suffix: prepared.Suffix, NodePort: prepared.NodePort},
		stateName:            prepared.StateName,
		deploymentName:       prepared.DeploymentName,
		serviceName:          prepared.ServiceName,
		serviceAccount:       prepared.ServiceAccount,
		witnessTLSSecretName: prepared.WitnessTLSSecretName,
		witnessConfigName:    prepared.WitnessConfigName,
		witnessTLSServerName: prepared.WitnessTLSServerName,
		externalEndpoint:     prepared.ExternalEndpoint,
		witnessCertPEM:       []byte(prepared.WitnessCertPEM),
		witnessKeyPEM:        []byte(prepared.WitnessKeyPEM),
		signerSecretName:     prepared.SignerSecretName,
		signerDeployment:     prepared.SignerDeployment,
		signerService:        prepared.SignerService,
		signerTLSServerName:  prepared.SignerTLSServerName,
		signerEndpoint:       prepared.SignerEndpoint,
		signerCertPEM:        []byte(prepared.SignerCertPEM),
		signerKeyPEM:         []byte(prepared.SignerKeyPEM),
		signerPublic:         append(ed25519.PublicKey(nil), signerPublic...),
		signerPrivate:        append(ed25519.PrivateKey(nil), signerPrivateRaw...),
		signerKeyID:          prepared.SignerKeyID,
		ownerPublic:          append(ed25519.PublicKey(nil), ownerPublic...),
		ownerPrivate:         append(ed25519.PrivateKey(nil), ownerPrivateRaw...),
		ownerKeyID:           prepared.OwnerKeyID,
		manifest:             prepared.Manifest,
		signedTrust:          prepared.SignedTrust,
		manifestHash:         prepared.ManifestHash,
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
