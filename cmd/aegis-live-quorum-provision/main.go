package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	authenticationv1 "k8s.io/api/authentication/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	bundleVersion = "aegis-ege/live-external-head-quorum-client/v1"
	namespace     = "aegis-capability-witness"
	journalID      = "cross-cluster-capability-root"
	historyPurpose = "capability-root-history"
	rootKeyID      = "aegis-ege/capability-root-head/v1"
	genesisEpoch  = uint64(1)

	witnessImage = "aegis-external-head-witness:ci"
	signerImage  = "aegis-external-head-witness-signer:ci"
)

type liveQuorumBundle struct {
	Version                  string             `json:"version"`
	GenesisEpoch             uint64             `json:"genesis_epoch"`
	CapabilityEnvelopeBase64 string             `json:"capability_envelope_base64"`
	CapabilityEnvelopeHash   string             `json:"capability_envelope_hash"`
	JournalID                string             `json:"journal_id"`
	WorkloadSignerKeyID      string             `json:"workload_signer_key_id"`
	WorkloadSignerPublicKey  string             `json:"workload_signer_public_key"`
	Members                  []liveQuorumMember `json:"members"`
}

type liveQuorumMember struct {
	ID                    string                             `json:"id"`
	StateName             string                             `json:"state_name"`
	DeploymentName        string                             `json:"deployment_name"`
	SignerDeploymentName  string                             `json:"signer_deployment_name"`
	Endpoint              string                             `json:"endpoint"`
	TLSServerName         string                             `json:"tls_server_name"`
	CAPEM                 string                             `json:"ca_pem"`
	WitnessOwnerKeyID     string                             `json:"witness_owner_key_id"`
	WitnessOwnerPublicKey string                             `json:"witness_owner_public_key"`
	SignedTrust           journal.SignedWitnessTrustManifest `json:"signed_trust"`
}

type capabilityEnvelope struct {
	ExternalWitnessQuorum journal.QuorumTrustPolicy          `json:"external_witness_quorum"`
	GovernedHistories     journal.GovernedHistoryTrustPolicy `json:"governed_histories"`
}

type memberSpec struct {
	ID       string
	Suffix   string
	NodePort int32
}

type memberMaterial struct {
	spec memberSpec

	stateName            string
	deploymentName       string
	serviceName          string
	serviceAccount       string
	witnessTLSSecretName string
	witnessConfigName    string
	witnessTLSServerName string
	externalEndpoint     string
	witnessCertPEM       []byte
	witnessKeyPEM        []byte

	signerSecretName    string
	signerDeployment    string
	signerService       string
	signerTLSServerName string
	signerEndpoint      string
	signerCertPEM       []byte
	signerKeyPEM        []byte
	signerPublic        ed25519.PublicKey
	signerPrivate       ed25519.PrivateKey
	signerKeyID         string

	ownerPublic  ed25519.PublicKey
	ownerPrivate ed25519.PrivateKey
	ownerKeyID   string

	manifest     journal.WitnessTrustManifest
	signedTrust  journal.SignedWitnessTrustManifest
	manifestHash string
}

func main() {
	ctx := context.Background()
	if strings.TrimSpace(os.Getenv("LIVE_QUORUM_TOPOLOGY")) == "independent-control-planes" {
		must(runIndependentControlPlanes(ctx))
		return
	}

	adminPath := requireEnv("WITNESS_ADMIN_KUBECONFIG")
	bundlePath := requireEnv("LIVE_QUORUM_CLIENT_BUNDLE")
	chaosKubeconfigPath := requireEnv("LIVE_QUORUM_CHAOS_KUBECONFIG")

	config, err := clientcmd.BuildConfigFromFlags("", adminPath)
	must(err)
	client, err := kubernetes.NewForConfig(config)
	must(err)
	must(ensureNamespace(ctx, client, namespace))

	workloadPublic, workloadPrivate, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	workloadKeyID, err := kernelfabric.BootstrapKeyID(workloadPublic)
	must(err)

	specs := []memberSpec{
		{ID: "witness-a", Suffix: "a", NodePort: 30445},
		{ID: "witness-b", Suffix: "b", NodePort: 30446},
		{ID: "witness-c", Suffix: "c", NodePort: 30447},
	}
	members := make([]memberMaterial, 0, len(specs))
	for _, spec := range specs {
		material, err := newMemberMaterial(
			spec,
			workloadKeyID,
			workloadPrivate,
		)
		must(err)
		members = append(members, material)
	}

	policy := journal.QuorumTrustPolicy{
		Protocol:  journal.QuorumTrustPolicyVersion,
		Threshold: 2,
		Members:   make([]journal.QuorumTrustPolicyMember, 0, len(members)),
	}
	for _, member := range members {
		policy.Members = append(
			policy.Members,
			journal.QuorumTrustPolicyMember{
				ID:                member.spec.ID,
				TrustManifestHash: member.manifestHash,
			},
		)
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
	must(err)
	envelopeHash := sha256Digest(envelope)
	binding, err := journal.ParseGenesisQuorumBinding(envelope, envelopeHash)
	must(err)
	historyBinding, err := journal.ParseGenesisHistoryBinding(
		envelope,
		envelopeHash,
		historyPurpose,
	)
	must(err)
	if historyBinding.JournalID() != journalID {
		must(fmt.Errorf(
			"Genesis history lineage=%q want provisioned %q",
			historyBinding.JournalID(),
			journalID,
		))
	}
	activePolicy, err := binding.ActivePolicy(genesisEpoch)
	must(err)

	for i := range members {
		must(provisionMember(ctx, client, &members[i], activePolicy))
	}
	for _, member := range members {
		must(waitDeployment(ctx, client, member.signerDeployment))
		must(waitDeployment(ctx, client, member.deploymentName))
	}

	chaosToken, err := provisionChaosServiceAccount(ctx, client, members)
	must(err)
	must(writeRuntimeKubeconfig(
		chaosKubeconfigPath,
		config,
		chaosToken,
		namespace,
	))

	output := liveQuorumBundle{
		Version:                  bundleVersion,
		GenesisEpoch:             genesisEpoch,
		CapabilityEnvelopeBase64: base64.StdEncoding.EncodeToString(envelope),
		CapabilityEnvelopeHash:   envelopeHash,
		JournalID:                journalID,
		WorkloadSignerKeyID:      workloadKeyID,
		WorkloadSignerPublicKey:  base64.StdEncoding.EncodeToString(workloadPublic),
		Members:                  make([]liveQuorumMember, 0, len(members)),
	}
	for _, member := range members {
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
	must(writeJSONFile(bundlePath, output, 0o600))
}

func newMemberMaterial(
	spec memberSpec,
	workloadKeyID string,
	workloadPrivate ed25519.PrivateKey,
) (memberMaterial, error) {
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return memberMaterial{}, err
	}
	signerKeyID, err := kernelfabric.BootstrapKeyID(signerPublic)
	if err != nil {
		return memberMaterial{}, err
	}
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return memberMaterial{}, err
	}
	ownerKeyID, err := kernelfabric.BootstrapKeyID(ownerPublic)
	if err != nil {
		return memberMaterial{}, err
	}

	witnessTLSServerName := fmt.Sprintf("aegis-head-witness-%s.local", spec.Suffix)
	witnessCertPEM, witnessKeyPEM, err := newTLSCertificate(witnessTLSServerName)
	if err != nil {
		return memberMaterial{}, err
	}
	signerTLSServerName := fmt.Sprintf(
		"aegis-external-head-witness-signer-%s.local",
		spec.Suffix,
	)
	signerCertPEM, signerKeyPEM, err := newTLSCertificate(signerTLSServerName)
	if err != nil {
		return memberMaterial{}, err
	}

	signerService := fmt.Sprintf("live-quorum-signer-%s", spec.Suffix)
	signerEndpoint := fmt.Sprintf(
		"https://%s.%s.svc:9444",
		signerService,
		namespace,
	)
	externalEndpoint := fmt.Sprintf("https://127.0.0.1:%d", spec.NodePort)
	manifest := journal.WitnessTrustManifest{
		Version:             journal.WitnessTrustManifestVersion,
		TrustEpoch:          1,
		WorkloadPrincipal:   "aegis-live-quorum-runtime",
		WitnessPrincipal:    spec.ID,
		Endpoint:            externalEndpoint,
		WitnessRuntimeKeyID: signerKeyID,
		WitnessRuntimeKey:   base64.StdEncoding.EncodeToString(signerPublic),
	}
	signedTrust, err := journal.SignWitnessTrustManifest(
		manifest,
		workloadKeyID,
		workloadPrivate,
		ownerKeyID,
		ownerPrivate,
	)
	if err != nil {
		return memberMaterial{}, err
	}
	manifestHash, err := journal.WitnessTrustManifestDigest(manifest)
	if err != nil {
		return memberMaterial{}, err
	}

	return memberMaterial{
		spec:                 spec,
		stateName:            fmt.Sprintf("live-quorum-state-%s", spec.Suffix),
		deploymentName:       fmt.Sprintf("live-quorum-witness-%s", spec.Suffix),
		serviceName:          fmt.Sprintf("live-quorum-witness-%s", spec.Suffix),
		serviceAccount:       fmt.Sprintf("live-quorum-witness-%s", spec.Suffix),
		witnessTLSSecretName: fmt.Sprintf("live-quorum-witness-%s-tls", spec.Suffix),
		witnessConfigName:    fmt.Sprintf("live-quorum-witness-%s-config", spec.Suffix),
		witnessTLSServerName: witnessTLSServerName,
		externalEndpoint:     externalEndpoint,
		witnessCertPEM:       witnessCertPEM,
		witnessKeyPEM:        witnessKeyPEM,
		signerSecretName:     fmt.Sprintf("live-quorum-signer-%s-secret", spec.Suffix),
		signerDeployment:     fmt.Sprintf("live-quorum-signer-%s", spec.Suffix),
		signerService:        signerService,
		signerTLSServerName:  signerTLSServerName,
		signerEndpoint:       signerEndpoint,
		signerCertPEM:        signerCertPEM,
		signerKeyPEM:         signerKeyPEM,
		signerPublic:         signerPublic,
		signerPrivate:        signerPrivate,
		signerKeyID:          signerKeyID,
		ownerPublic:          ownerPublic,
		ownerPrivate:         ownerPrivate,
		ownerKeyID:           ownerKeyID,
		manifest:             manifest,
		signedTrust:          signedTrust,
		manifestHash:         manifestHash,
	}, nil
}

func provisionMember(
	ctx context.Context,
	client kubernetes.Interface,
	member *memberMaterial,
	policy journal.QuorumPolicyState,
) error {
	if err := initializeState(ctx, client, *member, policy); err != nil {
		return err
	}
	if err := provisionSigner(ctx, client, *member); err != nil {
		return err
	}
	if err := provisionWitness(ctx, client, *member, policy); err != nil {
		return err
	}
	return nil
}

func initializeState(
	ctx context.Context,
	client kubernetes.Interface,
	member memberMaterial,
	policy journal.QuorumPolicyState,
) error {
	store, err := journal.NewKubernetesGovernedWitnessStateStore(
		client,
		namespace,
		member.stateName,
	)
	if err != nil {
		return err
	}
	state, err := journal.InitializeGovernedWitnessState(ctx, store, policy)
	if err != nil {
		return err
	}
	if state.Heads == nil {
		state.Heads = map[string]journal.ExternalHead{}
	}
	if _, exists := state.Heads[journalID]; exists {
		return nil
	}
	state.Heads[journalID] = journal.ExternalHead{
		JournalID: journalID,
		Sequence:  0,
		HeadHash:  "",
		KeyID:     rootKeyID,
	}
	_, err = store.CompareAndSwap(ctx, state.StoreVersion, state)
	return err
}

func provisionSigner(
	ctx context.Context,
	client kubernetes.Interface,
	member memberMaterial,
) error {
	immutable := true
	if _, err := client.CoreV1().Secrets(namespace).Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.signerSecretName,
				Namespace: namespace,
			},
			Immutable: &immutable,
			StringData: map[string]string{
				"head-witness-signing-private-key": base64.StdEncoding.EncodeToString(member.signerPrivate),
				"tls.crt":                          string(member.signerCertPEM),
				"tls.key":                          string(member.signerKeyPEM),
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	falseValue := false
	replicas := int32(1)
	mode := int32(0o400)
	labels := map[string]string{"app": member.signerDeployment}
	if _, err := client.AppsV1().Deployments(namespace).Create(
		ctx,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.signerDeployment,
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken: &falseValue,
						Containers: []corev1.Container{{
							Name:            "signer",
							Image:           signerImage,
							ImagePullPolicy: corev1.PullNever,
							Env: []corev1.EnvVar{
								{
									Name:  "HEAD_WITNESS_SIGNER_PRIVATE_KEY_PATH",
									Value: "/run/aegis-head-signer/secret/head-witness-signing-private-key",
								},
								{Name: "TLS_CERT_PATH", Value: "/run/aegis-head-signer/secret/tls.crt"},
								{Name: "TLS_KEY_PATH", Value: "/run/aegis-head-signer/secret/tls.key"},
								{Name: "LISTEN_ADDR", Value: ":9444"},
							},
							Ports: []corev1.ContainerPort{{
								Name:          "https",
								ContainerPort: 9444,
								Protocol:      corev1.ProtocolTCP,
							}},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(9444),
									},
								},
								PeriodSeconds:    1,
								FailureThreshold: 30,
							},
							VolumeMounts: []corev1.VolumeMount{{
								Name:      "signer-secret",
								MountPath: "/run/aegis-head-signer/secret",
								ReadOnly:  true,
							}},
						}},
						Volumes: []corev1.Volume{{
							Name: "signer-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  member.signerSecretName,
									DefaultMode: &mode,
								},
							},
						}},
					},
				},
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	if _, err := client.CoreV1().Services(namespace).Create(
		ctx,
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.signerService,
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Selector: labels,
				Ports: []corev1.ServicePort{{
					Name:       "https",
					Protocol:   corev1.ProtocolTCP,
					Port:       9444,
					TargetPort: intstr.FromInt(9444),
				}},
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func provisionWitness(
	ctx context.Context,
	client kubernetes.Interface,
	member memberMaterial,
	policy journal.QuorumPolicyState,
) error {
	if err := ensureWitnessServiceAccount(ctx, client, member); err != nil {
		return err
	}

	immutable := true
	if _, err := client.CoreV1().Secrets(namespace).Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.witnessTLSSecretName,
				Namespace: namespace,
			},
			Immutable: &immutable,
			StringData: map[string]string{
				"tls.crt": string(member.witnessCertPEM),
				"tls.key": string(member.witnessKeyPEM),
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	policyPayload, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	if _, err := client.CoreV1().ConfigMaps(namespace).Create(
		ctx,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.witnessConfigName,
				Namespace: namespace,
			},
			Immutable: &immutable,
			Data: map[string]string{
				"policy.json":            string(policyPayload),
				"signer-public-key":      base64.StdEncoding.EncodeToString(member.signerPublic),
				"signer-ca.pem":          string(member.signerCertPEM),
				"signer-endpoint":        member.signerEndpoint,
				"signer-tls-server-name": member.signerTLSServerName,
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	replicas := int32(1)
	mode := int32(0o400)
	labels := map[string]string{"app": member.deploymentName}
	if _, err := client.AppsV1().Deployments(namespace).Create(
		ctx,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.deploymentName,
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec: corev1.PodSpec{
						ServiceAccountName: member.serviceAccount,
						Containers: []corev1.Container{{
							Name:            "witness",
							Image:           witnessImage,
							ImagePullPolicy: corev1.PullNever,
							Env: []corev1.EnvVar{
								{Name: "WITNESS_STATE_NAMESPACE", Value: namespace},
								{Name: "WITNESS_STATE_NAME", Value: member.stateName},
								{Name: "WITNESS_KEY_ID", Value: member.signerKeyID},
								{
									Name:  "HEAD_WITNESS_SIGNER_PUBLIC_KEY_PATH",
									Value: "/run/aegis-head-witness/config/signer-public-key",
								},
								{
									Name:  "HEAD_WITNESS_SIGNER_TLS_CA_PATH",
									Value: "/run/aegis-head-witness/config/signer-ca.pem",
								},
								{Name: "HEAD_WITNESS_SIGNER_ENDPOINT", Value: member.signerEndpoint},
								{
									Name:  "HEAD_WITNESS_SIGNER_TLS_SERVER_NAME",
									Value: member.signerTLSServerName,
								},
								{
									Name:  "WITNESS_POLICY_PATH",
									Value: "/run/aegis-head-witness/config/policy.json",
								},
								{Name: "TLS_CERT_PATH", Value: "/run/aegis-head-witness/secret/tls.crt"},
								{Name: "TLS_KEY_PATH", Value: "/run/aegis-head-witness/secret/tls.key"},
								{Name: "LISTEN_ADDR", Value: ":8443"},
							},
							Ports: []corev1.ContainerPort{{
								Name:          "https",
								ContainerPort: 8443,
								Protocol:      corev1.ProtocolTCP,
							}},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthz",
										Port:   intstr.FromInt(8443),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								PeriodSeconds:    1,
								FailureThreshold: 30,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret",
									MountPath: "/run/aegis-head-witness/secret",
									ReadOnly:  true,
								},
								{
									Name:      "config",
									MountPath: "/run/aegis-head-witness/config",
									ReadOnly:  true,
								},
							},
						}},
						Volumes: []corev1.Volume{
							{
								Name: "secret",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName:  member.witnessTLSSecretName,
										DefaultMode: &mode,
									},
								},
							},
							{
								Name: "config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: member.witnessConfigName,
										},
										DefaultMode: &mode,
									},
								},
							},
						},
					},
				},
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	if _, err := client.CoreV1().Services(namespace).Create(
		ctx,
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.serviceName,
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeNodePort,
				Selector: labels,
				Ports: []corev1.ServicePort{{
					Name:       "https",
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt(8443),
					NodePort:   member.spec.NodePort,
				}},
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ensureWitnessServiceAccount(
	ctx context.Context,
	client kubernetes.Interface,
	member memberMaterial,
) error {
	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(
		ctx,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      member.serviceAccount,
				Namespace: namespace,
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	roleName := member.serviceAccount + "-state"
	if _, err := client.RbacV1().Roles(namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			Rules: []rbacv1.PolicyRule{{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{member.stateName},
				Verbs:         []string{"get", "update"},
			}},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	if _, err := client.RbacV1().RoleBindings(namespace).Create(
		ctx,
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      member.serviceAccount,
				Namespace: namespace,
			}},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func provisionChaosServiceAccount(
	ctx context.Context,
	client kubernetes.Interface,
	members []memberMaterial,
) (string, error) {
	const name = "live-quorum-chaos"
	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(
		ctx,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}

	witnessDeployments := make([]string, 0, len(members))
	allDeployments := make([]string, 0, len(members)*2)
	for _, member := range members {
		witnessDeployments = append(witnessDeployments, member.deploymentName)
		allDeployments = append(
			allDeployments,
			member.deploymentName,
			member.signerDeployment,
		)
	}
	roleName := name + "-runtime"
	if _, err := client.RbacV1().Roles(namespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployments"},
					ResourceNames: allDeployments,
					Verbs:         []string{"get"},
				},
				{
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployments/scale"},
					ResourceNames: witnessDeployments,
					Verbs:         []string{"get", "update", "patch"},
				},
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}
	if _, err := client.RbacV1().RoleBindings(namespace).Create(
		ctx,
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: namespace},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			}},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}
	token, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		name,
		&authenticationv1.TokenRequest{},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", err
	}
	if token.Status.Token == "" {
		return "", errors.New("live quorum chaos service account token is empty")
	}
	return token.Status.Token, nil
}

func waitDeployment(
	ctx context.Context,
	client kubernetes.Interface,
	name string,
) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		deployment, err := client.AppsV1().Deployments(namespace).Get(
			ctx,
			name,
			metav1.GetOptions{},
		)
		if err != nil {
			return err
		}
		if deployment.Status.ReadyReplicas >= 1 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("deployment %s did not become ready", name)
		}
		time.Sleep(time.Second)
	}
}

func ensureNamespace(
	ctx context.Context,
	client kubernetes.Interface,
	name string,
) error {
	if _, err := client.CoreV1().Namespaces().Get(
		ctx,
		name,
		metav1.GetOptions{},
	); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	_, err := client.CoreV1().Namespaces().Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}},
		metav1.CreateOptions{},
	)
	return err
}

func newTLSCertificate(serverName string) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		publicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
	}), pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateDER,
	}), nil
}

func writeRuntimeKubeconfig(
	path string,
	base *rest.Config,
	token string,
	namespace string,
) error {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["runtime"] = &clientcmdapi.Cluster{
		Server:                   base.Host,
		CertificateAuthority:     base.CAFile,
		CertificateAuthorityData: append([]byte(nil), base.CAData...),
		InsecureSkipTLSVerify:    base.Insecure,
		TLSServerName:            base.ServerName,
	}
	cfg.AuthInfos["runtime"] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts["runtime"] = &clientcmdapi.Context{
		Cluster:   "runtime",
		AuthInfo:  "runtime",
		Namespace: namespace,
	}
	cfg.CurrentContext = "runtime"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return clientcmd.WriteToFile(*cfg, path)
}

func writeJSONFile(path string, value any, mode os.FileMode) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(payload, '\n'), mode)
}

func sha256Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requireEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		panic(name + " is required")
	}
	return value
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
