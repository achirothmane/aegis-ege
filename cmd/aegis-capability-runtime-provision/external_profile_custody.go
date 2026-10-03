package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/achirothmane/aegis-ege/internal/recoverywitnessprofile"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const preparedTaintRecoveryWitnessVersion = "aegis.ege/taint-recovery-prepared-witness/v2"

type preparedTaintRecoveryWitness struct {
	Version                         string                                             `json:"version"`
	AuthorityPrivateKey             string                                             `json:"authority_private_key"`
	SignedTrust                     kernelfabric.SignedTaintRecoveryTrustManifest     `json:"signed_trust"`
	TrustSignerPublicKey            string                                             `json:"trust_signer_public_key"`
	Policy                          recoverywitnessprofile.StaticPolicy                `json:"policy"`
	WitnessCAPEM                    string                                             `json:"witness_ca_pem"`
	WitnessTLSKeyPEM                string                                             `json:"witness_tls_key_pem"`
	WitnessTLSServerName            string                                             `json:"witness_tls_server_name"`
	WitnessSignerEndpoint           string                                             `json:"witness_signer_endpoint"`
	WitnessSignerCAPEM              string                                             `json:"witness_signer_ca_pem"`
	WitnessSignerTLSServerName      string                                             `json:"witness_signer_tls_server_name"`
	GenesisCapabilityEnvelopeBase64 string                                             `json:"genesis_capability_envelope_base64"`
	GenesisCapabilityEnvelopeHash   string                                             `json:"genesis_capability_envelope_hash"`
	UnsignedWitnessProfile          kernelfabric.ExternalRecoveryWitnessProfile       `json:"unsigned_witness_profile"`
}

func prepareTaintRecoveryWitness(
	preparedBundlePath string,
	unsignedProfilePath string,
	profileAuthorityPublicKeyPath string,
	witnessPublicKeyPath string,
	witnessSignerEndpointPath string,
	witnessSignerTLSCertPath string,
	witnessSignerTLSServerNamePath string,
) error {
	profileAuthorityPublic, err := readEd25519PublicKey(profileAuthorityPublicKeyPath)
	if err != nil {
		return fmt.Errorf("read external profile authority public key: %w", err)
	}
	witnessPublic, err := readEd25519PublicKey(witnessPublicKeyPath)
	if err != nil {
		return fmt.Errorf("read external witness signer public key: %w", err)
	}
	witnessSignerEndpoint, err := readTrimmedFile(witnessSignerEndpointPath)
	if err != nil {
		return fmt.Errorf("read witness signer endpoint: %w", err)
	}
	witnessSignerCAPEM, err := os.ReadFile(witnessSignerTLSCertPath)
	if err != nil {
		return fmt.Errorf("read witness signer TLS certificate: %w", err)
	}
	witnessSignerTLSServerName, err := readTrimmedFile(witnessSignerTLSServerNamePath)
	if err != nil {
		return fmt.Errorf("read witness signer TLS server name: %w", err)
	}
	if err := validateWitnessSignerPublicConfig(
		witnessSignerEndpoint,
		witnessSignerCAPEM,
		witnessSignerTLSServerName,
	); err != nil {
		return err
	}

	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	trustSignerPublic, trustSignerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	authorityKeyID, err := kernelfabric.BootstrapKeyID(authorityPublic)
	if err != nil {
		return err
	}
	recoveryWitnessKeyID, err := kernelfabric.BootstrapKeyID(witnessPublic)
	if err != nil {
		return err
	}
	trustSignerKeyID, err := kernelfabric.BootstrapKeyID(trustSignerPublic)
	if err != nil {
		return err
	}
	profileAuthorityKeyID, err := kernelfabric.BootstrapKeyID(profileAuthorityPublic)
	if err != nil {
		return err
	}
	if profileAuthorityKeyID == authorityKeyID ||
		profileAuthorityKeyID == recoveryWitnessKeyID ||
		profileAuthorityKeyID == trustSignerKeyID {
		return fmt.Errorf("external profile authority collapses a recovery role")
	}

	const trustEpoch uint64 = 1
	signedTrust, err := kernelfabric.SignTaintRecoveryTrustManifest(
		kernelfabric.TaintRecoveryTrustManifest{
			Version:            kernelfabric.TaintRecoveryTrustManifestVersion,
			TrustEpoch:         trustEpoch,
			AuthorityPrincipal: "workload/recovery-controller",
			AuthorityKeyID:     authorityKeyID,
			AuthorityPublicKey: base64.StdEncoding.EncodeToString(authorityPublic),
			WitnessPrincipal:   "witness/control-plane-b",
			WitnessKeyID:       recoveryWitnessKeyID,
			WitnessPublicKey:   base64.StdEncoding.EncodeToString(witnessPublic),
		},
		trustSignerPrivate,
	)
	if err != nil {
		return err
	}

	policy := recoverywitnessprofile.StaticPolicy{
		Version:       recoverywitnessprofile.StaticPolicyVersion,
		PolicyEpoch:   1,
		PlanDigest:    "sha256:" + strings.Repeat("c", 64),
		CgroupID:      4242,
		BPFFSRoot:     "/sys/fs/bpf/aegis-ege/taint-ci",
		BootIDHash:    "sha256:" + strings.Repeat("d", 64),
		FromEpoch:     11,
		ToEpoch:       12,
		ExpectedDirty: 7,
	}
	if err := policy.Validate(); err != nil {
		return err
	}

	tlsCertPEM, tlsKeyPEM, err := newWitnessTLSCertificate(recoveryWitnessServerName)
	if err != nil {
		return err
	}
	policyHash, err := policy.RecoveryWitnessPolicyHash()
	if err != nil {
		return err
	}
	tlsTrustAnchorHash, err := kernelfabric.TLSCertificatePEMSHA256(tlsCertPEM)
	if err != nil {
		return err
	}

	genesisCapabilityEnvelope, err := json.Marshal(recoveryGenesisCapabilityEnvelope{
		ExternalRecoveryWitness: kernelfabric.ExternalRecoveryWitnessGenesisPolicy{
			Protocol:                  kernelfabric.ExternalRecoveryWitnessGenesisPolicyVersion,
			ProfileAuthorityKeyID:     profileAuthorityKeyID,
			ProfileAuthorityPublicKey: base64.StdEncoding.EncodeToString(profileAuthorityPublic),
			RequiredWitnessID:         "witness/control-plane-b",
			TLSServerName:             recoveryWitnessServerName,
			MinimumProfileEpoch:       1,
			MinimumPolicyEpoch:        1,
		},
	})
	if err != nil {
		return err
	}
	genesisEnvelopeSum := sha256.Sum256(genesisCapabilityEnvelope)
	genesisCapabilityEnvelopeHash := "sha256:" + hex.EncodeToString(genesisEnvelopeSum[:])
	if _, err := kernelfabric.ParseGenesisExternalRecoveryWitnessBinding(
		genesisCapabilityEnvelope,
		genesisCapabilityEnvelopeHash,
	); err != nil {
		return fmt.Errorf("self-verify external witness Genesis binding: %w", err)
	}

	unsignedProfile := kernelfabric.ExternalRecoveryWitnessProfile{
		Version:              kernelfabric.ExternalRecoveryWitnessProfileVersion,
		ProfileEpoch:         1,
		WitnessID:            "witness/control-plane-b",
		WitnessKeyID:         recoveryWitnessKeyID,
		Endpoint:             recoveryWitnessExternalEndpoint,
		TLSTrustAnchorSHA256: tlsTrustAnchorHash,
		PolicyEpoch:          policy.PolicyEpoch,
		PolicyHash:           policyHash,
	}

	prepared := preparedTaintRecoveryWitness{
		Version:                         preparedTaintRecoveryWitnessVersion,
		AuthorityPrivateKey:             base64.StdEncoding.EncodeToString(authorityPrivate),
		SignedTrust:                     signedTrust,
		TrustSignerPublicKey:            base64.StdEncoding.EncodeToString(trustSignerPublic),
		Policy:                          policy,
		WitnessCAPEM:                    string(tlsCertPEM),
		WitnessTLSKeyPEM:                string(tlsKeyPEM),
		WitnessTLSServerName:            recoveryWitnessServerName,
		WitnessSignerEndpoint:           witnessSignerEndpoint,
		WitnessSignerCAPEM:              string(witnessSignerCAPEM),
		WitnessSignerTLSServerName:      witnessSignerTLSServerName,
		GenesisCapabilityEnvelopeBase64: base64.StdEncoding.EncodeToString(genesisCapabilityEnvelope),
		GenesisCapabilityEnvelopeHash:   genesisCapabilityEnvelopeHash,
		UnsignedWitnessProfile:          unsignedProfile,
	}
	if err := writeJSONFile(preparedBundlePath, prepared, 0o600); err != nil {
		return err
	}
	return writeJSONFile(unsignedProfilePath, unsignedProfile, 0o644)
}

type verifiedPreparedTaintRecoveryWitness struct {
	prepared                  preparedTaintRecoveryWitness
	signedWitnessProfile      kernelfabric.SignedExternalRecoveryWitnessProfile
	genesisCapabilityEnvelope []byte
}

func verifyPreparedTaintRecoveryWitness(
	preparedBundlePath string,
	signedProfilePath string,
) (*verifiedPreparedTaintRecoveryWitness, error) {
	var prepared preparedTaintRecoveryWitness
	if err := readJSONFile(preparedBundlePath, &prepared); err != nil {
		return nil, fmt.Errorf("read prepared recovery witness: %w", err)
	}
	if prepared.Version != preparedTaintRecoveryWitnessVersion {
		return nil, fmt.Errorf("unsupported prepared recovery witness version %q", prepared.Version)
	}

	var signedWitnessProfile kernelfabric.SignedExternalRecoveryWitnessProfile
	if err := readJSONFile(signedProfilePath, &signedWitnessProfile); err != nil {
		return nil, fmt.Errorf("read externally signed witness profile: %w", err)
	}

	trustSignerPublicRaw, err := base64.StdEncoding.DecodeString(prepared.TrustSignerPublicKey)
	if err != nil || len(trustSignerPublicRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid prepared trust signer public key")
	}
	root, err := kernelfabric.NewTaintRecoveryTrustRoot(
		prepared.SignedTrust,
		ed25519.PublicKey(trustSignerPublicRaw),
		prepared.SignedTrust.Manifest.TrustEpoch,
	)
	if err != nil {
		return nil, err
	}

	genesisCapabilityEnvelope, err := base64.StdEncoding.DecodeString(
		prepared.GenesisCapabilityEnvelopeBase64,
	)
	if err != nil {
		return nil, fmt.Errorf("decode prepared Genesis capability envelope: %w", err)
	}
	genesisBinding, err := kernelfabric.ParseGenesisExternalRecoveryWitnessBinding(
		genesisCapabilityEnvelope,
		prepared.GenesisCapabilityEnvelopeHash,
	)
	if err != nil {
		return nil, err
	}
	verifiedProfile, err := genesisBinding.VerifyProfile(signedWitnessProfile, root)
	if err != nil {
		return nil, fmt.Errorf("verify externally signed witness profile: %w", err)
	}
	if verifiedProfile.Profile() != prepared.UnsignedWitnessProfile {
		return nil, fmt.Errorf("externally signed witness profile differs from prepared activation request")
	}
	if genesisBinding.Policy().TLSServerName != prepared.WitnessTLSServerName {
		return nil, fmt.Errorf("prepared TLS server name differs from Genesis")
	}
	if err := genesisBinding.VerifyMountedTLSCertificate(
		[]byte(prepared.WitnessCAPEM),
		verifiedProfile,
	); err != nil {
		return nil, err
	}
	policyHash, err := prepared.Policy.RecoveryWitnessPolicyHash()
	if err != nil {
		return nil, err
	}
	if verifiedProfile.Profile().PolicyEpoch != prepared.Policy.PolicyEpoch ||
		verifiedProfile.Profile().PolicyHash != policyHash {
		return nil, fmt.Errorf("prepared witness policy differs from externally signed profile")
	}

	if err := validateWitnessSignerPublicConfig(
		prepared.WitnessSignerEndpoint,
		[]byte(prepared.WitnessSignerCAPEM),
		prepared.WitnessSignerTLSServerName,
	); err != nil {
		return nil, err
	}
	witnessPublicRaw, err := base64.StdEncoding.DecodeString(
		prepared.SignedTrust.Manifest.WitnessPublicKey,
	)
	if err != nil || len(witnessPublicRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("prepared recovery trust witness public key is invalid")
	}
	witnessKeyID, err := kernelfabric.BootstrapKeyID(ed25519.PublicKey(witnessPublicRaw))
	if err != nil {
		return nil, err
	}
	if witnessKeyID != prepared.SignedTrust.Manifest.WitnessKeyID {
		return nil, fmt.Errorf("prepared recovery trust witness key id mismatch")
	}

	return &verifiedPreparedTaintRecoveryWitness{
		prepared:                  prepared,
		signedWitnessProfile:      signedWitnessProfile,
		genesisCapabilityEnvelope: genesisCapabilityEnvelope,
	}, nil
}

func activateVerifiedTaintRecoveryWitness(
	ctx context.Context,
	witnessAdmin kubernetes.Interface,
	controllerBundlePath string,
	verified *verifiedPreparedTaintRecoveryWitness,
) error {
	if verified == nil {
		return fmt.Errorf("verified prepared recovery witness is required")
	}
	prepared := verified.prepared
	signedWitnessProfile := verified.signedWitnessProfile
	genesisCapabilityEnvelope := verified.genesisCapabilityEnvelope

	trustPayload, err := json.Marshal(prepared.SignedTrust)
	if err != nil {
		return err
	}
	policyPayload, err := json.Marshal(prepared.Policy)
	if err != nil {
		return err
	}
	witnessProfilePayload, err := json.Marshal(signedWitnessProfile)
	if err != nil {
		return err
	}

	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessSecretName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		StringData: map[string]string{
			"tls.crt": prepared.WitnessCAPEM,
			"tls.key": prepared.WitnessTLSKeyPEM,
		},
	}
	if _, err := witnessAdmin.CoreV1().Secrets(witnessNamespace).Create(
		ctx,
		secret,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness secret: %w", err)
	}

	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessConfigName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		Data: map[string]string{
			"trust-manifest.json":              string(trustPayload),
			"external-profile.json":            string(witnessProfilePayload),
			"genesis-capability-envelope.json": string(genesisCapabilityEnvelope),
			"genesis-capability-envelope-hash": prepared.GenesisCapabilityEnvelopeHash,
			"trust-signer-public-key":          prepared.TrustSignerPublicKey,
			"policy.json":                      string(policyPayload),
			"witness-signer-endpoint":          prepared.WitnessSignerEndpoint,
			"witness-signer-ca.pem":            prepared.WitnessSignerCAPEM,
			"witness-signer-tls-server-name":   prepared.WitnessSignerTLSServerName,
		},
	}
	if _, err := witnessAdmin.CoreV1().ConfigMaps(witnessNamespace).Create(
		ctx,
		config,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness config: %w", err)
	}

	falseValue := false
	replicas := int32(1)
	labels := map[string]string{"app": recoveryWitnessDeploymentName}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessDeploymentName,
			Namespace: witnessNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &falseValue,
					Containers: []corev1.Container{{
						Name:            "witness",
						Image:           recoveryWitnessImage,
						ImagePullPolicy: corev1.PullNever,
						Env: []corev1.EnvVar{
							{Name: "WITNESS_SIGNER_ENDPOINT_PATH", Value: "/run/aegis-witness/config/witness-signer-endpoint"},
							{Name: "WITNESS_SIGNER_CA_PATH", Value: "/run/aegis-witness/config/witness-signer-ca.pem"},
							{Name: "WITNESS_SIGNER_TLS_SERVER_NAME_PATH", Value: "/run/aegis-witness/config/witness-signer-tls-server-name"},
							{Name: "TRUST_MANIFEST_PATH", Value: "/run/aegis-witness/config/trust-manifest.json"},
							{Name: "EXTERNAL_WITNESS_PROFILE_PATH", Value: "/run/aegis-witness/config/external-profile.json"},
							{Name: "GENESIS_CAPABILITY_ENVELOPE_PATH", Value: "/run/aegis-witness/config/genesis-capability-envelope.json"},
							{Name: "GENESIS_CAPABILITY_ENVELOPE_HASH_PATH", Value: "/run/aegis-witness/config/genesis-capability-envelope-hash"},
							{Name: "TRUST_SIGNER_PUBLIC_KEY_PATH", Value: "/run/aegis-witness/config/trust-signer-public-key"},
							{Name: "WITNESS_POLICY_PATH", Value: "/run/aegis-witness/config/policy.json"},
							{Name: "TLS_CERT_PATH", Value: "/run/aegis-witness/secret/tls.crt"},
							{Name: "TLS_KEY_PATH", Value: "/run/aegis-witness/secret/tls.key"},
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
							{Name: "secret", MountPath: "/run/aegis-witness/secret", ReadOnly: true},
							{Name: "config", MountPath: "/run/aegis-witness/config", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  recoveryWitnessSecretName,
									DefaultMode: int32Ptr(0o400),
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: recoveryWitnessConfigName},
									DefaultMode:          int32Ptr(0o400),
								},
							},
						},
					},
				},
			},
		},
	}
	if _, err := witnessAdmin.AppsV1().Deployments(witnessNamespace).Create(
		ctx,
		deployment,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness deployment: %w", err)
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      recoveryWitnessServiceName,
			Namespace: witnessNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Protocol:   corev1.ProtocolTCP,
				Port:       443,
				TargetPort: intstr.FromInt(8443),
				NodePort:   recoveryWitnessNodePort,
			}},
		},
	}
	if _, err := witnessAdmin.CoreV1().Services(witnessNamespace).Create(
		ctx,
		service,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create recovery witness service: %w", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		current, err := witnessAdmin.AppsV1().Deployments(witnessNamespace).Get(
			ctx,
			recoveryWitnessDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			return err
		}
		if current.Status.ReadyReplicas >= 1 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recovery witness deployment did not become ready")
		}
		time.Sleep(time.Second)
	}

	bundle := controllerBundle{
		Version:                         controllerBundleVersion,
		AuthorityPrivateKey:             prepared.AuthorityPrivateKey,
		SignedTrust:                     prepared.SignedTrust,
		SignedWitnessProfile:            signedWitnessProfile,
		GenesisCapabilityEnvelopeBase64: prepared.GenesisCapabilityEnvelopeBase64,
		GenesisCapabilityEnvelopeHash:   prepared.GenesisCapabilityEnvelopeHash,
		TrustSignerPublicKey:            prepared.TrustSignerPublicKey,
		WitnessCAPEM:                    prepared.WitnessCAPEM,
		WitnessTLSServerName:            prepared.WitnessTLSServerName,
		Policy:                          prepared.Policy,
	}
	return writeJSONFile(controllerBundlePath, bundle, 0o600)
}

func validateWitnessSignerPublicConfig(
	endpoint string,
	caPEM []byte,
	tlsServerName string,
) error {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("witness signer endpoint must be an absolute HTTPS URL")
	}
	if strings.TrimSpace(tlsServerName) == "" {
		return fmt.Errorf("witness signer TLS server name is required")
	}
	if strings.TrimSpace(string(caPEM)) == "" {
		return fmt.Errorf("witness signer TLS certificate is required")
	}
	return nil
}

func readTrimmedFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("file %s is empty", path)
	}
	return value, nil
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func readJSONFile(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}

func writeJSONFile(path string, value any, mode os.FileMode) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, payload, mode)
}
