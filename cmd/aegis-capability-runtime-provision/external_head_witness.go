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
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const (
	externalHeadWitnessBundleVersion = "aegis-ege/external-head-witness-client/v1"

	externalHeadWitnessStateName      = "aegis-external-head-witness-state"
	externalHeadWitnessSecretName     = "aegis-external-head-witness-secret"
	externalHeadWitnessConfigName     = "aegis-external-head-witness-config"
	externalHeadWitnessDeploymentName = "aegis-external-head-witness"
	externalHeadWitnessServiceName    = "aegis-external-head-witness"
	externalHeadWitnessServiceAccount = "aegis-external-head-witness"

	externalHeadWitnessImage            = "aegis-external-head-witness:ci"
	externalHeadWitnessServerName       = "aegis-head-witness.local"
	externalHeadWitnessExternalEndpoint = "https://127.0.0.1:30444"
	externalHeadWitnessNodePort   int32  = 30444
)

type externalHeadWitnessClientBundle struct {
	Version          string                    `json:"version"`
	Endpoint         string                    `json:"endpoint"`
	TLSServerName    string                    `json:"tls_server_name"`
	CAPEM            string                    `json:"ca_pem"`
	WitnessKeyID     string                    `json:"witness_key_id"`
	WitnessPublicKey string                    `json:"witness_public_key"`
	Policy           journal.QuorumPolicyState `json:"policy"`
	JournalID        string                    `json:"journal_id"`
	StateName        string                    `json:"state_name"`
}

func activateExternalHeadWitness(
	ctx context.Context,
	witnessAdmin kubernetes.Interface,
	clientBundlePath string,
) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keyID, err := kernelfabric.BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	tlsCertPEM, tlsKeyPEM, err := newWitnessTLSCertificate(
		externalHeadWitnessServerName,
	)
	if err != nil {
		return err
	}
	policySeed := sha256.Sum256(
		[]byte("aegis-ege/live-external-head-witness-policy/v1"),
	)
	policy := journal.QuorumPolicyState{
		Phase:        journal.QuorumPolicyPhaseActive,
		GenesisEpoch: 1,
		PolicyHash:   "sha256:" + hex.EncodeToString(policySeed[:]),
	}

	stateStore, err := journal.NewKubernetesGovernedWitnessStateStore(
		witnessAdmin,
		witnessNamespace,
		externalHeadWitnessStateName,
	)
	if err != nil {
		return err
	}
	state, err := journal.InitializeGovernedWitnessState(
		ctx,
		stateStore,
		policy,
	)
	if err != nil {
		return err
	}
	if state.Heads == nil {
		state.Heads = map[string]journal.ExternalHead{}
	}
	if _, ok := state.Heads[witnessJournalID]; !ok {
		state.Heads[witnessJournalID] = journal.ExternalHead{
			JournalID: witnessJournalID,
			Sequence:  0,
			HeadHash:  "",
			KeyID:     witnessKeyID,
		}
		state, err = stateStore.CompareAndSwap(
			ctx,
			state.StoreVersion,
			state,
		)
		if err != nil {
			return fmt.Errorf("initialize external head witness journal: %w", err)
		}
	}

	if err := ensureInternalWitnessServiceAccount(
		ctx,
		witnessAdmin,
	); err != nil {
		return err
	}

	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      externalHeadWitnessSecretName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		StringData: map[string]string{
			"head-witness-signing-key": base64.StdEncoding.EncodeToString(privateKey),
			"tls.crt":             string(tlsCertPEM),
			"tls.key":             string(tlsKeyPEM),
		},
	}
	if _, err := witnessAdmin.CoreV1().Secrets(witnessNamespace).Create(
		ctx,
		secret,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create external head witness secret: %w", err)
	}

	policyPayload, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      externalHeadWitnessConfigName,
			Namespace: witnessNamespace,
		},
		Immutable: &immutable,
		Data: map[string]string{
			"policy.json": string(policyPayload),
		},
	}
	if _, err := witnessAdmin.CoreV1().ConfigMaps(witnessNamespace).Create(
		ctx,
		config,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create external head witness config: %w", err)
	}

	replicas := int32(1)
	labels := map[string]string{"app": externalHeadWitnessDeploymentName}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      externalHeadWitnessDeploymentName,
			Namespace: witnessNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: externalHeadWitnessServiceAccount,
					Containers: []corev1.Container{{
						Name:            "witness",
						Image:           externalHeadWitnessImage,
						ImagePullPolicy: corev1.PullNever,
						Env: []corev1.EnvVar{
							{Name: "WITNESS_STATE_NAMESPACE", Value: witnessNamespace},
							{Name: "WITNESS_STATE_NAME", Value: externalHeadWitnessStateName},
							{Name: "WITNESS_KEY_ID", Value: keyID},
							{Name: "HEAD_WITNESS_SIGNING_KEY_PATH", Value: "/run/aegis-head-witness/secret/head-witness-signing-key"},
							{Name: "WITNESS_POLICY_PATH", Value: "/run/aegis-head-witness/config/policy.json"},
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
							{Name: "secret", MountPath: "/run/aegis-head-witness/secret", ReadOnly: true},
							{Name: "config", MountPath: "/run/aegis-head-witness/config", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  externalHeadWitnessSecretName,
									DefaultMode: int32Ptr(0o400),
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: externalHeadWitnessConfigName,
									},
									DefaultMode: int32Ptr(0o400),
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
		return fmt.Errorf("create external head witness deployment: %w", err)
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      externalHeadWitnessServiceName,
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
				NodePort:   externalHeadWitnessNodePort,
			}},
		},
	}
	if _, err := witnessAdmin.CoreV1().Services(witnessNamespace).Create(
		ctx,
		service,
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create external head witness service: %w", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		current, err := witnessAdmin.AppsV1().Deployments(witnessNamespace).Get(
			ctx,
			externalHeadWitnessDeploymentName,
			metav1.GetOptions{},
		)
		if err != nil {
			return err
		}
		if current.Status.ReadyReplicas >= 1 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("external head witness deployment did not become ready")
		}
		time.Sleep(time.Second)
	}

	return writeJSONFile(
		clientBundlePath,
		externalHeadWitnessClientBundle{
			Version:          externalHeadWitnessBundleVersion,
			Endpoint:         externalHeadWitnessExternalEndpoint,
			TLSServerName:    externalHeadWitnessServerName,
			CAPEM:            string(tlsCertPEM),
			WitnessKeyID:     keyID,
			WitnessPublicKey: base64.StdEncoding.EncodeToString(publicKey),
			Policy:           policy,
			JournalID:        witnessJournalID,
			StateName:        externalHeadWitnessStateName,
		},
		0o600,
	)
}

func ensureInternalWitnessServiceAccount(
	ctx context.Context,
	client kubernetes.Interface,
) error {
	if _, err := client.CoreV1().ServiceAccounts(witnessNamespace).Create(
		ctx,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      externalHeadWitnessServiceAccount,
				Namespace: witnessNamespace,
			},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	roleName := externalHeadWitnessServiceAccount + "-runtime"
	if _, err := client.RbacV1().Roles(witnessNamespace).Create(
		ctx,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleName,
				Namespace: witnessNamespace,
			},
			Rules: []rbacv1.PolicyRule{{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{externalHeadWitnessStateName},
				Verbs:         []string{"get", "update"},
			}},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	if _, err := client.RbacV1().RoleBindings(witnessNamespace).Create(
		ctx,
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleName,
				Namespace: witnessNamespace,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      externalHeadWitnessServiceAccount,
				Namespace: witnessNamespace,
			}},
		},
		metav1.CreateOptions{},
	); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}
