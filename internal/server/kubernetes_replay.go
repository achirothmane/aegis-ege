package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/achirothmane/aegis-ege/internal/decision"
)

type KubernetesReplayGuard struct {
	client    kubernetes.Interface
	namespace string
}

func NewKubernetesReplayGuard(
	client kubernetes.Interface,
	namespace string,
) (*KubernetesReplayGuard, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("replay namespace is required")
	}
	return &KubernetesReplayGuard{client: client, namespace: namespace}, nil
}

func (g *KubernetesReplayGuard) Issue(
	ctx context.Context,
	auth decision.Authorization,
) error {
	record := newExecutionClaimRecord(auth, ExecutionClaimIssued)
	cm, err := g.configMapForRecord(auth, record)
	if err != nil {
		return err
	}
	_, err = g.client.CoreV1().ConfigMaps(g.namespace).Create(
		ctx,
		cm,
		metav1.CreateOptions{},
	)
	if apierrors.IsAlreadyExists(err) {
		return ErrExecutionReplay
	}
	if err != nil {
		return fmt.Errorf("issue shared execution capability: %w", err)
	}
	return nil
}

func (g *KubernetesReplayGuard) Claim(
	ctx context.Context,
	auth decision.Authorization,
) error {
	name, err := g.nameForAuthorization(auth)
	if err != nil {
		return err
	}
	api := g.client.CoreV1().ConfigMaps(g.namespace)
	current, err := api.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		record := newExecutionClaimRecord(auth, ExecutionClaimClaimed)
		cm, buildErr := g.configMapForRecord(auth, record)
		if buildErr != nil {
			return buildErr
		}
		if _, createErr := api.Create(ctx, cm, metav1.CreateOptions{}); apierrors.IsAlreadyExists(createErr) {
			return ErrExecutionReplay
		} else if createErr != nil {
			return fmt.Errorf("create shared execution replay claim: %w", createErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read shared execution claim: %w", err)
	}

	record, err := executionClaimRecordFromConfigMap(current, auth)
	if err != nil {
		return err
	}
	if record.State != ExecutionClaimIssued {
		return ErrExecutionReplay
	}
	record.State = ExecutionClaimClaimed
	record.Outcome = ""
	record.Reason = ""
	applyExecutionClaimRecord(current, record)

	if _, err := api.Update(ctx, current, metav1.UpdateOptions{}); apierrors.IsConflict(err) {
		return ErrExecutionReplay
	} else if err != nil {
		return fmt.Errorf("claim shared execution capability: %w", err)
	}
	return nil
}

func (g *KubernetesReplayGuard) Consume(
	ctx context.Context,
	auth decision.Authorization,
	outcome string,
) error {
	return g.finalize(ctx, auth, ExecutionClaimConsumed, strings.TrimSpace(outcome))
}

func (g *KubernetesReplayGuard) Abort(
	ctx context.Context,
	auth decision.Authorization,
	reason string,
) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("%w: abort reason is required", ErrExecutionClaimTransition)
	}
	return g.finalize(ctx, auth, ExecutionClaimAborted, reason)
}

func (g *KubernetesReplayGuard) State(
	ctx context.Context,
	auth decision.Authorization,
) (ExecutionClaimRecord, error) {
	name, err := g.nameForAuthorization(auth)
	if err != nil {
		return ExecutionClaimRecord{}, err
	}
	current, err := g.client.CoreV1().ConfigMaps(g.namespace).Get(
		ctx,
		name,
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return ExecutionClaimRecord{}, ErrExecutionClaimNotFound
	}
	if err != nil {
		return ExecutionClaimRecord{}, fmt.Errorf("read shared execution claim state: %w", err)
	}
	return executionClaimRecordFromConfigMap(current, auth)
}

func (g *KubernetesReplayGuard) finalize(
	ctx context.Context,
	auth decision.Authorization,
	state ExecutionClaimState,
	detail string,
) error {
	name, err := g.nameForAuthorization(auth)
	if err != nil {
		return err
	}
	api := g.client.CoreV1().ConfigMaps(g.namespace)
	current, err := api.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ErrExecutionClaimNotFound
	}
	if err != nil {
		return fmt.Errorf("read shared execution claim for finalization: %w", err)
	}

	record, err := executionClaimRecordFromConfigMap(current, auth)
	if err != nil {
		return err
	}
	if record.State == state {
		if state == ExecutionClaimConsumed && record.Outcome == detail {
			return nil
		}
		if state == ExecutionClaimAborted && record.Reason == detail {
			return nil
		}
		return ErrExecutionClaimTransition
	}
	if record.State != ExecutionClaimClaimed {
		return ErrExecutionClaimTransition
	}

	record.State = state
	record.Outcome = ""
	record.Reason = ""
	switch state {
	case ExecutionClaimConsumed:
		record.Outcome = detail
	case ExecutionClaimAborted:
		record.Reason = detail
	default:
		return ErrExecutionClaimTransition
	}
	applyExecutionClaimRecord(current, record)

	if _, err := api.Update(ctx, current, metav1.UpdateOptions{}); apierrors.IsConflict(err) {
		latest, readErr := api.Get(ctx, name, metav1.GetOptions{})
		if readErr != nil {
			return fmt.Errorf("resolve execution claim finalization conflict: %w", readErr)
		}
		latestRecord, parseErr := executionClaimRecordFromConfigMap(latest, auth)
		if parseErr != nil {
			return parseErr
		}
		if latestRecord.State == state {
			if state == ExecutionClaimConsumed && latestRecord.Outcome == detail {
				return nil
			}
			if state == ExecutionClaimAborted && latestRecord.Reason == detail {
				return nil
			}
		}
		return ErrExecutionClaimTransition
	} else if err != nil {
		return fmt.Errorf("finalize shared execution capability: %w", err)
	}
	return nil
}

func (g *KubernetesReplayGuard) configMapForRecord(
	auth decision.Authorization,
	record ExecutionClaimRecord,
) (*corev1.ConfigMap, error) {
	name, err := g.nameForAuthorization(auth)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":     "state-latch",
				"state-latch.dev/state-kind": "execution-claim",
			},
		},
	}
	applyExecutionClaimRecord(cm, record)
	return cm, nil
}

func (g *KubernetesReplayGuard) nameForAuthorization(
	auth decision.Authorization,
) (string, error) {
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return "", err
	}
	return "state-latch-replay-" + key[:24], nil
}

func applyExecutionClaimRecord(
	cm *corev1.ConfigMap,
	record ExecutionClaimRecord,
) {
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["version"] = record.Version
	cm.Data["state"] = string(record.State)
	cm.Data["action_id"] = record.ActionID
	cm.Data["target"] = record.Target
	cm.Data["authority_domain"] = record.AuthorityDomain
	cm.Data["authority_term"] = fmt.Sprintf("%d", record.AuthorityTerm)
	cm.Data["decision_epoch"] = fmt.Sprintf("%d", record.DecisionEpoch)
	cm.Data["revocation_epoch"] = fmt.Sprintf("%d", record.RevocationEpoch)
	cm.Data["target_identity"] = record.TargetIdentity
	cm.Data["state_binding_digest"] = record.StateBindingDigest
	cm.Data["outcome"] = record.Outcome
	cm.Data["reason"] = record.Reason
}

func executionClaimRecordFromConfigMap(
	cm *corev1.ConfigMap,
	auth decision.Authorization,
) (ExecutionClaimRecord, error) {
	if cm == nil {
		return ExecutionClaimRecord{}, errors.New("execution claim ConfigMap is nil")
	}
	state := ExecutionClaimState(strings.TrimSpace(cm.Data["state"]))
	if state == "" {
		// ConfigMaps created by the previous replay-only implementation are
		// conservatively interpreted as already CLAIMED.
		return newExecutionClaimRecord(auth, ExecutionClaimClaimed), nil
	}
	switch state {
	case ExecutionClaimIssued, ExecutionClaimClaimed, ExecutionClaimConsumed, ExecutionClaimAborted:
	default:
		return ExecutionClaimRecord{}, fmt.Errorf(
			"unknown execution claim state %q",
			state,
		)
	}

	parseUint := func(key string) (uint64, error) {
		value := strings.TrimSpace(cm.Data[key])
		if value == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid execution claim %s: %w", key, err)
		}
		return parsed, nil
	}

	authorityTerm, err := parseUint("authority_term")
	if err != nil {
		return ExecutionClaimRecord{}, err
	}
	decisionEpoch, err := parseUint("decision_epoch")
	if err != nil {
		return ExecutionClaimRecord{}, err
	}
	revocationEpoch, err := parseUint("revocation_epoch")
	if err != nil {
		return ExecutionClaimRecord{}, err
	}

	record := ExecutionClaimRecord{
		Version:            strings.TrimSpace(cm.Data["version"]),
		State:              state,
		ActionID:           strings.TrimSpace(cm.Data["action_id"]),
		Target:             strings.TrimSpace(cm.Data["target"]),
		AuthorityDomain:    strings.TrimSpace(cm.Data["authority_domain"]),
		AuthorityTerm:      authorityTerm,
		DecisionEpoch:      decisionEpoch,
		RevocationEpoch:    revocationEpoch,
		TargetIdentity:     strings.TrimSpace(cm.Data["target_identity"]),
		StateBindingDigest: strings.TrimSpace(cm.Data["state_binding_digest"]),
		Outcome:            cm.Data["outcome"],
		Reason:             cm.Data["reason"],
	}
	if record.Version == "" {
		record.Version = ExecutionClaimRecordVersion
	}
	if err := validateExecutionClaimRecord(record, auth); err != nil {
		return ExecutionClaimRecord{}, err
	}
	return record, nil
}
