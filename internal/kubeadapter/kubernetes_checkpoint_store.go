package kubeadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const checkpointDataKey = "checkpoint.json"

type KubernetesDrainCheckpointStore struct {
	client    kubernetes.Interface
	namespace string
}

func NewKubernetesDrainCheckpointStore(
	client kubernetes.Interface,
	namespace string,
) (*KubernetesDrainCheckpointStore, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("checkpoint namespace is required")
	}
	return &KubernetesDrainCheckpointStore{client: client, namespace: namespace}, nil
}

func (s *KubernetesDrainCheckpointStore) Load(
	ctx context.Context,
	actionID string,
) (DrainExecutionCheckpoint, error) {
	configMap, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(
		ctx,
		checkpointConfigMapName(actionID),
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return DrainExecutionCheckpoint{}, ErrDrainCheckpointNotFound
	}
	if err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("get Kubernetes checkpoint: %w", err)
	}

	payload, ok := configMap.Data[checkpointDataKey]
	if !ok {
		return DrainExecutionCheckpoint{}, fmt.Errorf("Kubernetes checkpoint is missing %s", checkpointDataKey)
	}
	var checkpoint DrainExecutionCheckpoint
	if err := json.Unmarshal([]byte(payload), &checkpoint); err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("decode Kubernetes checkpoint: %w", err)
	}
	if checkpoint.ActionID != actionID {
		return DrainExecutionCheckpoint{}, fmt.Errorf(
			"checkpoint action id mismatch: expected %q got %q",
			actionID,
			checkpoint.ActionID,
		)
	}
	checkpoint.StoreVersion = configMap.ResourceVersion
	return checkpoint, nil
}

func (s *KubernetesDrainCheckpointStore) Save(
	ctx context.Context,
	checkpoint DrainExecutionCheckpoint,
) error {
	_, err := s.SaveVersioned(ctx, checkpoint)
	return err
}

func (s *KubernetesDrainCheckpointStore) SaveVersioned(
	ctx context.Context,
	checkpoint DrainExecutionCheckpoint,
) (DrainExecutionCheckpoint, error) {
	if checkpoint.ActionID == "" {
		return DrainExecutionCheckpoint{}, fmt.Errorf("checkpoint action id is required")
	}

	payloadCheckpoint := checkpoint
	payloadCheckpoint.StoreVersion = ""
	payload, err := json.Marshal(payloadCheckpoint)
	if err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("encode Kubernetes checkpoint: %w", err)
	}

	name := checkpointConfigMapName(checkpoint.ActionID)
	configMaps := s.client.CoreV1().ConfigMaps(s.namespace)

	var saved *corev1.ConfigMap
	if checkpoint.StoreVersion == "" {
		saved, err = configMaps.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":       "state-latch",
					"state-latch.dev/state-kind":   "drain-checkpoint",
				},
			},
			Data: map[string]string{checkpointDataKey: string(payload)},
		}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return DrainExecutionCheckpoint{}, ErrDrainCheckpointConflict
		}
	} else {
		saved, err = configMaps.Update(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       s.namespace,
				ResourceVersion: checkpoint.StoreVersion,
				Labels: map[string]string{
					"app.kubernetes.io/name":       "state-latch",
					"state-latch.dev/state-kind":   "drain-checkpoint",
				},
			},
			Data: map[string]string{checkpointDataKey: string(payload)},
		}, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return DrainExecutionCheckpoint{}, ErrDrainCheckpointConflict
		}
	}
	if err != nil {
		return DrainExecutionCheckpoint{}, fmt.Errorf("write Kubernetes checkpoint: %w", err)
	}

	checkpoint.StoreVersion = saved.ResourceVersion
	return checkpoint, nil
}

func checkpointConfigMapName(actionID string) string {
	sum := sha256.Sum256([]byte(actionID))
	return "state-latch-checkpoint-" + hex.EncodeToString(sum[:12])
}

func IsDrainCheckpointConflict(err error) bool {
	return errors.Is(err, ErrDrainCheckpointConflict)
}
