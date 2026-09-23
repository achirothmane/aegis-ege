package journal

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const externalHeadDataKey = "head.json"

type KubernetesHeadStore struct {
	client    kubernetes.Interface
	namespace string
}

func NewKubernetesHeadStore(
	client kubernetes.Interface,
	namespace string,
) (*KubernetesHeadStore, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("external head namespace is required")
	}
	return &KubernetesHeadStore{client: client, namespace: namespace}, nil
}

func (s *KubernetesHeadStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	configMap, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(
		ctx,
		externalHeadConfigMapName(journalID),
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return ExternalHead{}, ErrExternalHeadNotFound
	}
	if err != nil {
		return ExternalHead{}, fmt.Errorf("get external journal head: %w", err)
	}
	payload, ok := configMap.Data[externalHeadDataKey]
	if !ok {
		return ExternalHead{}, fmt.Errorf("external journal head is missing %s", externalHeadDataKey)
	}
	var head ExternalHead
	if err := json.Unmarshal([]byte(payload), &head); err != nil {
		return ExternalHead{}, fmt.Errorf("decode external journal head: %w", err)
	}
	if head.JournalID != journalID {
		return ExternalHead{}, fmt.Errorf("external journal id mismatch")
	}
	head.StoreVersion = configMap.ResourceVersion
	return head, nil
}

func (s *KubernetesHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if next.JournalID == "" {
		return ExternalHead{}, fmt.Errorf("journal id is required")
	}
	if next.Sequence < previous.Sequence {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if next.Sequence == previous.Sequence &&
		(next.HeadHash != previous.HeadHash || next.KeyID != previous.KeyID) &&
		previous.StoreVersion != "" {
		return ExternalHead{}, ErrExternalHeadConflict
	}

	configMaps := s.client.CoreV1().ConfigMaps(s.namespace)
	name := externalHeadConfigMapName(next.JournalID)
	payloadHead := next
	payloadHead.StoreVersion = ""
	payload, err := json.Marshal(payloadHead)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("encode external journal head: %w", err)
	}

	if previous.StoreVersion == "" {
		current, err := s.Load(ctx, next.JournalID)
		if err == nil {
			if current.Sequence != previous.Sequence ||
				current.HeadHash != previous.HeadHash ||
				current.KeyID != previous.KeyID {
				return ExternalHead{}, ErrExternalHeadConflict
			}
			previous.StoreVersion = current.StoreVersion
		} else if !apierrors.IsNotFound(err) && err != ErrExternalHeadNotFound {
			// Load wraps normal API errors but returns the sentinel directly for NotFound.
			return ExternalHead{}, err
		}
	}

	var saved *corev1.ConfigMap
	if previous.StoreVersion == "" {
		saved, err = configMaps.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":     "state-latch",
					"state-latch.dev/state-kind": "journal-head",
				},
			},
			Data: map[string]string{externalHeadDataKey: string(payload)},
		}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return ExternalHead{}, ErrExternalHeadConflict
		}
	} else {
		saved, err = configMaps.Update(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       s.namespace,
				ResourceVersion: previous.StoreVersion,
				Labels: map[string]string{
					"app.kubernetes.io/name":     "state-latch",
					"state-latch.dev/state-kind": "journal-head",
				},
			},
			Data: map[string]string{externalHeadDataKey: string(payload)},
		}, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return ExternalHead{}, ErrExternalHeadConflict
		}
	}
	if err != nil {
		return ExternalHead{}, fmt.Errorf("write external journal head: %w", err)
	}

	next.StoreVersion = saved.ResourceVersion
	return next, nil
}

func externalHeadConfigMapName(journalID string) string {
	if len(journalID) > 24 {
		journalID = journalID[:24]
	}
	return "state-latch-journal-head-" + journalID
}
