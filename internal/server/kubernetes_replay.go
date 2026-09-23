package server

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/achirothmane/state-latch/internal/decision"
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

func (g *KubernetesReplayGuard) Claim(
	ctx context.Context,
	auth decision.Authorization,
) error {
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return err
	}
	name := "state-latch-replay-" + key[:24]
	_, err = g.client.CoreV1().ConfigMaps(g.namespace).Create(
		ctx,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: g.namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":     "state-latch",
					"state-latch.dev/state-kind": "execution-replay-claim",
				},
			},
			Data: map[string]string{
				"action_id":   auth.ActionID,
				"target":      auth.Target,
				"valid_until": auth.ValidUntil.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			},
		},
		metav1.CreateOptions{},
	)
	if apierrors.IsAlreadyExists(err) {
		return ErrExecutionReplay
	}
	if err != nil {
		return fmt.Errorf("create shared execution replay claim: %w", err)
	}
	return nil
}
