package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	GovernedWitnessStateVersion = "aegis-ege/governed-witness-state/v1"
	governedWitnessStateDataKey = "state.json"
)

var (
	ErrGovernedWitnessStateNotFound = errors.New("governed witness state not found")
	ErrGovernedWitnessStateConflict = errors.New("governed witness state conflict")
)

type GovernedWitnessState struct {
	Protocol     string                    `json:"protocol"`
	Policy       QuorumPolicyState         `json:"policy"`
	Heads        map[string]ExternalHead   `json:"heads"`
	StoreVersion string                    `json:"-"`
}

type GovernedWitnessStateStore interface {
	Load(context.Context) (GovernedWitnessState, error)
	CompareAndSwap(
		context.Context,
		string,
		GovernedWitnessState,
	) (GovernedWitnessState, error)
}

type KubernetesGovernedWitnessStateStore struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

func NewKubernetesGovernedWitnessStateStore(
	client kubernetes.Interface,
	namespace string,
	name string,
) (*KubernetesGovernedWitnessStateStore, error) {
	if client == nil {
		return nil, errors.New("kubernetes client is required")
	}
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" {
		return nil, errors.New("governed witness namespace is required")
	}
	if name == "" {
		return nil, errors.New("governed witness state name is required")
	}
	return &KubernetesGovernedWitnessStateStore{
		client:    client,
		namespace: namespace,
		name:      name,
	}, nil
}

func (s *KubernetesGovernedWitnessStateStore) Load(
	ctx context.Context,
) (GovernedWitnessState, error) {
	configMap, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(
		ctx,
		s.name,
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return GovernedWitnessState{}, ErrGovernedWitnessStateNotFound
	}
	if err != nil {
		return GovernedWitnessState{}, fmt.Errorf(
			"get governed witness state: %w",
			err,
		)
	}
	payload, ok := configMap.Data[governedWitnessStateDataKey]
	if !ok {
		return GovernedWitnessState{}, fmt.Errorf(
			"governed witness state is missing %s",
			governedWitnessStateDataKey,
		)
	}
	var state GovernedWitnessState
	if err := json.Unmarshal([]byte(payload), &state); err != nil {
		return GovernedWitnessState{}, fmt.Errorf(
			"decode governed witness state: %w",
			err,
		)
	}
	if err := validateGovernedWitnessState(state); err != nil {
		return GovernedWitnessState{}, err
	}
	state.StoreVersion = configMap.ResourceVersion
	for id, head := range state.Heads {
		head.StoreVersion = state.StoreVersion
		state.Heads[id] = head
	}
	return state, nil
}

func (s *KubernetesGovernedWitnessStateStore) CompareAndSwap(
	ctx context.Context,
	expectedVersion string,
	next GovernedWitnessState,
) (GovernedWitnessState, error) {
	next.Protocol = GovernedWitnessStateVersion
	next.StoreVersion = ""
	if next.Heads == nil {
		next.Heads = map[string]ExternalHead{}
	}
	for id, head := range next.Heads {
		head.StoreVersion = ""
		next.Heads[id] = head
	}
	if err := validateGovernedWitnessState(next); err != nil {
		return GovernedWitnessState{}, err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return GovernedWitnessState{}, fmt.Errorf(
			"encode governed witness state: %w",
			err,
		)
	}

	configMaps := s.client.CoreV1().ConfigMaps(s.namespace)
	var saved *corev1.ConfigMap
	if strings.TrimSpace(expectedVersion) == "" {
		saved, err = configMaps.Create(
			ctx,
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.name,
					Namespace: s.namespace,
					Labels: map[string]string{
						"app.kubernetes.io/name":     "aegis-ege",
						"aegis-ege.dev/state-kind":   "governed-witness",
					},
				},
				Data: map[string]string{
					governedWitnessStateDataKey: string(payload),
				},
			},
			metav1.CreateOptions{},
		)
		if apierrors.IsAlreadyExists(err) {
			return GovernedWitnessState{}, ErrGovernedWitnessStateConflict
		}
	} else {
		saved, err = configMaps.Update(
			ctx,
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:            s.name,
					Namespace:       s.namespace,
					ResourceVersion: expectedVersion,
					Labels: map[string]string{
						"app.kubernetes.io/name":     "aegis-ege",
						"aegis-ege.dev/state-kind":   "governed-witness",
					},
				},
				Data: map[string]string{
					governedWitnessStateDataKey: string(payload),
				},
			},
			metav1.UpdateOptions{},
		)
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return GovernedWitnessState{}, ErrGovernedWitnessStateConflict
		}
	}
	if err != nil {
		return GovernedWitnessState{}, fmt.Errorf(
			"write governed witness state: %w",
			err,
		)
	}
	next.StoreVersion = saved.ResourceVersion
	for id, head := range next.Heads {
		head.StoreVersion = next.StoreVersion
		next.Heads[id] = head
	}
	return next, nil
}

func InitializeGovernedWitnessState(
	ctx context.Context,
	store GovernedWitnessStateStore,
	initialPolicy QuorumPolicyState,
) (GovernedWitnessState, error) {
	if store == nil {
		return GovernedWitnessState{}, errors.New(
			"governed witness state store is required",
		)
	}
	if err := validateQuorumPolicyState(initialPolicy); err != nil {
		return GovernedWitnessState{}, err
	}
	if initialPolicy.Phase != QuorumPolicyPhaseActive {
		return GovernedWitnessState{}, errors.New(
			"initial governed witness policy must be ACTIVE",
		)
	}
	state, err := store.Load(ctx)
	if err == nil {
		if state.Policy != initialPolicy {
			return GovernedWitnessState{}, fmt.Errorf(
				"%w: persisted policy %+v differs from startup policy %+v",
				ErrQuorumPolicyMismatch,
				state.Policy,
				initialPolicy,
			)
		}
		return state, nil
	}
	if !errors.Is(err, ErrGovernedWitnessStateNotFound) {
		return GovernedWitnessState{}, err
	}
	return store.CompareAndSwap(
		ctx,
		"",
		GovernedWitnessState{
			Protocol: GovernedWitnessStateVersion,
			Policy:   initialPolicy,
			Heads:    map[string]ExternalHead{},
		},
	)
}

func validateGovernedWitnessState(state GovernedWitnessState) error {
	if state.Protocol != GovernedWitnessStateVersion {
		return fmt.Errorf(
			"governed witness state protocol mismatch: got %q want %q",
			state.Protocol,
			GovernedWitnessStateVersion,
		)
	}
	if err := validateQuorumPolicyState(state.Policy); err != nil {
		return fmt.Errorf("governed witness policy: %w", err)
	}
	for id, head := range state.Heads {
		id = strings.TrimSpace(id)
		if id == "" || head.JournalID != id {
			return fmt.Errorf(
				"governed witness head key %q does not match journal id %q",
				id,
				head.JournalID,
			)
		}
	}
	return nil
}
