package kubeadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type ClientGoReader struct {
	client kubernetes.Interface
}

func NewClientGoReader(client kubernetes.Interface) *ClientGoReader {
	return &ClientGoReader{client: client}
}

func NewInCluster() (*Adapter, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("build in-cluster config: %w", err)
	}
	return NewForConfig(config)
}

func NewFromKubeconfig(path string) (*Adapter, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	return NewForConfig(config)
}

func NewForConfig(config *rest.Config) (*Adapter, error) {
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	reader := NewClientGoReader(client)
	return NewWithExecutor(reader, reader), nil
}

func NewForConfigWithExperimentalMutations(config *rest.Config) (*Adapter, error) {
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	reader := NewClientGoReader(client)
	return NewWithExperimentalMutations(reader, reader), nil
}

func (r *ClientGoReader) GetNode(ctx context.Context, name string) (*corev1.Node, error) {
	return r.client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
}

func (r *ClientGoReader) ListPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	pods, err := r.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func (r *ClientGoReader) ListPodDisruptionBudgets(ctx context.Context) ([]PodDisruptionBudgetView, error) {
	pdbs, err := r.client.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	out := make([]PodDisruptionBudgetView, 0, len(pdbs.Items))
	for _, pdb := range pdbs.Items {
		out = append(out, PodDisruptionBudgetView{
			Namespace:          pdb.Namespace,
			Name:               pdb.Name,
			Generation:         pdb.Generation,
			ObservedGeneration: pdb.Status.ObservedGeneration,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
			Selector:           pdb.Spec.Selector,
		})
	}
	return out, nil
}

func (r *ClientGoReader) DryRunCordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]string{
			"resourceVersion": resourceVersion,
		},
		"spec": map[string]bool{
			"unschedulable": true,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal cordon patch: %w", err)
	}

	_, err = r.client.CoreV1().Nodes().Patch(
		ctx,
		nodeName,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}},
	)
	if err != nil {
		return fmt.Errorf("server dry-run cordon node %q: %w", nodeName, err)
	}
	return nil
}

func (r *ClientGoReader) DryRunEvictPod(ctx context.Context, pod PodStateRef) error {
	uid := types.UID(pod.UID)

	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &metav1.DeleteOptions{
			DryRun: []string{metav1.DryRunAll},
			Preconditions: &metav1.Preconditions{
				UID: &uid,
			},
		},
	}

	if err := r.client.PolicyV1().Evictions(pod.Namespace).Evict(ctx, eviction); err != nil {
		return fmt.Errorf("server dry-run evict pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return nil
}

func (r *ClientGoReader) CordonNode(ctx context.Context, nodeName, resourceVersion string) error {
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]string{
			"resourceVersion": resourceVersion,
		},
		"spec": map[string]bool{
			"unschedulable": true,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal cordon patch: %w", err)
	}

	if _, err := r.client.CoreV1().Nodes().Patch(
		ctx,
		nodeName,
		types.MergePatchType,
		patch,
		metav1.PatchOptions{},
	); err != nil {
		return fmt.Errorf("cordon node %q: %w", nodeName, err)
	}
	return nil
}

func (r *ClientGoReader) EvictPod(ctx context.Context, pod PodStateRef) error {
	uid := types.UID(pod.UID)

	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID: &uid,
			},
		},
	}

	if err := r.client.PolicyV1().Evictions(pod.Namespace).Evict(ctx, eviction); err != nil {
		return fmt.Errorf("evict pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return nil
}

func (r *ClientGoReader) AcquireExecutionLock(
	ctx context.Context,
	namespace string,
	target string,
	holder string,
	duration time.Duration,
) (ExecutionLease, error) {
	if namespace == "" || target == "" || holder == "" {
		return ExecutionLease{}, fmt.Errorf("execution lock namespace, target, and holder are required")
	}

	leaseName := executionLeaseName(target)
	leases := r.client.CoordinationV1().Leases(namespace)
	durationSeconds := int32((duration + time.Second - 1) / time.Second)
	if durationSeconds < 1 {
		durationSeconds = 1
	}

	for attempt := 0; attempt < 8; attempt++ {
		now := metav1.NewMicroTime(time.Now().UTC())
		current, err := leases.Get(ctx, leaseName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			transitions := int32(0)
			created, createErr := leases.Create(ctx, &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{
					Name:      leaseName,
					Namespace: namespace,
				},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holder,
					LeaseDurationSeconds: &durationSeconds,
					AcquireTime:          &now,
					RenewTime:            &now,
					LeaseTransitions:     &transitions,
				},
			}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(createErr) {
				continue
			}
			if createErr != nil {
				return ExecutionLease{}, fmt.Errorf("create execution lease %s/%s: %w", namespace, leaseName, createErr)
			}
			return ExecutionLease{
				Namespace: created.Namespace,
				Name:      created.Name,
				Target:    target,
				Holder:    holder,
			}, nil
		}
		if err != nil {
			return ExecutionLease{}, fmt.Errorf("get execution lease %s/%s: %w", namespace, leaseName, err)
		}

		currentHolder := ""
		if current.Spec.HolderIdentity != nil {
			currentHolder = *current.Spec.HolderIdentity
		}
		if currentHolder != "" && currentHolder != holder && !kubernetesLeaseExpired(current, time.Now().UTC()) {
			return ExecutionLease{}, fmt.Errorf(
				"%w: %s/%s holder=%s",
				ErrExecutionLockHeld,
				namespace,
				leaseName,
				currentHolder,
			)
		}

		next := current.DeepCopy()
		transitions := int32(0)
		if next.Spec.LeaseTransitions != nil {
			transitions = *next.Spec.LeaseTransitions
		}
		if currentHolder != holder {
			transitions++
		}
		next.Spec.HolderIdentity = &holder
		next.Spec.LeaseDurationSeconds = &durationSeconds
		next.Spec.AcquireTime = &now
		next.Spec.RenewTime = &now
		next.Spec.LeaseTransitions = &transitions

		if _, err := leases.Update(ctx, next, metav1.UpdateOptions{}); apierrors.IsConflict(err) {
			continue
		} else if err != nil {
			return ExecutionLease{}, fmt.Errorf("acquire execution lease %s/%s: %w", namespace, leaseName, err)
		}

		return ExecutionLease{
			Namespace: namespace,
			Name:      leaseName,
			Target:    target,
			Holder:    holder,
		}, nil
	}

	return ExecutionLease{}, fmt.Errorf("acquire execution lease %s/%s: too many conflicts", namespace, leaseName)
}

func (r *ClientGoReader) RenewExecutionLock(
	ctx context.Context,
	lease ExecutionLease,
	duration time.Duration,
) error {
	leases := r.client.CoordinationV1().Leases(lease.Namespace)
	durationSeconds := int32((duration + time.Second - 1) / time.Second)
	if durationSeconds < 1 {
		durationSeconds = 1
	}

	for attempt := 0; attempt < 8; attempt++ {
		current, err := leases.Get(ctx, lease.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: execution lease disappeared", ErrExecutionLockLost)
		}
		if err != nil {
			return fmt.Errorf("get execution lease for renew: %w", err)
		}

		if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != lease.Holder {
			return fmt.Errorf("%w: holder changed", ErrExecutionLockLost)
		}

		next := current.DeepCopy()
		now := metav1.NewMicroTime(time.Now().UTC())
		next.Spec.RenewTime = &now
		next.Spec.LeaseDurationSeconds = &durationSeconds

		if _, err := leases.Update(ctx, next, metav1.UpdateOptions{}); apierrors.IsConflict(err) {
			continue
		} else if err != nil {
			return fmt.Errorf("renew execution lease: %w", err)
		}
		return nil
	}

	return fmt.Errorf("%w: too many renew conflicts", ErrExecutionLockLost)
}

func (r *ClientGoReader) ReleaseExecutionLock(
	ctx context.Context,
	lease ExecutionLease,
) error {
	leases := r.client.CoordinationV1().Leases(lease.Namespace)
	current, err := leases.Get(ctx, lease.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get execution lease for release: %w", err)
	}
	if current.Spec.HolderIdentity == nil || *current.Spec.HolderIdentity != lease.Holder {
		return fmt.Errorf("%w: holder changed before release", ErrExecutionLockLost)
	}

	resourceVersion := current.ResourceVersion
	if err := leases.Delete(ctx, lease.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			ResourceVersion: &resourceVersion,
		},
	}); apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("release execution lease: %w", err)
	}
	return nil
}

func executionLeaseName(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "state-latch-" + hex.EncodeToString(sum[:12])
}

func kubernetesLeaseExpired(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return true
	}
	if lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds <= 0 {
		return false
	}

	var base time.Time
	switch {
	case lease.Spec.RenewTime != nil:
		base = lease.Spec.RenewTime.Time
	case lease.Spec.AcquireTime != nil:
		base = lease.Spec.AcquireTime.Time
	default:
		return false
	}

	expiresAt := base.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second)
	return !now.Before(expiresAt)
}
