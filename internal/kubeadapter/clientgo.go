package kubeadapter

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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
