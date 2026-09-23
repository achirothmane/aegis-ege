package kubeadapter

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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
	return New(NewClientGoReader(client)), nil
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
