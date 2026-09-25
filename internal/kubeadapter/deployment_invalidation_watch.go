package kubeadapter

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/achirothmane/aegis-ege/internal/epistemic"
)

type DeploymentInvalidationWatcher struct {
	Client    kubernetes.Interface
	Namespace string
	Name      string
}

func (w *DeploymentInvalidationWatcher) Run(
	ctx context.Context,
	out chan<- epistemic.ResourceEvent,
	synced chan<- struct{},
) error {
	if w.Client == nil {
		return fmt.Errorf("nil kubernetes client")
	}

	selector := ""
	if w.Name != "" {
		selector = fields.OneTermEqualSelector("metadata.name", w.Name).String()
	}

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector
			return w.Client.AppsV1().Deployments(w.Namespace).List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector
			return w.Client.AppsV1().Deployments(w.Namespace).Watch(ctx, options)
		},
	}

	informer := cache.NewSharedInformer(lw, &appsv1.Deployment{}, 0)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			oldDeployment, okOld := oldObj.(*appsv1.Deployment)
			newDeployment, okNew := newObj.(*appsv1.Deployment)
			if !okOld || !okNew || oldDeployment.ResourceVersion == newDeployment.ResourceVersion {
				return
			}
			emitEpistemicEvent(ctx, out, "MODIFIED", deploymentResourceRef(newDeployment))
		},
		DeleteFunc: func(obj any) {
			deployment, ok := obj.(*appsv1.Deployment)
			if !ok {
				if tombstone, okTombstone := obj.(cache.DeletedFinalStateUnknown); okTombstone {
					deployment, _ = tombstone.Obj.(*appsv1.Deployment)
				}
			}
			if deployment == nil {
				return
			}
			emitEpistemicEvent(ctx, out, "DELETED", deploymentResourceRef(deployment))
		},
	})

	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("deployment informer cache failed to sync")
	}

	if synced != nil {
		close(synced)
	}

	<-ctx.Done()
	return nil
}

func emitEpistemicEvent(
	ctx context.Context,
	out chan<- epistemic.ResourceEvent,
	eventType string,
	resource epistemic.ResourceRef,
) {
	event := epistemic.ResourceEvent{
		Type:     eventType,
		Resource: resource,
		At:       time.Now().UTC(),
	}
	select {
	case out <- event:
	case <-ctx.Done():
	}
}

func deploymentResourceRef(deployment *appsv1.Deployment) epistemic.ResourceRef {
	return epistemic.ResourceRef{
		APIVersion:      "apps/v1",
		Kind:            "Deployment",
		Namespace:       deployment.Namespace,
		Name:            deployment.Name,
		UID:             string(deployment.UID),
		ResourceVersion: deployment.ResourceVersion,
	}
}
