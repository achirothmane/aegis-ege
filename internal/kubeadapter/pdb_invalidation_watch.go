package kubeadapter

import (
	"context"
	"fmt"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/achirothmane/aegis-ege/internal/epistemic"
)

type PDBInvalidationWatcher struct {
	Client    kubernetes.Interface
	Namespace string
	Name      string
}

func (w *PDBInvalidationWatcher) Run(
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
			return w.Client.PolicyV1().PodDisruptionBudgets(w.Namespace).List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector
			return w.Client.PolicyV1().PodDisruptionBudgets(w.Namespace).Watch(ctx, options)
		},
	}

	informer := cache.NewSharedInformer(lw, &policyv1.PodDisruptionBudget{}, 0)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			oldPDB, okOld := oldObj.(*policyv1.PodDisruptionBudget)
			newPDB, okNew := newObj.(*policyv1.PodDisruptionBudget)
			if !okOld || !okNew || oldPDB.ResourceVersion == newPDB.ResourceVersion {
				return
			}
			emitEpistemicEvent(ctx, out, "MODIFIED", pdbResourceRef(newPDB))
		},
		DeleteFunc: func(obj any) {
			pdb, ok := obj.(*policyv1.PodDisruptionBudget)
			if !ok {
				if tombstone, okTombstone := obj.(cache.DeletedFinalStateUnknown); okTombstone {
					pdb, _ = tombstone.Obj.(*policyv1.PodDisruptionBudget)
				}
			}
			if pdb == nil {
				return
			}
			emitEpistemicEvent(ctx, out, "DELETED", pdbResourceRef(pdb))
		},
	})

	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("PDB informer cache failed to sync")
	}

	if synced != nil {
		close(synced)
	}

	<-ctx.Done()
	return nil
}

func pdbResourceRef(pdb *policyv1.PodDisruptionBudget) epistemic.ResourceRef {
	return epistemic.ResourceRef{
		APIVersion:      "policy/v1",
		Kind:            "PodDisruptionBudget",
		Namespace:       pdb.Namespace,
		Name:            pdb.Name,
		UID:             string(pdb.UID),
		ResourceVersion: pdb.ResourceVersion,
	}
}
