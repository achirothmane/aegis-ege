package kubeadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	corev1 "k8s.io/api/core/v1"
)

type canonicalPodDrainState struct {
	Namespace        string                  `json:"namespace"`
	Name             string                  `json:"name"`
	UID              string                  `json:"uid"`
	NodeName         string                  `json:"node_name"`
	Labels           []string                `json:"labels"`
	Controller       *canonicalPodController `json:"controller,omitempty"`
	MirrorAnnotation string                  `json:"mirror_annotation,omitempty"`
	HasEmptyDir      bool                    `json:"has_empty_dir"`
	Phase            corev1.PodPhase         `json:"phase"`
	Ready            bool                    `json:"ready"`
	Terminal         bool                    `json:"terminal"`
	Deleting         bool                    `json:"deleting"`
}

type canonicalPodController struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

func isPodReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func DigestDrainRelevantPodState(pod corev1.Pod) string {
	labelPairs := make([]string, 0, len(pod.Labels))
	for key, value := range pod.Labels {
		labelPairs = append(labelPairs, key+"="+value)
	}
	sort.Strings(labelPairs)

	var controller *canonicalPodController
	if owner := controllerOwner(pod); owner != nil {
		controller = &canonicalPodController{
			APIVersion: owner.APIVersion,
			Kind:       owner.Kind,
			Name:       owner.Name,
			UID:        string(owner.UID),
		}
	}

	state := canonicalPodDrainState{
		Namespace:        pod.Namespace,
		Name:             pod.Name,
		UID:              string(pod.UID),
		NodeName:         pod.Spec.NodeName,
		Labels:           labelPairs,
		Controller:       controller,
		MirrorAnnotation: pod.Annotations[mirrorPodAnnotationKey],
		HasEmptyDir:      usesEmptyDir(pod),
		Phase:            pod.Status.Phase,
		Ready:            isPodReady(pod),
		Terminal:         isTerminalPod(pod),
		Deleting:         pod.DeletionTimestamp != nil,
	}

	payload, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(hash[:])
}
