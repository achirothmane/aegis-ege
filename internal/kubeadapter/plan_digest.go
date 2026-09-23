package kubeadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type canonicalDrainPlan struct {
	ActionID            string               `json:"action_id"`
	NodeName            string               `json:"node_name"`
	NodeResourceVersion string               `json:"node_resource_version"`
	Steps               []canonicalDrainStep `json:"steps"`
}

type canonicalDrainStep struct {
	Kind               DrainExecutionStepKind `json:"kind"`
	NodeName           string                 `json:"node_name,omitempty"`
	ResourceVersion    string                 `json:"resource_version,omitempty"`
	PodNamespace       string                 `json:"pod_namespace,omitempty"`
	PodName            string                 `json:"pod_name,omitempty"`
	PodUID             string                 `json:"pod_uid,omitempty"`
	PodResourceVersion string                 `json:"pod_resource_version,omitempty"`
}

func DigestDrainExecutionPlan(plan DrainExecutionPlan) string {
	canonical := canonicalDrainPlan{
		ActionID:            plan.ActionID,
		NodeName:            plan.NodeName,
		NodeResourceVersion: plan.NodeResourceVersion,
		Steps:               make([]canonicalDrainStep, 0, len(plan.Steps)),
	}

	for _, step := range plan.Steps {
		item := canonicalDrainStep{
			Kind:            step.Kind,
			NodeName:        step.NodeName,
			ResourceVersion: step.ResourceVersion,
		}
		if step.Pod != nil {
			item.PodNamespace = step.Pod.Namespace
			item.PodName = step.Pod.Name
			item.PodUID = step.Pod.UID
			item.PodResourceVersion = step.Pod.ResourceVersion
		}
		canonical.Steps = append(canonical.Steps, item)
	}

	payload, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(hash[:])
}
