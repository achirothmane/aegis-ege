package kubeadapter

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/achirothmane/state-latch/internal/decision"
)

const mirrorPodAnnotationKey = "kubernetes.io/config.mirror"

type DrainFindingCode string

const (
	FindingDaemonSetRequiresIgnore  DrainFindingCode = "DAEMONSET_POD_REQUIRES_IGNORE"
	FindingUnmanagedPodRequiresForce DrainFindingCode = "UNMANAGED_POD_REQUIRES_FORCE"
	FindingEmptyDirRequiresDelete    DrainFindingCode = "EMPTYDIR_DATA_REQUIRES_DELETE"
	FindingMirrorPodSkipped          DrainFindingCode = "MIRROR_POD_SKIPPED"
	FindingPDBDisruptionBlocked      DrainFindingCode = "PDB_DISRUPTION_BLOCKED"
	FindingPDBStatusStale            DrainFindingCode = "PDB_STATUS_STALE"
	FindingPDBEvidenceUnavailable    DrainFindingCode = "PDB_EVIDENCE_UNAVAILABLE"
	FindingPDBSelectorInvalid        DrainFindingCode = "PDB_SELECTOR_INVALID"
)

type FindingSeverity string

const (
	FindingInfo     FindingSeverity = "INFO"
	FindingBlock    FindingSeverity = "BLOCK"
	FindingEscalate FindingSeverity = "ESCALATE"
)

type DrainFinding struct {
	Code      DrainFindingCode
	Severity  FindingSeverity
	Namespace string
	Pod       string
	PDB       string
	Detail    string
}

type PodStateRef struct {
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	StateDigest     string
}

type DrainPreflightReport struct {
	Decision             decision.Decision
	EvictablePods        int
	EvictionCandidates   []PodStateRef
	SkippedMirrorPods    int
	SkippedDaemonSetPods int
	Findings             []DrainFinding
}

type PodDisruptionBudgetView struct {
	Namespace          string
	Name               string
	Generation         int64
	ObservedGeneration int64
	DisruptionsAllowed int32
	Selector           *metav1.LabelSelector
}

func (a *Adapter) PreflightNodeDrain(
	ctx context.Context,
	nodeName string,
	policy NodeDrainPolicy,
) (DrainPreflightReport, error) {
	_, pods, err := a.inspectNodeDrainState(ctx, nodeName)
	if err != nil {
		return DrainPreflightReport{}, err
	}
	return a.preflightNodeDrain(ctx, pods, policy), nil
}

func (a *Adapter) preflightNodeDrain(
	ctx context.Context,
	pods []corev1.Pod,
	policy NodeDrainPolicy,
) DrainPreflightReport {
	report := DrainPreflightReport{Decision: decision.Allow}
	evictionCandidates := make([]corev1.Pod, 0, len(pods))

	for _, pod := range pods {
		if isTerminalPod(pod) {
			continue
		}

		if isMirrorPod(pod) {
			report.SkippedMirrorPods++
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingMirrorPodSkipped,
				Severity:  FindingInfo,
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Detail:    "mirror/static pod is not deleted by drain",
			})
			continue
		}

		if isDaemonSetPod(pod) {
			report.SkippedDaemonSetPods++
			if !policy.IgnoreDaemonSets {
				report.Findings = append(report.Findings, DrainFinding{
					Code:      FindingDaemonSetRequiresIgnore,
					Severity:  FindingBlock,
					Namespace: pod.Namespace,
					Pod:       pod.Name,
					Detail:    "DaemonSet-managed pod requires explicit ignore-daemonsets policy",
				})
			}
			continue
		}

		if !isDrainManagedPod(pod) && !policy.ForceUnmanagedPods {
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingUnmanagedPodRequiresForce,
				Severity:  FindingBlock,
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Detail:    "pod has no supported workload controller and requires explicit force policy",
			})
		}

		if usesEmptyDir(pod) && !policy.DeleteEmptyDirData {
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingEmptyDirRequiresDelete,
				Severity:  FindingBlock,
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Detail:    "pod uses emptyDir data that would be deleted by drain",
			})
		}

		evictionCandidates = append(evictionCandidates, pod)
	}

	report.EvictablePods = len(evictionCandidates)
	report.EvictionCandidates = make([]PodStateRef, 0, len(evictionCandidates))
	for _, pod := range evictionCandidates {
		report.EvictionCandidates = append(report.EvictionCandidates, PodStateRef{
			Namespace:       pod.Namespace,
			Name:            pod.Name,
			UID:             string(pod.UID),
			ResourceVersion: pod.ResourceVersion,
			StateDigest:     DigestDrainRelevantPodState(pod),
		})
	}
	sort.Slice(report.EvictionCandidates, func(i, j int) bool {
		left := report.EvictionCandidates[i].Namespace + "/" + report.EvictionCandidates[i].Name
		right := report.EvictionCandidates[j].Namespace + "/" + report.EvictionCandidates[j].Name
		return left < right
	})

	pdbs, err := a.reader.ListPodDisruptionBudgets(ctx)
	if err != nil {
		report.Findings = append(report.Findings, DrainFinding{
			Code:     FindingPDBEvidenceUnavailable,
			Severity: FindingEscalate,
			Detail:   fmt.Sprintf("cannot read PodDisruptionBudgets: %v", err),
		})
		return finalizePreflight(report)
	}

	for _, pdb := range pdbs {
		matched, selectorErr := podsMatchingPDB(evictionCandidates, pdb)
		if selectorErr != nil {
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingPDBSelectorInvalid,
				Severity:  FindingEscalate,
				Namespace: pdb.Namespace,
				PDB:       pdb.Name,
				Detail:    selectorErr.Error(),
			})
			continue
		}
		if matched == 0 {
			continue
		}

		if pdb.ObservedGeneration != pdb.Generation {
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingPDBStatusStale,
				Severity:  FindingEscalate,
				Namespace: pdb.Namespace,
				PDB:       pdb.Name,
				Detail:    fmt.Sprintf("PDB status observedGeneration=%d does not match generation=%d", pdb.ObservedGeneration, pdb.Generation),
			})
			continue
		}

		if int32(matched) > pdb.DisruptionsAllowed {
			report.Findings = append(report.Findings, DrainFinding{
				Code:      FindingPDBDisruptionBlocked,
				Severity:  FindingBlock,
				Namespace: pdb.Namespace,
				PDB:       pdb.Name,
				Detail:    fmt.Sprintf("%d target pods match PDB but only %d disruptions are currently allowed", matched, pdb.DisruptionsAllowed),
			})
		}
	}

	return finalizePreflight(report)
}

func finalizePreflight(report DrainPreflightReport) DrainPreflightReport {
	hasEscalation := false
	for _, finding := range report.Findings {
		switch finding.Severity {
		case FindingBlock:
			report.Decision = decision.Block
			return report
		case FindingEscalate:
			hasEscalation = true
		}
	}

	if hasEscalation {
		report.Decision = decision.Escalate
	} else {
		report.Decision = decision.Allow
	}
	return report
}

func podsMatchingPDB(pods []corev1.Pod, pdb PodDisruptionBudgetView) (int, error) {
	if pdb.Selector == nil {
		return 0, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(pdb.Selector)
	if err != nil {
		return 0, fmt.Errorf("invalid PDB selector: %w", err)
	}
	if selector == nil {
		selector = labels.Nothing()
	}

	matched := 0
	for _, pod := range pods {
		if pod.Namespace != pdb.Namespace {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			matched++
		}
	}
	return matched, nil
}

func isMirrorPod(pod corev1.Pod) bool {
	_, ok := pod.Annotations[mirrorPodAnnotationKey]
	return ok
}

func isDaemonSetPod(pod corev1.Pod) bool {
	owner := controllerOwner(pod)
	return owner != nil && owner.Kind == "DaemonSet"
}

func isDrainManagedPod(pod corev1.Pod) bool {
	owner := controllerOwner(pod)
	if owner == nil {
		return false
	}

	switch owner.Kind {
	case "ReplicationController", "ReplicaSet", "DaemonSet", "StatefulSet", "Job":
		return true
	default:
		return false
	}
}

func controllerOwner(pod corev1.Pod) *metav1.OwnerReference {
	for i := range pod.OwnerReferences {
		owner := &pod.OwnerReferences[i]
		if owner.Controller != nil && *owner.Controller {
			return owner
		}
	}
	return nil
}

func usesEmptyDir(pod corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.EmptyDir != nil {
			return true
		}
	}
	return false
}
