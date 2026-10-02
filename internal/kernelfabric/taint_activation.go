package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrTaintActivationPlan = errors.New("taint activation plan is invalid")

type TaintSourceBinding struct {
	Path   string       `json:"path"`
	File   TaintFileKey `json:"file"`
	Labels uint64       `json:"labels"`
}

type TaintActivationPlan struct {
	CgroupPath       string               `json:"cgroup_path"`
	MountNamespaceID uint64               `json:"mount_namespace_id"`
	AllowedLabels    uint64               `json:"allowed_labels"`
	Sources          []TaintSourceBinding `json:"sources"`
}

func ValidateTaintActivationPlan(plan TaintActivationPlan) error {
	cgroup := filepath.Clean(strings.TrimSpace(plan.CgroupPath))
	if cgroup == "." || !filepath.IsAbs(cgroup) {
		return fmt.Errorf("%w: cgroup_path must be absolute", ErrTaintActivationPlan)
	}
	if plan.MountNamespaceID == 0 {
		return fmt.Errorf("%w: mount_namespace_id must be non-zero", ErrTaintActivationPlan)
	}
	if len(plan.Sources) == 0 {
		return fmt.Errorf("%w: at least one sensitive source is required", ErrTaintActivationPlan)
	}
	seen := make(map[TaintFileKey]struct{}, len(plan.Sources))
	pathLabels := make(map[string]uint64)
	for _, source := range plan.Sources {
		path := filepath.Clean(strings.TrimSpace(source.Path))
		if path == "." || !filepath.IsAbs(path) {
			return fmt.Errorf("%w: source path must be absolute", ErrTaintActivationPlan)
		}
		if source.File.Device == 0 || source.File.Inode == 0 || source.Labels == 0 {
			return fmt.Errorf("%w: source binding is incomplete", ErrTaintActivationPlan)
		}
		if _, exists := seen[source.File]; exists {
			return fmt.Errorf("%w: duplicate source identity %+v", ErrTaintActivationPlan, source.File)
		}
		if labels, exists := pathLabels[path]; exists && labels != source.Labels {
			return fmt.Errorf(
				"%w: source path %s has inconsistent label sets",
				ErrTaintActivationPlan,
				path,
			)
		}
		seen[source.File] = struct{}{}
		pathLabels[path] = source.Labels
	}
	return nil
}

func TaintActivationPlanDigest(plan TaintActivationPlan) (string, error) {
	if err := ValidateTaintActivationPlan(plan); err != nil {
		return "", err
	}
	normalized := plan
	normalized.CgroupPath = filepath.Clean(strings.TrimSpace(plan.CgroupPath))
	normalized.Sources = append([]TaintSourceBinding(nil), plan.Sources...)
	for i := range normalized.Sources {
		normalized.Sources[i].Path = filepath.Clean(strings.TrimSpace(normalized.Sources[i].Path))
	}
	sort.Slice(normalized.Sources, func(i, j int) bool {
		if normalized.Sources[i].Path != normalized.Sources[j].Path {
			return normalized.Sources[i].Path < normalized.Sources[j].Path
		}
		if normalized.Sources[i].File.Device != normalized.Sources[j].File.Device {
			return normalized.Sources[i].File.Device < normalized.Sources[j].File.Device
		}
		return normalized.Sources[i].File.Inode < normalized.Sources[j].File.Inode
	})
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("aegis-ege/taint-activation-plan/v0\x00"), payload...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func LoadTaintActivationPlan(path string) (TaintActivationPlan, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return TaintActivationPlan{}, err
	}
	var plan TaintActivationPlan
	if err := json.Unmarshal(payload, &plan); err != nil {
		return TaintActivationPlan{}, fmt.Errorf("decode taint activation plan: %w", err)
	}
	if err := ValidateTaintActivationPlan(plan); err != nil {
		return TaintActivationPlan{}, err
	}
	return plan, nil
}

func WriteTaintActivationPlan(path string, plan TaintActivationPlan) error {
	if err := ValidateTaintActivationPlan(plan); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o600)
}
