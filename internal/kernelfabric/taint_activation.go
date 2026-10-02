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
	File   TaintFileKey `json:"file"`
	Labels uint64       `json:"labels"`
}

type TaintActivationPlan struct {
	CgroupPath   string               `json:"cgroup_path"`
	AllowedLabels uint64              `json:"allowed_labels"`
	Sources      []TaintSourceBinding `json:"sources"`
}

func ValidateTaintActivationPlan(plan TaintActivationPlan) error {
	cgroup := filepath.Clean(strings.TrimSpace(plan.CgroupPath))
	if cgroup == "." || !filepath.IsAbs(cgroup) {
		return fmt.Errorf("%w: cgroup_path must be absolute", ErrTaintActivationPlan)
	}
	if len(plan.Sources) == 0 {
		return fmt.Errorf("%w: at least one sensitive source is required", ErrTaintActivationPlan)
	}
	seen := make(map[TaintFileKey]struct{}, len(plan.Sources))
	for _, source := range plan.Sources {
		if source.File.Device == 0 || source.File.Inode == 0 || source.Labels == 0 {
			return fmt.Errorf("%w: source binding is incomplete", ErrTaintActivationPlan)
		}
		if _, exists := seen[source.File]; exists {
			return fmt.Errorf("%w: duplicate source identity %+v", ErrTaintActivationPlan, source.File)
		}
		seen[source.File] = struct{}{}
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
	sort.Slice(normalized.Sources, func(i, j int) bool {
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
