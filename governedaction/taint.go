package governedaction

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrMissingTaintBinding = errors.New("taint egress binding is incomplete")
	ErrTaintBindingChanged = errors.New("taint egress binding changed")
	ErrInvalidTaintLabel    = errors.New("taint label is invalid")
	ErrTaintNotAuthorized   = errors.New("observed taint is not authorized for egress")
)

// TaintEgressBinding describes the taint classes an admitted subject may carry
// across an effect boundary. Empty AllowedLabels means clean-only egress.
//
// MonitorRef/MonitorEpoch identify the trusted taint evidence producer. The
// caller cannot substitute a different monitor or epoch without fresh admission.
type TaintEgressBinding struct {
	SubjectRef    string
	MonitorRef    string
	MonitorEpoch  string
	AllowedLabels []string
}

// TaintEvidence is a no-payload observation. It carries labels and provenance,
// never the sensitive bytes that caused the labels.
type TaintEvidence struct {
	SubjectRef   string
	MonitorRef   string
	MonitorEpoch string
	Labels       []string
}

// CheckTaintEgress enforces explicit taint authorization at the effect boundary.
// Every observed label must be admitted. Unknown/unlisted labels fail closed.
//
// This relation does not discover reads, forks, files, sockets or process
// lineage. A trusted monitor must produce the observation and make propagation
// complete under its declared failure model.
func CheckTaintEgress(admitted TaintEgressBinding, observed TaintEvidence) error {
	fields := []struct {
		name              string
		admitted, observed string
	}{
		{"subject_ref", admitted.SubjectRef, observed.SubjectRef},
		{"monitor_ref", admitted.MonitorRef, observed.MonitorRef},
		{"monitor_epoch", admitted.MonitorEpoch, observed.MonitorEpoch},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.admitted) == "" || strings.TrimSpace(field.observed) == "" {
			return fmt.Errorf("%s: %w", field.name, ErrMissingTaintBinding)
		}
		if field.admitted != field.observed {
			return fmt.Errorf("%s: %w", field.name, ErrTaintBindingChanged)
		}
	}

	allowed, err := canonicalTaintLabels(admitted.AllowedLabels)
	if err != nil {
		return err
	}
	current, err := canonicalTaintLabels(observed.Labels)
	if err != nil {
		return err
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, label := range allowed {
		allowedSet[label] = struct{}{}
	}
	for _, label := range current {
		if _, ok := allowedSet[label]; !ok {
			return fmt.Errorf("%s: %w", label, ErrTaintNotAuthorized)
		}
	}
	return nil
}

func canonicalTaintLabels(labels []string) ([]string, error) {
	result := append([]string(nil), labels...)
	for _, label := range result {
		if label == "" || strings.TrimSpace(label) != label || strings.ContainsAny(label, "\r\n\t ") {
			return nil, fmt.Errorf("%q: %w", label, ErrInvalidTaintLabel)
		}
	}
	sort.Strings(result)
	for i := 1; i < len(result); i++ {
		if result[i] == result[i-1] {
			return nil, fmt.Errorf("%q: %w", result[i], ErrInvalidTaintLabel)
		}
	}
	return result, nil
}
