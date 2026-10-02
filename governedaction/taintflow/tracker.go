package taintflow

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

var (
	ErrMissingReference = errors.New("taint-flow reference is required")
	ErrUnknownProcess    = errors.New("taint-flow process is unknown")
	ErrUnknownChannel    = errors.New("taint-flow channel is unknown")
	ErrInvalidLabel      = errors.New("taint-flow label is invalid")
)

// Tracker is a monotonic in-memory taint propagation model used only by the
// Muse-class adversarial corpus. It is not a production process monitor.
//
// Labels can be added and propagated, never silently removed. Fork copies the
// complete parent label set to the child. Write unions process labels into a
// channel. Read unions channel labels into the destination process.
type Tracker struct {
	mu           sync.RWMutex
	monitorRef   string
	monitorEpoch string
	processes    map[string]map[string]struct{}
	channels     map[string]map[string]struct{}
}

func New(monitorRef, monitorEpoch string) (*Tracker, error) {
	if strings.TrimSpace(monitorRef) == "" || strings.TrimSpace(monitorEpoch) == "" {
		return nil, ErrMissingReference
	}
	return &Tracker{
		monitorRef:   monitorRef,
		monitorEpoch: monitorEpoch,
		processes:    make(map[string]map[string]struct{}),
		channels:     make(map[string]map[string]struct{}),
	}, nil
}

func (t *Tracker) RegisterProcess(processRef string) error {
	if strings.TrimSpace(processRef) == "" {
		return ErrMissingReference
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.processes[processRef]; !exists {
		t.processes[processRef] = make(map[string]struct{})
	}
	return nil
}

func (t *Tracker) TaintProcess(processRef, label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	labels, ok := t.processes[processRef]
	if !ok {
		return ErrUnknownProcess
	}
	labels[label] = struct{}{}
	return nil
}

func (t *Tracker) Fork(parentRef, childRef string) error {
	if strings.TrimSpace(childRef) == "" {
		return ErrMissingReference
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	parent, ok := t.processes[parentRef]
	if !ok {
		return ErrUnknownProcess
	}
	if _, exists := t.processes[childRef]; exists {
		return fmt.Errorf("child process %q already exists", childRef)
	}
	child := make(map[string]struct{}, len(parent))
	for label := range parent {
		child[label] = struct{}{}
	}
	t.processes[childRef] = child
	return nil
}

func (t *Tracker) Write(processRef, channelRef string) error {
	if strings.TrimSpace(channelRef) == "" {
		return ErrMissingReference
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	process, ok := t.processes[processRef]
	if !ok {
		return ErrUnknownProcess
	}
	channel := t.channels[channelRef]
	if channel == nil {
		channel = make(map[string]struct{})
		t.channels[channelRef] = channel
	}
	for label := range process {
		channel[label] = struct{}{}
	}
	return nil
}

func (t *Tracker) Read(processRef, channelRef string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	process, ok := t.processes[processRef]
	if !ok {
		return ErrUnknownProcess
	}
	channel, ok := t.channels[channelRef]
	if !ok {
		return ErrUnknownChannel
	}
	for label := range channel {
		process[label] = struct{}{}
	}
	return nil
}

func (t *Tracker) Observation(processRef string) (ga.TaintEvidence, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	labels, ok := t.processes[processRef]
	if !ok {
		return ga.TaintEvidence{}, ErrUnknownProcess
	}
	return ga.TaintEvidence{
		SubjectRef:   processRef,
		MonitorRef:   t.monitorRef,
		MonitorEpoch: t.monitorEpoch,
		Labels:       sortedLabels(labels),
	}, nil
}

func (t *Tracker) ChannelLabels(channelRef string) ([]string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	labels, ok := t.channels[channelRef]
	if !ok {
		return nil, ErrUnknownChannel
	}
	return sortedLabels(labels), nil
}

func validateLabel(label string) error {
	if label == "" || strings.TrimSpace(label) != label || strings.ContainsAny(label, "\r\n\t ") {
		return ErrInvalidLabel
	}
	return nil
}

func sortedLabels(labels map[string]struct{}) []string {
	result := make([]string, 0, len(labels))
	for label := range labels {
		result = append(result, label)
	}
	sort.Strings(result)
	return result
}
