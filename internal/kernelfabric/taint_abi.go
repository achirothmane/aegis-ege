package kernelfabric

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

const (
	TaintABIVersion uint32 = 1

	TaintOperationRead    uint32 = 1
	TaintOperationWrite   uint32 = 2
	TaintOperationFork    uint32 = 3
	TaintOperationConnect uint32 = 4

	TaintEventSourceRead         uint32 = 1
	TaintEventPropagatedRead     uint32 = 2
	TaintEventPropagatedWrite    uint32 = 3
	TaintEventForkPropagation    uint32 = 4
	TaintEventPropagationFailure uint32 = 5
	TaintEventEgressAllow        uint32 = 6
	TaintEventEgressDeny         uint32 = 7
	TaintEventFileReadObserved   uint32 = 8

	TaintFileKeySize    = 16
	TaintProbeKeySize   = 24
	TaintEventSize      = 72
	TaintAccountingSize = 24
)

var (
	ErrTaintABIInvalid      = errors.New("kernel taint ABI value is invalid")
	ErrTaintLabelUnmapped   = errors.New("kernel taint label bit is unmapped")
	ErrTaintLabelMapInvalid = errors.New("kernel taint label registry is invalid")
)

type TaintFileKey struct {
	Device uint64
	Inode  uint64
}

type TaintProbeKey struct {
	TID      uint32
	Reserved uint32
	Device   uint64
	Inode    uint64
}

type TaintEvent struct {
	Sequence         uint64
	ObservedAtMonoNS uint64
	CgroupID         uint64
	FileDevice       uint64
	FileInode        uint64
	Labels           uint64
	TGID             uint32
	RelatedTGID      uint32
	EventType        uint32
	Operation        uint32
	ABIVersion       uint32
	Reserved         uint32
}

type TaintAccounting struct {
	Sequence uint64
	Emitted  uint64
	Lost     uint64
}

// DecodeTaintLabels maps kernel bit positions to profile-owned semantic labels.
// The kernel owns only the bitset transport; the profile owns meanings.
//
// Every observed set bit must have exactly one non-empty label. Unknown bits
// fail closed rather than silently disappearing from the evidence presented to
// CheckTaintEgress.
func DecodeTaintLabels(bits uint64, labelByBit map[uint8]string) ([]string, error) {
	if bits == 0 {
		return nil, nil
	}
	if len(labelByBit) == 0 {
		return nil, ErrTaintLabelUnmapped
	}

	seenLabels := make(map[string]struct{}, len(labelByBit))
	for bit, label := range labelByBit {
		if bit >= 64 {
			return nil, fmt.Errorf("%w: bit %d", ErrTaintLabelMapInvalid, bit)
		}
		if label == "" || strings.TrimSpace(label) != label || strings.ContainsAny(label, "\r\n\t ") {
			return nil, fmt.Errorf("%w: label %q", ErrTaintLabelMapInvalid, label)
		}
		if _, duplicate := seenLabels[label]; duplicate {
			return nil, fmt.Errorf("%w: duplicate label %q", ErrTaintLabelMapInvalid, label)
		}
		seenLabels[label] = struct{}{}
	}

	labels := make([]string, 0, 8)
	for bit := uint8(0); bit < 64; bit++ {
		if bits&(uint64(1)<<bit) == 0 {
			continue
		}
		label, ok := labelByBit[bit]
		if !ok {
			return nil, fmt.Errorf("%w: bit %d", ErrTaintLabelUnmapped, bit)
		}
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels, nil
}

// BuildTaintEvidence converts a kernel bitset into the standalone
// governed-action relation without inventing a process identity. The caller
// must supply a subject_ref derived from its trusted Linux process-identity
// evidence (boot/start-time/executable/cgroup lineage), not from an actor label.
func BuildTaintEvidence(
	subjectRef string,
	monitorRef string,
	monitorEpoch string,
	bits uint64,
	labelByBit map[uint8]string,
) (ga.TaintEvidence, error) {
	if strings.TrimSpace(subjectRef) == "" ||
		strings.TrimSpace(monitorRef) == "" ||
		strings.TrimSpace(monitorEpoch) == "" {
		return ga.TaintEvidence{}, fmt.Errorf("%w: evidence provenance is incomplete", ErrTaintABIInvalid)
	}
	labels, err := DecodeTaintLabels(bits, labelByBit)
	if err != nil {
		return ga.TaintEvidence{}, err
	}
	return ga.TaintEvidence{
		SubjectRef:   subjectRef,
		MonitorRef:   monitorRef,
		MonitorEpoch: monitorEpoch,
		Labels:       labels,
	}, nil
}
