package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	ABIVersion uint32 = 1

	ActionClassNetworkConnect uint32 = 1

	KernelDecisionBlock uint32 = 0
	KernelDecisionAllow uint32 = 1

	AddressFamilyWildcard uint32 = 0
	AddressFamilyIPv4     uint32 = 2
	AddressFamilyIPv6     uint32 = 10

	EvidenceEventVersion     uint32 = 1
	EvidenceEventEnforcement uint32 = 1

	EvidenceVerdictDeny  uint32 = 0
	EvidenceVerdictAllow uint32 = 1

	ScopeKeySize           = 40
	ScopeFenceKeySize      = 16
	ScopeFenceStateSize    = 56
	DecisionCapsuleSize    = 240
	EvidenceEventSize      = 128
	EvidenceAccountingSize = 24
)

var (
	ErrInvalidScope       = errors.New("invalid kernel enforcement scope")
	ErrInvalidDigest      = errors.New("invalid sha256 digest")
	ErrInvalidCapsule     = errors.New("invalid decision capsule")
	ErrLeaseExpired       = errors.New("decision lease is expired")
	ErrLeaseInvalid       = errors.New("decision lease is invalid")
)

type ScopeKey struct {
	CgroupID        uint64
	ActionClass     uint32
	AddressFamily   uint32
	DestinationAddr [16]byte
	DestinationPort uint32
	Protocol        uint32
}

type ScopeFenceKey struct {
	CgroupID    uint64
	ActionClass uint32
	Reserved    uint32
}

type ScopeFenceState struct {
	BootIDHash      [32]byte
	AuthorityTerm   uint64
	DecisionEpoch   uint64
	RevocationEpoch uint64
}

type DecisionCapsule struct {
	DecisionIDHash    [32]byte
	SubjectHash       [32]byte
	ActionHash        [32]byte
	PolicyHash        [32]byte
	EvidenceHash      [32]byte
	BootIDHash        [32]byte
	AuthorityTerm     uint64
	DecisionEpoch     uint64
	RevocationEpoch   uint64
	InstalledAtMonoNS uint64
	DeadlineMonoNS    uint64
	Decision          uint32
	Constraints       uint32
}

type EvidenceEvent struct {
	Sequence           uint64
	ObservedAtMonoNS   uint64
	CgroupID           uint64
	AuthorityTerm      uint64
	DecisionEpoch      uint64
	RevocationEpoch    uint64
	DecisionIDHash     [32]byte
	ActionClass        uint32
	Verdict            uint32
	Reason             uint32
	AddressFamily      uint32
	DestinationAddr    [16]byte
	DestinationPort    uint32
	Protocol           uint32
	ABIVersion         uint32
	EventType          uint32
}

type EvidenceAccounting struct {
	Sequence uint64
	Emitted  uint64
	Lost     uint64
}

type NetworkScope struct {
	CgroupID   uint64
	Destination netip.Addr
	Port        uint16
	Protocol    uint8
}

func (s NetworkScope) ExactKey() (ScopeKey, error) {
	if s.CgroupID == 0 {
		return ScopeKey{}, fmt.Errorf("%w: cgroup id must be non-zero", ErrInvalidScope)
	}
	if !s.Destination.IsValid() {
		return ScopeKey{}, fmt.Errorf("%w: destination address is required", ErrInvalidScope)
	}
	if s.Port == 0 {
		return ScopeKey{}, fmt.Errorf("%w: destination port must be non-zero", ErrInvalidScope)
	}
	if s.Protocol == 0 {
		return ScopeKey{}, fmt.Errorf("%w: protocol must be non-zero", ErrInvalidScope)
	}

	key := ScopeKey{
		CgroupID:        s.CgroupID,
		ActionClass:     ActionClassNetworkConnect,
		DestinationPort: uint32(s.Port),
		Protocol:        uint32(s.Protocol),
	}
	if s.Destination.Is4() {
		key.AddressFamily = AddressFamilyIPv4
		v4 := s.Destination.As4()
		copy(key.DestinationAddr[:4], v4[:])
		return key, nil
	}
	if s.Destination.Is6() {
		key.AddressFamily = AddressFamilyIPv6
		v6 := s.Destination.As16()
		copy(key.DestinationAddr[:], v6[:])
		return key, nil
	}
	return ScopeKey{}, fmt.Errorf("%w: unsupported address family", ErrInvalidScope)
}

func WildcardNetworkKey(cgroupID uint64) (ScopeKey, error) {
	if cgroupID == 0 {
		return ScopeKey{}, fmt.Errorf("%w: cgroup id must be non-zero", ErrInvalidScope)
	}
	return ScopeKey{
		CgroupID:    cgroupID,
		ActionClass: ActionClassNetworkConnect,
	}, nil
}

func FenceKey(cgroupID uint64, actionClass uint32) (ScopeFenceKey, error) {
	if cgroupID == 0 || actionClass == 0 {
		return ScopeFenceKey{}, fmt.Errorf("%w: cgroup id and action class must be non-zero", ErrInvalidScope)
	}
	return ScopeFenceKey{CgroupID: cgroupID, ActionClass: actionClass}, nil
}

func HashOpaque(value string) ([32]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return [32]byte{}, errors.New("value is required")
	}
	return sha256.Sum256([]byte(value)), nil
}

func ParseSHA256Digest(value string) ([32]byte, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") {
		return [32]byte{}, fmt.Errorf("%w: expected sha256: prefix", ErrInvalidDigest)
	}
	raw := strings.TrimPrefix(value, "sha256:")
	if len(raw) != sha256.Size*2 {
		return [32]byte{}, fmt.Errorf("%w: expected %d hex characters", ErrInvalidDigest, sha256.Size*2)
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrInvalidDigest, err)
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, nil
}

func ValidateCapsule(c DecisionCapsule) error {
	switch {
	case c.AuthorityTerm == 0:
		return fmt.Errorf("%w: authority term must be non-zero", ErrInvalidCapsule)
	case c.DecisionEpoch == 0:
		return fmt.Errorf("%w: decision epoch must be non-zero", ErrInvalidCapsule)
	case c.DeadlineMonoNS == 0:
		return fmt.Errorf("%w: monotonic deadline must be non-zero", ErrInvalidCapsule)
	case c.DeadlineMonoNS <= c.InstalledAtMonoNS:
		return fmt.Errorf("%w: monotonic deadline must follow installation", ErrInvalidCapsule)
	case c.Decision != KernelDecisionAllow && c.Decision != KernelDecisionBlock:
		return fmt.Errorf("%w: unsupported decision %d", ErrInvalidCapsule, c.Decision)
	default:
		return nil
	}
}
