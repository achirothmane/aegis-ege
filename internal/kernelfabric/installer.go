package kernelfabric

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
)

var ErrKernelStoreUnavailable = errors.New("kernel enforcement store unavailable")

type KernelStore interface {
	PutFence(context.Context, ScopeFenceKey, ScopeFenceState) error
	PutCapsule(context.Context, ScopeKey, DecisionCapsule) error
	DeleteCapsule(context.Context, ScopeKey) error
}

type KernelFenceReader interface {
	GetFence(context.Context, ScopeFenceKey) (ScopeFenceState, error)
}

type InstallRequest struct {
	Scope           ScopeKey
	DecisionID      string
	Subject         string
	Action          string
	PolicyDigest    string
	EvidenceDigest  string
	AuthorityTerm   uint64
	DecisionEpoch   uint64
	RevocationEpoch uint64
	Decision        uint32
	Constraints     uint32
	Lease           ExternalLease
}

type InstallResult struct {
	FenceKey ScopeFenceKey
	Fence    ScopeFenceState
	Scope    ScopeKey
	Capsule  DecisionCapsule
}

type Installer struct {
	Store KernelStore
}

func (i Installer) Install(
	ctx context.Context,
	req InstallRequest,
	clock ClockSnapshot,
) (InstallResult, error) {
	if i.Store == nil {
		return InstallResult{}, ErrKernelStoreUnavailable
	}
	if err := validateScopeKey(req.Scope); err != nil {
		return InstallResult{}, err
	}
	if req.AuthorityTerm == 0 || req.DecisionEpoch == 0 {
		return InstallResult{}, fmt.Errorf("%w: authority term and decision epoch are required", ErrInvalidCapsule)
	}
	localLease, err := BindExternalLease(req.Lease, clock)
	if err != nil {
		return InstallResult{}, err
	}
	decisionIDHash, err := HashOpaque(req.DecisionID)
	if err != nil {
		return InstallResult{}, fmt.Errorf("decision id: %w", err)
	}
	subjectHash, err := HashOpaque(req.Subject)
	if err != nil {
		return InstallResult{}, fmt.Errorf("subject: %w", err)
	}
	actionHash, err := HashOpaque(req.Action)
	if err != nil {
		return InstallResult{}, fmt.Errorf("action: %w", err)
	}
	policyHash, err := ParseSHA256Digest(req.PolicyDigest)
	if err != nil {
		return InstallResult{}, fmt.Errorf("policy digest: %w", err)
	}
	evidenceHash, err := ParseSHA256Digest(req.EvidenceDigest)
	if err != nil {
		return InstallResult{}, fmt.Errorf("evidence digest: %w", err)
	}

	fenceKey, err := FenceKey(req.Scope.CgroupID, req.Scope.ActionClass)
	if err != nil {
		return InstallResult{}, err
	}
	fence := ScopeFenceState{
		BootIDHash:      localLease.BootIDHash,
		AuthorityTerm:   req.AuthorityTerm,
		DecisionEpoch:   req.DecisionEpoch,
		RevocationEpoch: req.RevocationEpoch,
	}
	capsule := DecisionCapsule{
		DecisionIDHash:    decisionIDHash,
		SubjectHash:       subjectHash,
		ActionHash:        actionHash,
		PolicyHash:        policyHash,
		EvidenceHash:      evidenceHash,
		BootIDHash:        localLease.BootIDHash,
		AuthorityTerm:     req.AuthorityTerm,
		DecisionEpoch:     req.DecisionEpoch,
		RevocationEpoch:   req.RevocationEpoch,
		InstalledAtMonoNS: localLease.InstalledAtMonoNS,
		DeadlineMonoNS:    localLease.DeadlineMonoNS,
		Decision:          req.Decision,
		Constraints:       req.Constraints,
	}
	if err := ValidateCapsule(capsule); err != nil {
		return InstallResult{}, err
	}

	// Fence first. Advancing the authoritative scope epoch invalidates any old
	// capsule before a replacement can become visible. A failed second write
	// therefore creates a temporary deny, never a stale allow.
	if err := i.Store.PutFence(ctx, fenceKey, fence); err != nil {
		return InstallResult{}, fmt.Errorf("install kernel scope fence: %w", err)
	}
	if err := i.Store.PutCapsule(ctx, req.Scope, capsule); err != nil {
		_ = i.Store.DeleteCapsule(context.WithoutCancel(ctx), req.Scope)
		return InstallResult{}, fmt.Errorf("install kernel decision capsule after fence: %w", err)
	}

	return InstallResult{
		FenceKey: fenceKey,
		Fence:    fence,
		Scope:    req.Scope,
		Capsule:  capsule,
	}, nil
}

func (i Installer) RevokeCurrentScope(
	ctx context.Context,
	key ScopeFenceKey,
) (ScopeFenceState, error) {
	if i.Store == nil {
		return ScopeFenceState{}, ErrKernelStoreUnavailable
	}
	reader, ok := i.Store.(KernelFenceReader)
	if !ok {
		return ScopeFenceState{}, errors.New("kernel enforcement store cannot read current scope fence")
	}
	current, err := reader.GetFence(ctx, key)
	if err != nil {
		return ScopeFenceState{}, fmt.Errorf("read current kernel scope fence: %w", err)
	}
	if current.RevocationEpoch == math.MaxUint64 {
		return ScopeFenceState{}, errors.New("kernel scope revocation epoch exhausted")
	}
	next := current
	next.RevocationEpoch++
	if err := i.RevokeScope(ctx, key, next); err != nil {
		return ScopeFenceState{}, err
	}
	return next, nil
}

func (i Installer) RevokeScope(
	ctx context.Context,
	key ScopeFenceKey,
	next ScopeFenceState,
) error {
	if i.Store == nil {
		return ErrKernelStoreUnavailable
	}
	if key.CgroupID == 0 || key.ActionClass == 0 {
		return ErrInvalidScope
	}
	if next.AuthorityTerm == 0 || next.DecisionEpoch == 0 {
		return fmt.Errorf("%w: authority term and decision epoch are required", ErrInvalidCapsule)
	}
	if bytes.Equal(next.BootIDHash[:], make([]byte, len(next.BootIDHash))) {
		return fmt.Errorf("%w: boot id hash is required", ErrInvalidCapsule)
	}
	// Revocation is one map write. All exact and wildcard capsules under the
	// scope become invalid immediately because kernel evaluation compares the
	// epochs against this fence.
	return i.Store.PutFence(ctx, key, next)
}

func validateScopeKey(key ScopeKey) error {
	if key.CgroupID == 0 || key.ActionClass == 0 {
		return fmt.Errorf("%w: cgroup id and action class must be non-zero", ErrInvalidScope)
	}
	switch key.AddressFamily {
	case AddressFamilyWildcard:
		if key.DestinationPort != 0 || key.Protocol != 0 || key.DestinationAddr != [16]byte{} {
			return fmt.Errorf("%w: wildcard scope cannot contain destination fields", ErrInvalidScope)
		}
	case AddressFamilyIPv4, AddressFamilyIPv6:
		if key.DestinationPort == 0 || key.Protocol == 0 {
			return fmt.Errorf("%w: exact network scope requires port and protocol", ErrInvalidScope)
		}
	default:
		return fmt.Errorf("%w: unsupported address family %d", ErrInvalidScope, key.AddressFamily)
	}
	return nil
}
