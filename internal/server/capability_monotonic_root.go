package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

var (
	ErrCapabilityMonotonicRootBehind = errors.New("independent capability monotonic root is behind mutable authority")
	ErrCapabilityMonotonicRootInvalid = errors.New("independent capability monotonic root is invalid")
)

// CapabilityMonotonicRoot is an independent high-water authority for capability
// fencing coordinates.
//
// Advance must atomically preserve monotonicity for the supplied scope: after a
// successful observation of Tn+1, a later Advance(Tn) must not lower the root.
// It returns the resulting high-water snapshot.
//
// Current must return that high-water snapshot from the independent failure
// domain. Implementations that cannot prove the current root must return an
// error so execution fails closed.
type CapabilityMonotonicRoot interface {
	Advance(
		context.Context,
		CapabilityFenceScope,
		egeproto.CapabilityAuthoritySnapshot,
	) (egeproto.CapabilityAuthoritySnapshot, error)
	Current(
		context.Context,
		CapabilityFenceScope,
	) (egeproto.CapabilityAuthoritySnapshot, error)
}

// IndependentRootCapabilityAuthority decorates a mutable capability authority
// with an independent monotonic high-water root.
//
// The mutable authority remains responsible for issuing and coordinating the
// live authority snapshot. The root is responsible only for remembering the
// greatest accepted authority coordinate. If mutable coordination is restored
// to an older value while the root remains newer, Current returns the newer root
// snapshot. The existing capability-fence validator then rejects the old permit
// before the mutation controller can run.
type IndependentRootCapabilityAuthority struct {
	Mutable CapabilityFenceAuthority
	Root    CapabilityMonotonicRoot
}

func NewIndependentRootCapabilityAuthority(
	mutable CapabilityFenceAuthority,
	root CapabilityMonotonicRoot,
) (*IndependentRootCapabilityAuthority, error) {
	if mutable == nil {
		return nil, errors.New("mutable capability fence authority is required")
	}
	if root == nil {
		return nil, errors.New("independent capability monotonic root is required")
	}
	return &IndependentRootCapabilityAuthority{
		Mutable: mutable,
		Root:    root,
	}, nil
}

func (a *IndependentRootCapabilityAuthority) Issue(
	ctx context.Context,
	scope CapabilityFenceScope,
) (CapabilityFenceIssue, error) {
	issue, err := a.Mutable.Issue(ctx, scope)
	if err != nil {
		return CapabilityFenceIssue{}, err
	}

	observed := capabilityAuthoritySnapshotFromIssue(issue)
	root, err := a.Root.Advance(ctx, scope, observed)
	if err != nil {
		return CapabilityFenceIssue{}, fmt.Errorf("advance independent capability monotonic root: %w", err)
	}

	relation, err := compareCapabilityMonotonicRoot(root, observed)
	if err != nil {
		return CapabilityFenceIssue{}, err
	}
	switch relation {
	case capabilityRootEqual:
		return issue, nil
	case capabilityRootAhead:
		return CapabilityFenceIssue{}, fmt.Errorf(
			"independent capability monotonic root supersedes mutable issue: %w",
			capabilityRootAheadError(root, observed),
		)
	case capabilityRootBehind:
		return CapabilityFenceIssue{}, fmt.Errorf(
			"%w after advance: root=%s mutable=%s",
			ErrCapabilityMonotonicRootBehind,
			formatCapabilityAuthoritySnapshot(root),
			formatCapabilityAuthoritySnapshot(observed),
		)
	default:
		return CapabilityFenceIssue{}, ErrCapabilityMonotonicRootInvalid
	}
}

func (a *IndependentRootCapabilityAuthority) Current(
	ctx context.Context,
	scope CapabilityFenceScope,
) (egeproto.CapabilityAuthoritySnapshot, error) {
	mutable, err := a.Mutable.Current(ctx, scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	root, err := a.Root.Current(ctx, scope)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"read independent capability monotonic root: %w",
			err,
		)
	}

	relation, err := compareCapabilityMonotonicRoot(root, mutable)
	if err != nil {
		return egeproto.CapabilityAuthoritySnapshot{}, err
	}
	switch relation {
	case capabilityRootEqual:
		return mutable, nil
	case capabilityRootAhead:
		// Returning the root is deliberate. Existing effect-boundary validation
		// compares the signed permit against this snapshot and therefore maps a
		// newer term/decision/revocation directly to the existing fail-closed
		// capability errors.
		return root, nil
	case capabilityRootBehind:
		return egeproto.CapabilityAuthoritySnapshot{}, fmt.Errorf(
			"%w: root=%s mutable=%s",
			ErrCapabilityMonotonicRootBehind,
			formatCapabilityAuthoritySnapshot(root),
			formatCapabilityAuthoritySnapshot(mutable),
		)
	default:
		return egeproto.CapabilityAuthoritySnapshot{}, ErrCapabilityMonotonicRootInvalid
	}
}

type capabilityRootRelation uint8

const (
	capabilityRootEqual capabilityRootRelation = iota
	capabilityRootAhead
	capabilityRootBehind
)

func capabilityAuthoritySnapshotFromIssue(issue CapabilityFenceIssue) egeproto.CapabilityAuthoritySnapshot {
	return egeproto.CapabilityAuthoritySnapshot{
		AuthorityDomain: issue.AuthorityDomain,
		AuthorityTerm:   issue.AuthorityTerm,
		DecisionEpoch:   issue.DecisionEpoch,
		RevocationEpoch: issue.RevocationEpoch,
	}
}

func compareCapabilityMonotonicRoot(
	root egeproto.CapabilityAuthoritySnapshot,
	mutable egeproto.CapabilityAuthoritySnapshot,
) (capabilityRootRelation, error) {
	if err := validateCapabilityAuthoritySnapshot(root); err != nil {
		return capabilityRootEqual, fmt.Errorf("%w: root: %v", ErrCapabilityMonotonicRootInvalid, err)
	}
	if err := validateCapabilityAuthoritySnapshot(mutable); err != nil {
		return capabilityRootEqual, fmt.Errorf("%w: mutable: %v", ErrCapabilityMonotonicRootInvalid, err)
	}
	if strings.TrimSpace(root.AuthorityDomain) != strings.TrimSpace(mutable.AuthorityDomain) {
		return capabilityRootEqual, fmt.Errorf(
			"%w: authority domain mismatch root=%q mutable=%q",
			ErrCapabilityMonotonicRootInvalid,
			root.AuthorityDomain,
			mutable.AuthorityDomain,
		)
	}

	if root.AuthorityTerm > mutable.AuthorityTerm {
		return capabilityRootAhead, nil
	}
	if root.AuthorityTerm < mutable.AuthorityTerm {
		return capabilityRootBehind, nil
	}

	decisionAhead := root.DecisionEpoch > mutable.DecisionEpoch
	decisionBehind := root.DecisionEpoch < mutable.DecisionEpoch
	revocationAhead := root.RevocationEpoch > mutable.RevocationEpoch
	revocationBehind := root.RevocationEpoch < mutable.RevocationEpoch

	if (decisionAhead || revocationAhead) && (decisionBehind || revocationBehind) {
		return capabilityRootEqual, fmt.Errorf(
			"%w: crossed monotonic coordinates root=%s mutable=%s",
			ErrCapabilityMonotonicRootInvalid,
			formatCapabilityAuthoritySnapshot(root),
			formatCapabilityAuthoritySnapshot(mutable),
		)
	}
	if decisionAhead || revocationAhead {
		return capabilityRootAhead, nil
	}
	if decisionBehind || revocationBehind {
		return capabilityRootBehind, nil
	}
	return capabilityRootEqual, nil
}

func validateCapabilityAuthoritySnapshot(snapshot egeproto.CapabilityAuthoritySnapshot) error {
	switch {
	case strings.TrimSpace(snapshot.AuthorityDomain) == "":
		return errors.New("authority domain is required")
	case snapshot.AuthorityTerm == 0:
		return errors.New("authority term must be non-zero")
	case snapshot.DecisionEpoch == 0:
		return errors.New("decision epoch must be non-zero")
	default:
		return nil
	}
}

func capabilityRootAheadError(
	root egeproto.CapabilityAuthoritySnapshot,
	mutable egeproto.CapabilityAuthoritySnapshot,
) error {
	switch {
	case root.AuthorityTerm > mutable.AuthorityTerm:
		return egeproto.ErrCapabilityAuthorityChanged
	case root.DecisionEpoch > mutable.DecisionEpoch:
		return egeproto.ErrCapabilityDecisionSuperseded
	case root.RevocationEpoch > mutable.RevocationEpoch:
		return egeproto.ErrCapabilityRevoked
	default:
		return ErrCapabilityMonotonicRootInvalid
	}
}

func formatCapabilityAuthoritySnapshot(snapshot egeproto.CapabilityAuthoritySnapshot) string {
	return fmt.Sprintf(
		"%s/term=%d/decision=%d/revocation=%d",
		strings.TrimSpace(snapshot.AuthorityDomain),
		snapshot.AuthorityTerm,
		snapshot.DecisionEpoch,
		snapshot.RevocationEpoch,
	)
}
