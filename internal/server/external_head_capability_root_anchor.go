package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/journal"
)

const capabilityRootExternalHeadKeyID = "aegis-ege/capability-root-head/v1"

// ExternalHeadCapabilityRootAnchor adapts the existing M10 ExternalHeadStore
// into the content-bound CapabilityRootAnchor contract.
//
// The external store retains the monotonic sequence and exact local-ledger head
// commitment outside the local root ledger failure domain. KubernetesHeadStore
// provides resourceVersion compare-and-set semantics for the v1 single-cluster
// deployment profile.
type ExternalHeadCapabilityRootAnchor struct {
	store  journal.ExternalHeadStore
	rootID string
}

func NewExternalHeadCapabilityRootAnchor(
	store journal.ExternalHeadStore,
	rootID string,
) (*ExternalHeadCapabilityRootAnchor, error) {
	if store == nil {
		return nil, errors.New("external capability root head store is required")
	}
	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return nil, errors.New("external capability root id is required")
	}
	return &ExternalHeadCapabilityRootAnchor{
		store:  store,
		rootID: rootID,
	}, nil
}

func (a *ExternalHeadCapabilityRootAnchor) Identity(context.Context) (string, error) {
	if a == nil || a.store == nil || strings.TrimSpace(a.rootID) == "" {
		return "", errors.New("external capability root anchor is unavailable")
	}
	return "external-head:" + a.rootID, nil
}

func (a *ExternalHeadCapabilityRootAnchor) Current(
	ctx context.Context,
) (CapabilityRootAnchorState, error) {
	if a == nil || a.store == nil {
		return CapabilityRootAnchorState{}, errors.New("external capability root anchor is unavailable")
	}
	head, err := a.store.Load(ctx, a.rootID)
	if errors.Is(err, journal.ErrExternalHeadNotFound) {
		return CapabilityRootAnchorState{}, nil
	}
	if err != nil {
		return CapabilityRootAnchorState{}, fmt.Errorf("load external capability root head: %w", err)
	}
	if err := a.validateHead(head); err != nil {
		return CapabilityRootAnchorState{}, err
	}
	return CapabilityRootAnchorState{
		Sequence:   head.Sequence,
		Commitment: head.HeadHash,
	}, nil
}

func (a *ExternalHeadCapabilityRootAnchor) Advance(
	ctx context.Context,
	expected CapabilityRootAnchorState,
	next CapabilityRootAnchorState,
) (CapabilityRootAnchorState, error) {
	if a == nil || a.store == nil {
		return CapabilityRootAnchorState{}, errors.New("external capability root anchor is unavailable")
	}
	if err := validateCapabilityRootAnchorState(expected); err != nil {
		return CapabilityRootAnchorState{}, fmt.Errorf("invalid expected capability root anchor state: %w", err)
	}
	if err := validateCapabilityRootAnchorState(next); err != nil {
		return CapabilityRootAnchorState{}, fmt.Errorf("invalid next capability root anchor state: %w", err)
	}
	if next.Sequence != expected.Sequence+1 {
		return CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: external capability root sequence must advance by one: current=%d next=%d",
			ErrCapabilityRootAnchorMismatch,
			expected.Sequence,
			next.Sequence,
		)
	}

	current, err := a.store.Load(ctx, a.rootID)
	switch {
	case errors.Is(err, journal.ErrExternalHeadNotFound):
		if expected != (CapabilityRootAnchorState{}) {
			return CapabilityRootAnchorState{}, fmt.Errorf(
				"%w: external capability root is absent but expected sequence=%d commitment=%q",
				ErrCapabilityRootAnchorMismatch,
				expected.Sequence,
				expected.Commitment,
			)
		}
		// ExternalHeadStore was originally designed for journals, which persist
		// an explicit sequence-zero head before the first entry. Preserve that
		// protocol so both MemoryHeadStore and KubernetesHeadStore share exactly
		// the same initialization semantics.
		zero := journal.ExternalHead{
			JournalID: a.rootID,
			Sequence:  0,
			HeadHash:  "",
			KeyID:     capabilityRootExternalHeadKeyID,
		}
		current, err = a.store.CompareAndAdvance(ctx, journal.ExternalHead{}, zero)
		if err != nil {
			return CapabilityRootAnchorState{}, fmt.Errorf(
				"initialize external capability root head: %w",
				err,
			)
		}
	case err != nil:
		return CapabilityRootAnchorState{}, fmt.Errorf("load external capability root head: %w", err)
	}

	if err := a.validateHead(current); err != nil {
		return CapabilityRootAnchorState{}, err
	}
	if current.Sequence != expected.Sequence || current.HeadHash != expected.Commitment {
		return CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: protected external head is sequence=%d commitment=%q; expected sequence=%d commitment=%q",
			ErrCapabilityRootAnchorMismatch,
			current.Sequence,
			current.HeadHash,
			expected.Sequence,
			expected.Commitment,
		)
	}

	advanced, err := a.store.CompareAndAdvance(
		ctx,
		current,
		journal.ExternalHead{
			JournalID: a.rootID,
			Sequence:  next.Sequence,
			HeadHash:  next.Commitment,
			KeyID:     capabilityRootExternalHeadKeyID,
		},
	)
	if err != nil {
		return CapabilityRootAnchorState{}, fmt.Errorf("advance external capability root head: %w", err)
	}
	if err := a.validateHead(advanced); err != nil {
		return CapabilityRootAnchorState{}, err
	}
	got := CapabilityRootAnchorState{
		Sequence:   advanced.Sequence,
		Commitment: advanced.HeadHash,
	}
	if got != next {
		return CapabilityRootAnchorState{}, fmt.Errorf(
			"%w: protected external head advanced to sequence=%d commitment=%q; expected sequence=%d commitment=%q",
			ErrCapabilityRootAnchorMismatch,
			got.Sequence,
			got.Commitment,
			next.Sequence,
			next.Commitment,
		)
	}
	return got, nil
}

func (a *ExternalHeadCapabilityRootAnchor) validateHead(head journal.ExternalHead) error {
	if strings.TrimSpace(head.JournalID) != a.rootID {
		return fmt.Errorf(
			"%w: external capability root id mismatch: got %q want %q",
			ErrCapabilityRootAnchorMismatch,
			head.JournalID,
			a.rootID,
		)
	}
	if head.KeyID != capabilityRootExternalHeadKeyID {
		return fmt.Errorf(
			"%w: external capability root key id mismatch: got %q want %q",
			ErrCapabilityRootAnchorMismatch,
			head.KeyID,
			capabilityRootExternalHeadKeyID,
		)
	}
	if head.Sequence == 0 {
		if head.HeadHash != "" {
			return fmt.Errorf(
				"%w: sequence-zero external capability root has non-empty commitment",
				ErrCapabilityRootAnchorMismatch,
			)
		}
		return nil
	}
	if !isCapabilityRootDigest(head.HeadHash) {
		return fmt.Errorf(
			"%w: external capability root commitment is not a sha256 digest",
			ErrCapabilityRootAnchorMismatch,
		)
	}
	return nil
}
