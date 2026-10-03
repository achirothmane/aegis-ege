//go:build linux

package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const taintRecoveryHistoryExternalHeadKeyID = "aegis-ege/taint-recovery-history-head/v1"

var ErrTaintRecoveryHistoryWitnessMismatch = errors.New("taint recovery history witness mismatch")

// ExternalHeadTaintRecoveryHistoryAnchor adapts an independent ExternalHeadStore
// (including QuorumHeadStore) to the recovery-history monotonic anchor contract.
type ExternalHeadTaintRecoveryHistoryAnchor struct {
	store     journal.ExternalHeadStore
	historyID string
}

func NewExternalHeadTaintRecoveryHistoryAnchor(
	store journal.ExternalHeadStore,
	historyID string,
) (*ExternalHeadTaintRecoveryHistoryAnchor, error) {
	if store == nil {
		return nil, errors.New("external taint recovery history head store is required")
	}
	historyID = strings.TrimSpace(historyID)
	if historyID == "" {
		return nil, errors.New("external taint recovery history id is required")
	}
	return &ExternalHeadTaintRecoveryHistoryAnchor{
		store:     store,
		historyID: historyID,
	}, nil
}

func (a *ExternalHeadTaintRecoveryHistoryAnchor) QuorumPolicyHash() string {
	if a == nil || a.store == nil {
		return ""
	}
	provider, ok := a.store.(interface{ QuorumPolicyHash() string })
	if !ok {
		return ""
	}
	return strings.TrimSpace(provider.QuorumPolicyHash())
}

func (a *ExternalHeadTaintRecoveryHistoryAnchor) Current(
	ctx context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a == nil || a.store == nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("external taint recovery history anchor is unavailable")
	}
	head, err := a.store.Load(ctx, a.historyID)
	if errors.Is(err, journal.ErrExternalHeadNotFound) {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, nil
	}
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("load external taint recovery history head: %w", err)
	}
	if err := a.validateHead(head); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	return kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   head.Sequence,
		HeadDigest: head.HeadHash,
	}, nil
}

func (a *ExternalHeadTaintRecoveryHistoryAnchor) CompareAndAdvance(
	ctx context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a == nil || a.store == nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("external taint recovery history anchor is unavailable")
	}
	if err := validateExternalHistoryAnchorState(expected); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if err := validateExternalHistoryAnchorState(next); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if next.Sequence != expected.Sequence+1 || next.HeadDigest == "" {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: external witness requires exact successor: current=(%d,%q) next=(%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			expected.Sequence,
			expected.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}

	current, err := a.store.Load(ctx, a.historyID)
	switch {
	case errors.Is(err, journal.ErrExternalHeadNotFound):
		if expected != (kernelfabric.TaintRecoveryHistoryAnchorState{}) {
			return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
				"%w: external witness is empty but expected sequence=%d head=%q",
				ErrTaintRecoveryHistoryWitnessMismatch,
				expected.Sequence,
				expected.HeadDigest,
			)
		}
		zero := journal.ExternalHead{
			JournalID: a.historyID,
			Sequence:  0,
			HeadHash:  "",
			KeyID:     taintRecoveryHistoryExternalHeadKeyID,
		}
		current, err = a.store.CompareAndAdvance(ctx, journal.ExternalHead{}, zero)
		if err != nil {
			return kernelfabric.TaintRecoveryHistoryAnchorState{},
				fmt.Errorf("initialize external taint recovery history head: %w", err)
		}
	case err != nil:
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("load external taint recovery history head: %w", err)
	}

	if err := a.validateHead(current); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if current.Sequence != expected.Sequence || current.HeadHash != expected.HeadDigest {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: witness=(%d,%q) expected=(%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			current.Sequence,
			current.HeadHash,
			expected.Sequence,
			expected.HeadDigest,
		)
	}

	advanced, err := a.store.CompareAndAdvance(
		ctx,
		current,
		journal.ExternalHead{
			JournalID: a.historyID,
			Sequence:  next.Sequence,
			HeadHash:  next.HeadDigest,
			KeyID:     taintRecoveryHistoryExternalHeadKeyID,
		},
	)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("advance external taint recovery history head: %w", err)
	}
	if err := a.validateHead(advanced); err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	got := kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   advanced.Sequence,
		HeadDigest: advanced.HeadHash,
	}
	if got != next {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: witness advanced to (%d,%q), expected (%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			got.Sequence,
			got.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}
	return got, nil
}

func (a *ExternalHeadTaintRecoveryHistoryAnchor) validateHead(
	head journal.ExternalHead,
) error {
	if strings.TrimSpace(head.JournalID) != a.historyID {
		return fmt.Errorf(
			"%w: history id mismatch: got=%q want=%q",
			ErrTaintRecoveryHistoryWitnessMismatch,
			head.JournalID,
			a.historyID,
		)
	}
	if head.KeyID != taintRecoveryHistoryExternalHeadKeyID {
		return fmt.Errorf(
			"%w: key id mismatch: got=%q want=%q",
			ErrTaintRecoveryHistoryWitnessMismatch,
			head.KeyID,
			taintRecoveryHistoryExternalHeadKeyID,
		)
	}
	return validateExternalHistoryAnchorState(kernelfabric.TaintRecoveryHistoryAnchorState{
		Sequence:   head.Sequence,
		HeadDigest: head.HeadHash,
	})
}

func validateExternalHistoryAnchorState(
	state kernelfabric.TaintRecoveryHistoryAnchorState,
) error {
	if state.Sequence == 0 {
		if state.HeadDigest != "" {
			return fmt.Errorf(
				"%w: sequence zero cannot carry a head digest",
				ErrTaintRecoveryHistoryWitnessMismatch,
			)
		}
		return nil
	}
	if !isSHA256HistoryDigest(state.HeadDigest) {
		return fmt.Errorf(
			"%w: nonzero sequence requires a sha256 head digest",
			ErrTaintRecoveryHistoryWitnessMismatch,
		)
	}
	return nil
}

func isSHA256HistoryDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

// ConjunctiveTaintRecoveryHistoryAnchor requires the local monotonic root and
// the independent witness root to agree exactly before history is accepted.
//
// Advancement is witness-first. If the second step fails, the system remains
// fail-closed because Current() observes divergence. Repairing such a partial
// commit is deliberately an authorized recovery operation rather than an
// implicit local reset.
type ConjunctiveTaintRecoveryHistoryAnchor struct {
	Local   kernelfabric.TaintRecoveryHistoryAnchor
	Witness kernelfabric.TaintRecoveryHistoryAnchor
}

func NewConjunctiveTaintRecoveryHistoryAnchor(
	local,
	witness kernelfabric.TaintRecoveryHistoryAnchor,
) (*ConjunctiveTaintRecoveryHistoryAnchor, error) {
	if local == nil || witness == nil {
		return nil, errors.New("local and witness recovery history anchors are required")
	}
	return &ConjunctiveTaintRecoveryHistoryAnchor{
		Local:   local,
		Witness: witness,
	}, nil
}

func (a *ConjunctiveTaintRecoveryHistoryAnchor) Current(
	ctx context.Context,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a == nil || a.Local == nil || a.Witness == nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("conjunctive recovery history anchor is unavailable")
	}
	local, err := a.Local.Current(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("read local recovery history anchor: %w", err)
	}
	witness, err := a.Witness.Current(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("read witness recovery history anchor: %w", err)
	}
	if local != witness {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: local=(%d,%q) witness=(%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			local.Sequence,
			local.HeadDigest,
			witness.Sequence,
			witness.HeadDigest,
		)
	}
	return local, nil
}

func (a *ConjunctiveTaintRecoveryHistoryAnchor) CompareAndAdvance(
	ctx context.Context,
	expected,
	next kernelfabric.TaintRecoveryHistoryAnchorState,
) (kernelfabric.TaintRecoveryHistoryAnchorState, error) {
	if a == nil || a.Local == nil || a.Witness == nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			errors.New("conjunctive recovery history anchor is unavailable")
	}
	current, err := a.Current(ctx)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, err
	}
	if current != expected {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: conjunctive anchor current=(%d,%q) expected=(%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			current.Sequence,
			current.HeadDigest,
			expected.Sequence,
			expected.HeadDigest,
		)
	}

	witnessAdvanced, err := a.Witness.CompareAndAdvance(ctx, expected, next)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{},
			fmt.Errorf("advance witness recovery history anchor: %w", err)
	}
	if witnessAdvanced != next {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: witness returned (%d,%q), expected (%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			witnessAdvanced.Sequence,
			witnessAdvanced.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}

	localAdvanced, err := a.Local.CompareAndAdvance(ctx, expected, next)
	if err != nil {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: witness committed (%d,%q) but local anchor did not: %v",
			ErrTaintRecoveryHistoryWitnessMismatch,
			next.Sequence,
			next.HeadDigest,
			err,
		)
	}
	if localAdvanced != next {
		return kernelfabric.TaintRecoveryHistoryAnchorState{}, fmt.Errorf(
			"%w: local returned (%d,%q), expected (%d,%q)",
			ErrTaintRecoveryHistoryWitnessMismatch,
			localAdvanced.Sequence,
			localAdvanced.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}
	return next, nil
}
