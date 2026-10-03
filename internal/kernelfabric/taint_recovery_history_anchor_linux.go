//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
)

var ErrTaintRecoveryHistoryRollback = errors.New("taint recovery history rollback detected")

type TaintRecoveryHistoryAnchorState = DurableHeadAnchorState
type TaintRecoveryHistoryAnchor = DurableHeadAnchor

type AnchoredTaintRecoveryHistoryStore struct {
	Store  TaintRecoveryHistoryStore
	Anchor TaintRecoveryHistoryAnchor
}

func (s AnchoredTaintRecoveryHistoryStore) Current(
	ctx context.Context,
	publicKey ed25519.PublicKey,
) (SignedTaintRecoveryHistoryReceipt, string, bool, error) {
	if s.Anchor == nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, errors.New("taint recovery history anchor is required")
	}
	receipt, digest, exists, err := s.Store.Current(publicKey)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	anchor, err := s.Anchor.Current(ctx)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf("read taint recovery history anchor: %w", err)
	}
	if err := validateTaintRecoveryHistoryAnchorBinding(anchor, digest, exists); err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	return receipt, digest, exists, nil
}

func (s AnchoredTaintRecoveryHistoryStore) Append(
	ctx context.Context,
	signed SignedTaintRecoveryHistoryReceipt,
	publicKey ed25519.PublicKey,
) (string, error) {
	if s.Anchor == nil {
		return "", errors.New("taint recovery history anchor is required")
	}

	_, currentDigest, currentExists, err := s.Store.Current(publicKey)
	if err != nil {
		return "", err
	}
	currentAnchor, err := s.Anchor.Current(ctx)
	if err != nil {
		return "", fmt.Errorf("read taint recovery history anchor: %w", err)
	}
	if err := validateTaintRecoveryHistoryAnchorBinding(currentAnchor, currentDigest, currentExists); err != nil {
		return "", err
	}

	digest, err := s.Store.Append(signed, publicKey)
	if err != nil {
		return "", err
	}
	if currentExists && digest == currentDigest {
		return digest, nil
	}

	next := TaintRecoveryHistoryAnchorState{
		Sequence:   currentAnchor.Sequence + 1,
		HeadDigest: digest,
	}
	advanced, err := s.Anchor.CompareAndAdvance(ctx, currentAnchor, next)
	if err != nil {
		return "", fmt.Errorf("advance taint recovery history anchor: %w", err)
	}
	if advanced != next {
		return "", fmt.Errorf(
			"%w: anchor advanced to sequence=%d head=%q; expected sequence=%d head=%q",
			ErrTaintRecoveryHistoryRollback,
			advanced.Sequence,
			advanced.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}
	return digest, nil
}

func validateTaintRecoveryHistoryAnchorBinding(
	anchor TaintRecoveryHistoryAnchorState,
	localDigest string,
	localExists bool,
) error {
	if !localExists {
		if anchor.Sequence != 0 || anchor.HeadDigest != "" {
			return fmt.Errorf(
				"%w: local history is empty while anchor is sequence=%d head=%q",
				ErrTaintRecoveryHistoryRollback,
				anchor.Sequence,
				anchor.HeadDigest,
			)
		}
		return nil
	}
	if anchor.Sequence == 0 || anchor.HeadDigest == "" {
		return fmt.Errorf(
			"%w: local history head=%q exists without an anchored commitment",
			ErrTaintRecoveryHistoryRollback,
			localDigest,
		)
	}
	if anchor.HeadDigest != localDigest {
		return fmt.Errorf(
			"%w: local head=%q anchored head=%q sequence=%d",
			ErrTaintRecoveryHistoryRollback,
			localDigest,
			anchor.HeadDigest,
			anchor.Sequence,
		)
	}
	return nil
}
