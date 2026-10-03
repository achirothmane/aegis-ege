//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
)

var ErrTaintRecoveryHistoryRollback = errors.New("taint recovery history rollback detected")

type TaintRecoveryHistoryAnchor interface {
	Advance(ctx context.Context, previousDigest, nextDigest string) error
	Current(ctx context.Context) (string, error)
}

func (s TaintRecoveryHistoryStore) AppendAnchored(
	ctx context.Context,
	signed SignedTaintRecoveryHistoryReceipt,
	publicKey ed25519.PublicKey,
	anchor TaintRecoveryHistoryAnchor,
) (string, error) {
	if anchor == nil {
		return "", fmt.Errorf("%w: monotonic anchor is required", ErrTaintRecoveryHistoryRollback)
	}
	digest, err := TaintRecoveryHistoryReceiptDigest(signed)
	if err != nil {
		return "", err
	}
	persisted, err := s.Append(signed, publicKey)
	if err != nil {
		return "", err
	}
	if persisted != digest {
		return "", fmt.Errorf(
			"%w: persisted digest mismatch: got=%s want=%s",
			ErrTaintRecoveryHistoryRollback,
			persisted,
			digest,
		)
	}
	if err := anchor.Advance(ctx, signed.Receipt.PreviousReceiptDigest, digest); err != nil {
		return "", fmt.Errorf("%w: %w", ErrTaintRecoveryHistoryRollback, err)
	}
	return digest, nil
}

func (s TaintRecoveryHistoryStore) CurrentAnchored(
	ctx context.Context,
	publicKey ed25519.PublicKey,
	anchor TaintRecoveryHistoryAnchor,
) (SignedTaintRecoveryHistoryReceipt, string, bool, error) {
	if anchor == nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false,
			fmt.Errorf("%w: monotonic anchor is required", ErrTaintRecoveryHistoryRollback)
	}

	signed, digest, exists, err := s.Current(publicKey)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, err
	}
	anchoredDigest, err := anchor.Current(ctx)
	if err != nil {
		return SignedTaintRecoveryHistoryReceipt{}, "", false,
			fmt.Errorf("%w: %w", ErrTaintRecoveryHistoryRollback, err)
	}

	if !exists {
		if anchoredDigest != "" {
			return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf(
				"%w: durable store is empty but anchor retains %s",
				ErrTaintRecoveryHistoryRollback,
				anchoredDigest,
			)
		}
		return SignedTaintRecoveryHistoryReceipt{}, "", false, nil
	}
	if anchoredDigest != digest {
		return SignedTaintRecoveryHistoryReceipt{}, "", false, fmt.Errorf(
			"%w: durable head=%s monotonic head=%s",
			ErrTaintRecoveryHistoryRollback,
			digest,
			anchoredDigest,
		)
	}
	return signed, digest, true, nil
}
