package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type EnrollmentIdentityReceiptStore struct {
	Path string
}

type EnrollmentIdentityReceiptReader interface {
	Current(
		context.Context,
		ed25519.PublicKey,
	) (SignedEnrollmentIdentityReceipt, string, bool, error)
}

type AnchoredEnrollmentIdentityStore struct {
	Store  EnrollmentIdentityReceiptStore
	Anchor DurableHeadAnchor
}

func (s EnrollmentIdentityReceiptStore) currentPath() string {
	return filepath.Clean(s.Path)
}

func (s EnrollmentIdentityReceiptStore) pendingPath() string {
	return filepath.Clean(s.Path) + ".pending"
}

func (s EnrollmentIdentityReceiptStore) read(
	path string,
	publicKey ed25519.PublicKey,
) (SignedEnrollmentIdentityReceipt, string, bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SignedEnrollmentIdentityReceipt{}, "", false, nil
		}
		return SignedEnrollmentIdentityReceipt{}, "", false, err
	}
	var signed SignedEnrollmentIdentityReceipt
	if err := json.Unmarshal(payload, &signed); err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf("decode enrollment identity receipt %s: %w", path, err)
	}
	if err := VerifySignedEnrollmentIdentityReceipt(signed, publicKey); err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf("verify enrollment identity receipt %s: %w", path, err)
	}
	digest, err := EnrollmentIdentityReceiptDigest(signed)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, err
	}
	return signed, digest, true, nil
}

func (s EnrollmentIdentityReceiptStore) writePending(
	signed SignedEnrollmentIdentityReceipt,
	publicKey ed25519.PublicKey,
) (string, error) {
	if s.Path == "" {
		return "", errors.New("enrollment identity receipt store path is required")
	}
	if err := VerifySignedEnrollmentIdentityReceipt(signed, publicKey); err != nil {
		return "", err
	}
	digest, err := EnrollmentIdentityReceiptDigest(signed)
	if err != nil {
		return "", err
	}
	payload, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, byte(10))

	path := s.pendingPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".enrollment-receipt-pending-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return "", err
	}
	if _, err := tmp.Write(payload); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := syncEnrollmentReceiptDirectory(dir); err != nil {
		return "", err
	}
	return digest, nil
}

func (s EnrollmentIdentityReceiptStore) promotePending() error {
	if s.Path == "" {
		return errors.New("enrollment identity receipt store path is required")
	}
	pending := s.pendingPath()
	current := s.currentPath()
	if err := os.Rename(pending, current); err != nil {
		return err
	}
	return syncEnrollmentReceiptDirectory(filepath.Dir(current))
}

func (s EnrollmentIdentityReceiptStore) removePending() error {
	err := os.Remove(s.pendingPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncEnrollmentReceiptDirectory(filepath.Dir(s.currentPath()))
}

func syncEnrollmentReceiptDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s AnchoredEnrollmentIdentityStore) Current(
	ctx context.Context,
	publicKey ed25519.PublicKey,
) (SignedEnrollmentIdentityReceipt, string, bool, error) {
	if s.Anchor == nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, errors.New("enrollment identity durable head anchor is required")
	}
	current, currentDigest, currentExists, err := s.Store.read(s.Store.currentPath(), publicKey)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, err
	}
	pending, pendingDigest, pendingExists, err := s.Store.read(s.Store.pendingPath(), publicKey)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, err
	}
	anchor, err := s.Anchor.Current(ctx)
	if err != nil {
		return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf("read enrollment identity anchor: %w", err)
	}

	if !currentExists {
		if !pendingExists {
			if anchor.Sequence != 0 || anchor.HeadDigest != "" {
				return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf(
					"%w: local enrollment receipt is empty while anchor=(%d,%s)",
					ErrEnrollmentIdentityRollback,
					anchor.Sequence,
					anchor.HeadDigest,
				)
			}
			return SignedEnrollmentIdentityReceipt{}, "", false, nil
		}
		if pending.Receipt.Sequence != 1 || pending.Receipt.PreviousReceiptDigest != "" {
			return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf(
				"%w: orphan pending first receipt has invalid predecessor",
				ErrEnrollmentIdentityRollback,
			)
		}
		switch {
		case anchor.Sequence == 0 && anchor.HeadDigest == "":
			if err := s.Store.removePending(); err != nil {
				return SignedEnrollmentIdentityReceipt{}, "", false, err
			}
			return SignedEnrollmentIdentityReceipt{}, "", false, nil
		case anchor.Sequence == 1 && anchor.HeadDigest == pendingDigest:
			if err := s.Store.promotePending(); err != nil {
				return SignedEnrollmentIdentityReceipt{}, "", false, err
			}
			return pending, pendingDigest, true, nil
		default:
			return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf(
				"%w: anchor=(%d,%s) does not match pending first receipt=%s",
				ErrEnrollmentIdentityRollback,
				anchor.Sequence,
				anchor.HeadDigest,
				pendingDigest,
			)
		}
	}

	if current.Receipt.Sequence == anchor.Sequence && currentDigest == anchor.HeadDigest {
		if !pendingExists {
			return current, currentDigest, true, nil
		}
		if !isEnrollmentReceiptSuccessor(current, currentDigest, pending) {
			return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf(
				"%w: pending receipt is not successor of current receipt",
				ErrEnrollmentIdentityRollback,
			)
		}
		if err := s.Store.removePending(); err != nil {
			return SignedEnrollmentIdentityReceipt{}, "", false, err
		}
		return current, currentDigest, true, nil
	}

	if pendingExists &&
		isEnrollmentReceiptSuccessor(current, currentDigest, pending) &&
		pending.Receipt.Sequence == anchor.Sequence &&
		pendingDigest == anchor.HeadDigest {
		if err := s.Store.promotePending(); err != nil {
			return SignedEnrollmentIdentityReceipt{}, "", false, err
		}
		return pending, pendingDigest, true, nil
	}

	return SignedEnrollmentIdentityReceipt{}, "", false, fmt.Errorf(
		"%w: current=(seq=%d digest=%s) pending=(exists=%t seq=%d digest=%s) anchor=(seq=%d digest=%s)",
		ErrEnrollmentIdentityRollback,
		current.Receipt.Sequence,
		currentDigest,
		pendingExists,
		pending.Receipt.Sequence,
		pendingDigest,
		anchor.Sequence,
		anchor.HeadDigest,
	)
}

func (s AnchoredEnrollmentIdentityStore) Append(
	ctx context.Context,
	signed SignedEnrollmentIdentityReceipt,
	publicKey ed25519.PublicKey,
) (string, error) {
	if signed.Receipt.Version == EnrollmentIdentityReceiptVersionV2 {
		return "", fmt.Errorf(
			"%w: governed successor receipt requires AppendGovernedSuccessor",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	return s.appendVerified(ctx, signed, publicKey)
}

// AppendGovernedSuccessor is the only storage path for a v2 successor receipt.
// It proves that the enrollment signer cannot advance durable enrollment
// lineage by itself: the exact current predecessor and a separately signed
// successor-governance authorization must agree before the anchor CAS occurs.
func (s AnchoredEnrollmentIdentityStore) AppendGovernedSuccessor(
	ctx context.Context,
	signed SignedEnrollmentIdentityReceipt,
	enrollmentPublicKey ed25519.PublicKey,
	signedSuccessor SignedEnrollmentIdentitySuccessorAuthorization,
	successorGovernancePublicKey ed25519.PublicKey,
	effectiveAt time.Time,
) (string, error) {
	if signed.Receipt.Version != EnrollmentIdentityReceiptVersionV2 {
		return "", fmt.Errorf(
			"%w: governed successor append requires receipt v2",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	if len(enrollmentPublicKey) != ed25519.PublicKeySize ||
		len(successorGovernancePublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf(
			"%w: enrollment and successor-governance public keys are required",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	if string(enrollmentPublicKey) == string(successorGovernancePublicKey) {
		return "", fmt.Errorf(
			"%w: successor governance authority must differ from enrollment authority",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	if err := VerifySignedEnrollmentIdentityReceipt(signed, enrollmentPublicKey); err != nil {
		return "", err
	}
	if err := VerifySignedEnrollmentIdentitySuccessorAuthorization(
		signedSuccessor,
		successorGovernancePublicKey,
		effectiveAt,
	); err != nil {
		return "", err
	}
	authorizationDigest, err := EnrollmentIdentitySuccessorAuthorizationDigest(signedSuccessor)
	if err != nil {
		return "", err
	}
	auth := signedSuccessor.Authorization
	receipt := signed.Receipt
	if receipt.SuccessorAuthorizationDigest != authorizationDigest ||
		receipt.Sequence != auth.PredecessorSequence+1 ||
		receipt.PreviousReceiptDigest != auth.PredecessorReceiptDigest ||
		receipt.ReceiptID != auth.SuccessorEnrollmentID ||
		receipt.DeviceID != auth.DeviceID ||
		receipt.EKSPKISHA256 != auth.SuccessorHardwareIdentityDigest {
		return "", fmt.Errorf(
			"%w: successor receipt does not match signed governance authorization",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	if receipt.IssuedAt.Before(auth.NotBefore.UTC()) ||
		!receipt.IssuedAt.Before(auth.ExpiresAt.UTC()) {
		return "", fmt.Errorf(
			"%w: successor receipt was issued outside the authorization window",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}

	current, currentDigest, exists, err := s.Current(ctx, enrollmentPublicKey)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf(
			"%w: governed successor requires an existing predecessor receipt",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	if current.Receipt.Sequence != auth.PredecessorSequence ||
		currentDigest != auth.PredecessorReceiptDigest ||
		current.Receipt.DeviceID != auth.DeviceID ||
		current.Receipt.EKSPKISHA256 != auth.PredecessorHardwareIdentityDigest {
		return "", fmt.Errorf(
			"%w: current receipt is not the exact authorized predecessor",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}
	return s.appendVerified(ctx, signed, enrollmentPublicKey)
}

func (s AnchoredEnrollmentIdentityStore) appendVerified(
	ctx context.Context,
	signed SignedEnrollmentIdentityReceipt,
	publicKey ed25519.PublicKey,
) (string, error) {
	if s.Anchor == nil {
		return "", errors.New("enrollment identity durable head anchor is required")
	}
	if err := VerifySignedEnrollmentIdentityReceipt(signed, publicKey); err != nil {
		return "", err
	}
	newDigest, err := EnrollmentIdentityReceiptDigest(signed)
	if err != nil {
		return "", err
	}

	current, currentDigest, currentExists, err := s.Current(ctx, publicKey)
	if err != nil {
		return "", err
	}
	anchor, err := s.Anchor.Current(ctx)
	if err != nil {
		return "", fmt.Errorf("read enrollment identity anchor: %w", err)
	}

	if currentExists && newDigest == currentDigest {
		return newDigest, nil
	}
	if currentExists {
		if !isEnrollmentReceiptSuccessor(current, currentDigest, signed) {
			return "", fmt.Errorf("%w: appended receipt is not the exact successor", ErrEnrollmentIdentityReceiptInvalid)
		}
	} else {
		if signed.Receipt.Sequence != 1 || signed.Receipt.PreviousReceiptDigest != "" {
			return "", fmt.Errorf("%w: first anchored receipt must be sequence 1 with no predecessor", ErrEnrollmentIdentityReceiptInvalid)
		}
	}
	if signed.Receipt.Sequence != anchor.Sequence+1 {
		return "", fmt.Errorf(
			"%w: receipt sequence=%d anchor sequence=%d",
			ErrEnrollmentIdentityReceiptInvalid,
			signed.Receipt.Sequence,
			anchor.Sequence,
		)
	}

	if _, err := s.Store.writePending(signed, publicKey); err != nil {
		return "", err
	}
	next := DurableHeadAnchorState{
		Sequence:   signed.Receipt.Sequence,
		HeadDigest: newDigest,
	}
	advanced, err := s.Anchor.CompareAndAdvance(ctx, anchor, next)
	if err != nil {
		return "", fmt.Errorf("advance enrollment identity anchor: %w", err)
	}
	if advanced != next {
		return "", fmt.Errorf(
			"%w: anchor advanced to (%d,%s), expected (%d,%s)",
			ErrEnrollmentIdentityRollback,
			advanced.Sequence,
			advanced.HeadDigest,
			next.Sequence,
			next.HeadDigest,
		)
	}
	if err := s.Store.promotePending(); err != nil {
		return "", fmt.Errorf("promote anchored enrollment identity receipt: %w", err)
	}
	return newDigest, nil
}
func isEnrollmentReceiptSuccessor(
	current SignedEnrollmentIdentityReceipt,
	currentDigest string,
	next SignedEnrollmentIdentityReceipt,
) bool {
	return next.Receipt.Sequence == current.Receipt.Sequence+1 &&
		next.Receipt.PreviousReceiptDigest == currentDigest &&
		next.Receipt.DeviceID == current.Receipt.DeviceID
}
