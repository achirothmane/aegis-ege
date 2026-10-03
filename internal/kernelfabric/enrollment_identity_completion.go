package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// CompleteAndCommitTPMEnrollmentReceipt is the authoritative VCS-11 initial
// enrollment completion path. A durable signed receipt is issued only after the
// TPM credential-activation secret and AK-signed enrollment transcript have
// been verified by CompleteTPMEnrollment.
//
// Challenge freshness is evaluated against verifier time. The completed
// identity's EnrolledAt is then normalized to the proof's stable CompletedAt so
// retrying the exact same ceremony produces the exact same identity digest.
//
// This function deliberately does not authorize successor enrollment. Hardware
// replacement or re-enrollment requires a separate governed authorization path.
// Retrying the same already-committed ceremony is idempotent.
func CompleteAndCommitTPMEnrollmentReceipt(
	ctx context.Context,
	pending PendingTPMEnrollment,
	proof TPMEnrollmentProof,
	now time.Time,
	store AnchoredEnrollmentIdentityStore,
	enrollmentAuthorityKey ed25519.PrivateKey,
) (
	EnrolledTPMIdentity,
	SignedEnrollmentIdentityReceipt,
	string,
	error,
) {
	if ctx == nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", errors.New("enrollment completion context is required")
	}
	if err := ctx.Err(); err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", err
	}
	if len(enrollmentAuthorityKey) != ed25519.PrivateKeySize {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", errors.New("enrollment authority Ed25519 private key is required")
	}

	effectiveNow := now.UTC()
	if now.IsZero() {
		effectiveNow = time.Now().UTC()
	}
	identity, err := CompleteTPMEnrollment(pending, proof, effectiveNow)
	if err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", err
	}

	completedAt := proof.CompletedAt.UTC()
	if proof.CompletedAt.IsZero() ||
		completedAt.Before(pending.Challenge.IssuedAt.UTC()) ||
		!completedAt.Before(pending.Challenge.ExpiresAt.UTC()) ||
		completedAt.After(effectiveNow) {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", fmt.Errorf(
			"%w: proof completion time is outside the verified enrollment ceremony window",
			ErrEnrollmentActivationFailed,
		)
	}
	identity.EnrolledAt = completedAt

	publicKey := enrollmentAuthorityKey.Public().(ed25519.PublicKey)
	current, currentDigest, exists, err := store.Current(ctx, publicKey)
	if err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", fmt.Errorf("read durable enrollment predecessor: %w", err)
	}
	if exists {
		if current.Receipt.ReceiptID == pending.Challenge.EnrollmentID {
			if err := VerifyEnrollmentIdentityReceiptForIdentity(current, publicKey, identity); err != nil {
				return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", fmt.Errorf(
					"%w: repeated enrollment ceremony differs from committed receipt: %v",
					ErrEnrollmentIdentityReceiptInvalid,
					err,
				)
			}
			return identity, current, currentDigest, nil
		}
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", fmt.Errorf(
			"%w: successor enrollment requires a separately governed authorization path",
			ErrEnrollmentIdentityReceiptInvalid,
		)
	}

	receipt, err := NewEnrollmentIdentityReceipt(
		pending.Challenge.EnrollmentID,
		1,
		"",
		identity,
		identity.EnrolledAt,
	)
	if err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", err
	}
	signed, err := SignEnrollmentIdentityReceipt(receipt, enrollmentAuthorityKey)
	if err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", err
	}
	digest, err := store.Append(ctx, signed, publicKey)
	if err != nil {
		return EnrolledTPMIdentity{}, SignedEnrollmentIdentityReceipt{}, "", fmt.Errorf("commit durable enrollment receipt: %w", err)
	}
	return identity, signed, digest, nil
}
