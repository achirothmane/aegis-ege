package kernelfabric

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// VerifySignedTaintRecoveryAuthorizationForBoot verifies the signed recovery
// authorization and then binds it to exactly one Linux boot identity.
//
// This helper deliberately does not infer continuity across boots. A recovery
// authorization issued on boot A is not authority on boot B, even when every
// other field is byte-for-byte identical.
func VerifySignedTaintRecoveryAuthorizationForBoot(
	signed SignedTaintRecoveryAuthorization,
	publicKey ed25519.PublicKey,
	now time.Time,
	currentBootIDHash string,
) error {
	if err := VerifySignedTaintRecoveryAuthorization(signed, publicKey, now); err != nil {
		return err
	}
	if _, err := ParseSHA256Digest(currentBootIDHash); err != nil {
		return fmt.Errorf("current boot identity: %w", err)
	}
	if signed.Authorization.BootIDHash != currentBootIDHash {
		return fmt.Errorf("%w: boot identity mismatch", ErrTaintRecoveryAuthorization)
	}
	return nil
}
