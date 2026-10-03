package kernelfabric

// TPMEnrollmentTranscriptPayload returns the canonical transcript bytes that
// the enrolled TPM AK signs during credential activation. It is exposed so
// higher-level executable proofs can reproduce the exact enrollment ceremony
// without duplicating canonicalization rules.
func TPMEnrollmentTranscriptPayload(
	challenge TPMEnrollmentChallenge,
) ([]byte, error) {
	return enrollmentTranscriptPayload(challenge)
}
