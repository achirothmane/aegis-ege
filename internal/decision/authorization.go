package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

func DigestEvidence(evidence []EvidenceObservation) string {
	canonical := make([]string, 0, len(evidence))
	for _, observation := range evidence {
		canonical = append(canonical, strings.Join([]string{
			observation.Claim,
			observation.Source,
			observation.Value,
			observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		}, "\x1f"))
	}
	sort.Strings(canonical)

	hash := sha256.Sum256([]byte(strings.Join(canonical, "\x1e")))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func ValidateAuthorization(auth Authorization, attempt ExecutionAttempt) AuthorizationValidation {
	reasons := make([]ReasonCode, 0, 4)

	if !attempt.Now.Before(auth.ValidUntil) {
		reasons = append(reasons, AuthorizationExpired)
	}
	if attempt.ResourceVersion != auth.ResourceVersion {
		reasons = append(reasons, ResourceVersionChanged)
	}
	if attempt.Action != auth.Action || attempt.ActionID != auth.ActionID {
		reasons = append(reasons, ActionChanged)
	}
	if attempt.Target != auth.Target {
		reasons = append(reasons, TargetChanged)
	}

	return AuthorizationValidation{
		Valid:       len(reasons) == 0,
		ReasonCodes: reasons,
	}
}
