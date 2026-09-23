package decision

import (
	"strings"
	"testing"
	"time"
)

func validAuthorizationFixture(t *testing.T) (Authorization, ExecutionAttempt) {
	t.Helper()

	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	req := Request{
		ActionID:         "act-drain-node-7",
		Action:           "drain",
		Target:           "node/node-7",
		ResourceVersion:  "928441",
		RequestedAt:      now,
		AuthorizationTTL: 5 * time.Second,
		MaxEvidenceAge:   10 * time.Second,
		Evidence: []EvidenceObservation{
			{
				Claim:      "node_health",
				Source:     "kubernetes-api",
				Value:      "unhealthy",
				ObservedAt: now.Add(-2 * time.Second),
			},
		},
	}

	result := Evaluate(req)
	if result.Decision != Allow || result.Authorization == nil {
		t.Fatalf("expected bound ALLOW authorization, got decision=%s auth=%v reasons=%v", result.Decision, result.Authorization, result.ReasonCodes)
	}
	if !strings.HasPrefix(result.Authorization.EvidenceDigest, "sha256:") {
		t.Fatalf("expected sha256 evidence digest, got %q", result.Authorization.EvidenceDigest)
	}

	attempt := ExecutionAttempt{
		ActionID:        req.ActionID,
		Action:          req.Action,
		Target:          req.Target,
		ResourceVersion: req.ResourceVersion,
		Now:             now.Add(2 * time.Second),
	}

	return *result.Authorization, attempt
}

func TestMatchingStateBoundAuthorizationIsValid(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)

	got := ValidateAuthorization(auth, attempt)

	if !got.Valid {
		t.Fatalf("expected valid authorization, got reasons %v", got.ReasonCodes)
	}
}

func TestExpiredAuthorizationIsInvalid(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)
	attempt.Now = auth.ValidUntil

	got := ValidateAuthorization(auth, attempt)

	if got.Valid || !containsReason(got.ReasonCodes, AuthorizationExpired) {
		t.Fatalf("expected %s, got valid=%v reasons=%v", AuthorizationExpired, got.Valid, got.ReasonCodes)
	}
}

func TestChangedResourceVersionInvalidatesAuthorization(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)
	attempt.ResourceVersion = "928442"

	got := ValidateAuthorization(auth, attempt)

	if got.Valid || !containsReason(got.ReasonCodes, ResourceVersionChanged) {
		t.Fatalf("expected %s, got valid=%v reasons=%v", ResourceVersionChanged, got.Valid, got.ReasonCodes)
	}
}

func TestChangedActionInvalidatesAuthorization(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)
	attempt.Action = "delete"

	got := ValidateAuthorization(auth, attempt)

	if got.Valid || !containsReason(got.ReasonCodes, ActionChanged) {
		t.Fatalf("expected %s, got valid=%v reasons=%v", ActionChanged, got.Valid, got.ReasonCodes)
	}
}

func TestChangedTargetInvalidatesAuthorization(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)
	attempt.Target = "node/node-8"

	got := ValidateAuthorization(auth, attempt)

	if got.Valid || !containsReason(got.ReasonCodes, TargetChanged) {
		t.Fatalf("expected %s, got valid=%v reasons=%v", TargetChanged, got.Valid, got.ReasonCodes)
	}
}

func containsReason(reasons []ReasonCode, want ReasonCode) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
