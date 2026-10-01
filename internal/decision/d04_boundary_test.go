package decision

import (
	"testing"
	"time"
)

func TestD04UnknownBoundaryTimeCannotAuthorizeWithoutOptionalStateBindings(t *testing.T) {
	auth, attempt := validAuthorizationFixture(t)
	auth.ResourceVersion, attempt.ResourceVersion = "", ""
	auth.PlanDigest, attempt.PlanDigest = "", ""
	attempt.Now = time.Time{}
	got := ValidateAuthorization(auth, attempt)
	if got.Valid || !containsReason(got.ReasonCodes, AuthorizationExpired) {
		t.Fatalf("unknown boundary time granted authority: %+v", got)
	}
}
