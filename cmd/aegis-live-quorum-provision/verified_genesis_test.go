package main

import (
	"context"
	"strings"
	"testing"
)

func TestIndependentLiveQuorumGenesisPinFailsClosedWithoutProductionArtifacts(t *testing.T) {
	t.Setenv("LIVE_QUORUM_GENESIS_MANIFEST", "")
	t.Setenv("LIVE_QUORUM_GENESIS_VERIFICATION_BUNDLE", "")
	if _, err := loadVerifiedIndependentGenesisPin(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "requires LIVE_QUORUM_GENESIS_MANIFEST") {
		t.Fatalf("missing production Genesis artifacts returned %v, want fail-closed", err)
	}
}
