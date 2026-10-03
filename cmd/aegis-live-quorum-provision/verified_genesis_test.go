package main

import (
	"context"
	"os"
	"path/filepath"
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

func TestIndependentPreparedQuorumRoundTripPreservesExactEnvelopeAndSecrets(t *testing.T) {
	prepared, err := prepareIndependentQuorum()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "prepared.json")
	if err := writeIndependentPreparedQuorum(path, prepared); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("prepared bundle permissions=%o want=600", info.Mode().Perm())
	}

	loaded, err := loadIndependentPreparedQuorum(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.genesisEpoch != prepared.genesisEpoch ||
		loaded.envelopeHash != prepared.envelopeHash ||
		string(loaded.envelope) != string(prepared.envelope) ||
		loaded.workloadKeyID != prepared.workloadKeyID ||
		len(loaded.members) != len(prepared.members) {
		t.Fatalf("prepared quorum round trip changed authority coordinates")
	}
	for i := range loaded.members {
		if loaded.members[i].spec != prepared.members[i].spec ||
			loaded.members[i].manifestHash != prepared.members[i].manifestHash ||
			string(loaded.members[i].signerPrivate) != string(prepared.members[i].signerPrivate) ||
			string(loaded.members[i].ownerPrivate) != string(prepared.members[i].ownerPrivate) {
			t.Fatalf("prepared member %d changed across round trip", i)
		}
	}
}
