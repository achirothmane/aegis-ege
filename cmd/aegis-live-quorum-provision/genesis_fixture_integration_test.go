//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/integrationfixture"
)

func TestWriteIndependentLiveQuorumGenesisFixtureForTargetExecutable(t *testing.T) {
	preparedPath := strings.TrimSpace(os.Getenv("LIVE_QUORUM_PREPARED_BUNDLE"))
	fixtureDir := strings.TrimSpace(os.Getenv("LIVE_QUORUM_GENESIS_FIXTURE_DIR"))
	targetExecutable := strings.TrimSpace(os.Getenv("LIVE_QUORUM_GENESIS_TARGET_EXECUTABLE"))
	if preparedPath == "" || fixtureDir == "" || targetExecutable == "" {
		t.Skip("prepared bundle, fixture dir, and target executable are required")
	}

	prepared, err := loadIndependentPreparedQuorum(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := integrationfixture.NewProductionGenesisFixtureForExecutable(
		fixtureDir,
		prepared.envelope,
		prepared.genesisEpoch,
		targetExecutable,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.ManifestPath != filepath.Join(fixtureDir, "genesis.json") ||
		fixture.BundlePath != filepath.Join(fixtureDir, "verification-bundle.json") {
		t.Fatalf("unexpected Genesis fixture paths: %+v", fixture)
	}
	for _, path := range []string{fixture.ManifestPath, fixture.BundlePath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == 0 {
			t.Fatalf("Genesis fixture file %s is empty", path)
		}
	}
}
