//go:build integration

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/achirothmane/easl/genesis"
	"github.com/achirothmane/aegis-ege/internal/genesisbootstrap"
	"github.com/achirothmane/aegis-ege/internal/testsupport"
)

func TestIndependentLiveQuorumActivationRequiresVerifiedGenesisPin(t *testing.T) {
	required := []string{
		"LIVE_QUORUM_CLIENT_BUNDLE",
		"LIVE_QUORUM_WITNESS_A_ADMIN_KUBECONFIG",
		"LIVE_QUORUM_WITNESS_B_ADMIN_KUBECONFIG",
		"LIVE_QUORUM_WITNESS_C_ADMIN_KUBECONFIG",
		"LIVE_QUORUM_WITNESS_A_CHAOS_KUBECONFIG",
		"LIVE_QUORUM_WITNESS_B_CHAOS_KUBECONFIG",
		"LIVE_QUORUM_WITNESS_C_CHAOS_KUBECONFIG",
	}
	for _, name := range required {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Skipf("%s is required", name)
		}
	}

	prepared, err := prepareIndependentQuorum()
	if err != nil {
		t.Fatal(err)
	}

	if err := activateIndependentControlPlanesWithPin(
		t.Context(),
		prepared,
		genesisbootstrap.VerifiedGenesisPin{},
	); err == nil || !strings.Contains(err.Error(), "verified Genesis pin is required") {
		t.Fatalf("zero Genesis pin activation=%v, want fail-closed", err)
	}

	fixture, err := testsupport.NewProductionGenesisFixture(
		t.TempDir(),
		prepared.envelope,
		prepared.genesisEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, result, pin, err := genesisbootstrap.BootstrapProductionWithSubjectPin(
		t.Context(),
		fixture.ManifestPath,
		fixture.BundlePath,
		prepared.genesisEpoch,
		independentMinimumDoctrineEpoch,
		genesis.ConformanceC3,
		fixture.Subject,
		fixture.Now,
	)
	if err != nil {
		t.Fatalf("production Genesis bootstrap: %v result=%+v", err, result)
	}
	if runtime == nil || result.State != genesis.StateReady {
		t.Fatalf("production Genesis did not reach BOOTSTRAP_READY: runtime=%v result=%+v", runtime, result)
	}
	if pin.CapabilityEnvelopeHash() != prepared.envelopeHash ||
		pin.GenesisEpoch() != prepared.genesisEpoch {
		t.Fatalf(
			"verified pin mismatch: epoch=%d hash=%q want epoch=%d hash=%q",
			pin.GenesisEpoch(),
			pin.CapabilityEnvelopeHash(),
			prepared.genesisEpoch,
			prepared.envelopeHash,
		)
	}

	tampered := prepared
	tampered.envelope = append(append([]byte(nil), prepared.envelope...), '\n')
	tampered.envelopeHash = sha256Digest(tampered.envelope)
	if err := activateIndependentControlPlanesWithPin(
		t.Context(),
		tampered,
		pin,
	); err == nil || !strings.Contains(err.Error(), "capability envelope hash") {
		t.Fatalf("tampered live quorum envelope activation=%v, want verified Genesis rejection", err)
	}

	if err := activateIndependentControlPlanesWithPin(
		t.Context(),
		prepared,
		pin,
	); err != nil {
		t.Fatalf("activate independent live quorum from verified Genesis: %v", err)
	}

	payload, err := os.ReadFile(requireEnv("LIVE_QUORUM_CLIENT_BUNDLE"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle liveQuorumBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.GenesisEpoch != pin.GenesisEpoch() ||
		bundle.CapabilityEnvelopeHash != pin.CapabilityEnvelopeHash() ||
		len(bundle.Members) != 3 {
		t.Fatalf("live bundle lost verified Genesis authority: %+v", bundle)
	}
}
