//go:build linux && cgo

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMRootExportsGenericMeasuredBootCommitmentAndRejectsDrift(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(909)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A179),
		StatePath: filepath.Join(t.TempDir(), "root.json"),
		IndexAuth: []byte("aegis-vcs09-platform-measurement"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	commitment, err := root.CurrentPlatformMeasurement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := kernelfabric.ValidatePlatformMeasurementCommitment(commitment); err != nil {
		t.Fatalf("exported commitment invalid: %v", err)
	}
	if commitment.EvidenceClass != kernelfabric.PlatformMeasurementClassMeasuredBoot {
		t.Fatalf("evidence class=%q", commitment.EvidenceClass)
	}

	state, ok, err := readTPMNVRootState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read TPM state: ok=%t err=%v", ok, err)
	}
	expected, err := kernelfabric.NewPlatformMeasurementCommitment(
		kernelfabric.PlatformMeasurementClassMeasuredBoot,
		state.DeviceIdentity,
		state.MeasuredBootIdentity,
		state.Generation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commitment != expected {
		t.Fatalf("generic commitment does not represent current verified TPM state: got=%+v want=%+v", commitment, expected)
	}

	extendDigest := sha256.Sum256([]byte("aegis-ege/vcs09-measured-boot-drift"))
	if err := legacytpm2.PCRExtend(
		sim,
		tpmutil.Handle(7),
		legacytpm2.AlgSHA256,
		extendDigest[:],
		"",
	); err != nil {
		t.Fatalf("extend measured-boot PCR: %v", err)
	}

	if _, err := root.CurrentPlatformMeasurement(context.Background()); !errors.Is(err, ErrTPMMonotonicRootMeasuredBootChanged) {
		t.Fatalf("expected generic export to fail closed after measured-boot drift, got %v", err)
	}
}

func TestTPMRootPlatformMeasurementIdentityStableAcrossUnrelatedRootGeneration(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(910)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A17A),
		StatePath: filepath.Join(t.TempDir(), "root.json"),
		IndexAuth: []byte("aegis-vcs09-generation"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	before, err := root.CurrentPlatformMeasurement(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	scope := CapabilityFenceScope{
		IntentID: "vcs09-intent",
		Kind:     "vcs09-kind",
		Target:   egeproto.Target{Type: "node", Name: "vcs09-target"},
	}
	observed := capabilityAuthoritySnapshotFromIssue(CapabilityFenceIssue{
		AuthorityDomain: "vcs09/domain",
		AuthorityTerm:   1,
		DecisionEpoch:   1,
		RevocationEpoch: 1,
	})
	if _, err := root.Advance(context.Background(), scope, observed); err != nil {
		t.Fatal(err)
	}
	after, err := root.CurrentPlatformMeasurement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.VerifiedGeneration <= before.VerifiedGeneration {
		t.Fatalf("expected monotonic verification generation to advance: before=%d after=%d", before.VerifiedGeneration, after.VerifiedGeneration)
	}
	if after.CommitmentDigest != before.CommitmentDigest {
		t.Fatal("unchanged measured boot identity should remain stable across unrelated capability-root advance")
	}
}
