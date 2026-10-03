//go:build linux && cgo

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMRootRejectsPermitAfterMeasuredBootPCRDrift(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(303)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A142),
		StatePath: filepath.Join(dir, "root.json"),
		IndexAuth: []byte("aegis-root-measured-boot-test"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report: kubeadapter.GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
		},
	}
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   41,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, root)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(
		controller,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			MutationsEnabled:         true,
			RequireAuthentication:    true,
			Authorizer:               allowAuthorizer{},
			ReplayGuard:              replay,
			RequireCapabilityFencing: true,
			CapabilityFenceAuthority: authority,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	permitT1 := prepareRootedCapabilityPermit(t, srv)
	scope := CapabilityFenceScope{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
	}

	stateBefore, ok, err := readTPMNVRootState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read TPM root state: ok=%t err=%v", ok, err)
	}
	deviceBefore, err := root.deviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if deviceBefore != stateBefore.DeviceIdentity {
		t.Fatalf("device identity drifted before PCR change: state=%s live=%s", stateBefore.DeviceIdentity, deviceBefore)
	}

	extendDigest := sha256.Sum256([]byte("aegis-ege/measured-boot-drift/v1"))
	if err := legacytpm2.PCRExtend(
		sim,
		tpmutil.Handle(7),
		legacytpm2.AlgSHA256,
		extendDigest[:],
		"",
	); err != nil {
		t.Fatalf("extend measured-boot PCR 7: %v", err)
	}

	deviceAfter, err := root.deviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if deviceAfter != deviceBefore {
		t.Fatalf("PCR drift unexpectedly changed TPM endorsement identity: before=%s after=%s", deviceBefore, deviceAfter)
	}
	measuredAfter, err := root.measuredBootIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if measuredAfter == stateBefore.MeasuredBootIdentity {
		t.Fatalf("PCR 7 extension did not change measured-boot identity: %s", measuredAfter)
	}

	if _, err := root.Current(context.Background(), scope); !errors.Is(err, ErrTPMMonotonicRootMeasuredBootChanged) {
		t.Fatalf("expected measured boot drift rejection, got %v", err)
	}

	recorder := executeRootedCapabilityPermit(t, srv, permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("pre-drift permit expected 409 after PCR drift, got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_ROOT_MEASURED_BOOT_CHANGED") {
		t.Fatalf("unexpected measured-boot denial: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("permit crossed effect boundary after PCR drift: mutation controller calls=%d", controller.executeCalls)
	}
}
