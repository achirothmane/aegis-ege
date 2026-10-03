//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMRootRejectsCopiedStateOnDifferentEndorsementIdentity(t *testing.T) {
	simA, err := simulator.GetWithFixedSeedInsecure(101)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)

	dir := t.TempDir()
	cfgA := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A141),
		StatePath: filepath.Join(dir, "root-a.json"),
		IndexAuth: []byte("aegis-root-device-test"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), deviceA, cfgA); err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	rootA, err := NewTPMNVMonotonicRoot(deviceA, cfgA)
	if err != nil {
		_ = simA.Close()
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
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, rootA)
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(filepath.Join(dir, "replay"))
	if err != nil {
		_ = simA.Close()
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
		_ = simA.Close()
		t.Fatal(err)
	}

	permitT1 := prepareRootedCapabilityPermit(t, srv)
	scope := CapabilityFenceScope{
		IntentID: "intent-cap-1",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-7"},
	}
	stateA, ok, err := readTPMNVRootState(cfgA.StatePath)
	if err != nil || !ok {
		_ = simA.Close()
		t.Fatalf("read TPM-A root state: ok=%t err=%v", ok, err)
	}
	counterA, err := rootA.readCounter(context.Background())
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	if counterA != stateA.Generation {
		_ = simA.Close()
		t.Fatalf("TPM-A state/counter mismatch: state=%d counter=%d", stateA.Generation, counterA)
	}
	if err := simA.Close(); err != nil {
		t.Fatalf("close TPM-A simulator: %v", err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(202)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)

	cfgB := cfgA
	cfgB.StatePath = filepath.Join(dir, "root-b.json")
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	rootB, err := NewTPMNVMonotonicRoot(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := rootB.deviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identityB == stateA.DeviceIdentity {
		t.Fatalf("TPM-A and TPM-B unexpectedly share endorsement identity: %s", identityB)
	}

	counterB, err := rootB.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for counterB < stateA.Generation {
		counterB, err = rootB.incrementCounter(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	if counterB != stateA.Generation {
		t.Fatalf("could not align TPM-B counter with copied state: counter=%d state=%d", counterB, stateA.Generation)
	}

	if err := writeTPMNVRootStateAtomic(cfgB.StatePath, stateA); err != nil {
		t.Fatalf("copy TPM-A companion state onto TPM-B: %v", err)
	}

	authority.Root = rootB
	if _, err := rootB.Current(context.Background(), scope); !errors.Is(err, ErrTPMMonotonicRootDeviceChanged) {
		t.Fatalf("expected copied state to be rejected on TPM-B, got %v", err)
	}

	recorder := executeRootedCapabilityPermit(t, srv, permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("copied TPM-A permit expected 409 on TPM-B, got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_ROOT_DEVICE_CHANGED") {
		t.Fatalf("unexpected device-change denial: %s", recorder.Body.String())
	}
	if controller.executeCalls != 0 {
		t.Fatalf("copied TPM state reached mutation controller %d times", controller.executeCalls)
	}
}
