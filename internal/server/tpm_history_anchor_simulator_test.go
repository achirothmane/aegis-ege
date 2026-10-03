//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMNVHistoryAnchorRejectsWholeVolumeRollbackToValidSignedHead(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-anchor.json"),
		IndexAuth:     []byte("aegis-history-anchor-test"),
		HeadIndexAuth: []byte("aegis-history-head-test"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { undefineTPMHistoryAnchorNV(t, device, cfg) })
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawStore := kernelfabric.TaintRecoveryHistoryStore{
		Dir: filepath.Join(dir, "recovery-history"),
	}
	store := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: anchor,
	}
	base := time.Date(2026, 10, 3, 2, 10, 0, 0, time.UTC)

	first := tpmHistoryAnchorReceipt("h1", "", 1, base)
	signedFirst, err := kernelfabric.SignTaintRecoveryHistoryReceipt(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := store.Append(context.Background(), signedFirst, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	headAtH1, err := os.ReadFile(filepath.Join(rawStore.Dir, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	anchorAtH1, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	stateAtH1, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read H1 anchor state: ok=%t err=%v", ok, err)
	}
	if stateAtH1.Sequence != 1 || stateAtH1.HeadDigest != firstDigest {
		t.Fatalf("unexpected H1 anchor state: %+v", stateAtH1)
	}

	second := tpmHistoryAnchorReceipt(
		"h2",
		firstDigest,
		2,
		base.Add(time.Minute),
	)
	signedSecond, err := kernelfabric.SignTaintRecoveryHistoryReceipt(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := store.Append(context.Background(), signedSecond, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if secondDigest == firstDigest {
		t.Fatal("distinct recovery receipts produced the same digest")
	}
	stateAtH2, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read H2 anchor state: ok=%t err=%v", ok, err)
	}
	if stateAtH2.Generation != stateAtH1.Generation+1 ||
		stateAtH2.Sequence != stateAtH1.Sequence+1 ||
		stateAtH2.HeadDigest != secondDigest ||
		stateAtH2.PreviousHeadDigest != firstDigest {
		t.Fatalf("TPM history anchor did not advance exactly once: H1=%+v H2=%+v", stateAtH1, stateAtH2)
	}
	counterAtH2, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAtH2 != stateAtH2.Generation {
		t.Fatalf(
			"TPM counter/state mismatch before rollback scenario: counter=%d state=%d",
			counterAtH2,
			stateAtH2.Generation,
		)
	}
	if _, digest, exists, err := store.Current(
		context.Background(),
		publicKey,
	); err != nil || !exists || digest != secondDigest {
		t.Fatalf(
			"H2 did not verify before rollback scenario: exists=%t digest=%s err=%v",
			exists,
			digest,
			err,
		)
	}

	// Restore the writable volume to the exact H1 snapshot while the TPM NV
	// counter remains at H2. The old H1 receipt and companion state are each
	// internally valid, but they are no longer current.
	if err := os.WriteFile(filepath.Join(rawStore.Dir, "head.json"), headAtH1, 0o600); err != nil {
		t.Fatal(err)
	}
	h2ReceiptPath := filepath.Join(
		rawStore.Dir,
		"receipts",
		strings.TrimPrefix(secondDigest, "sha256:")+".json",
	)
	if err := os.Remove(h2ReceiptPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, anchorAtH1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.StatePath + ".pending"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	unanchored, unanchoredDigest, exists, err := rawStore.Current(publicKey)
	if err != nil {
		t.Fatalf("restored H1 signature should still verify locally: %v", err)
	}
	if !exists || unanchoredDigest != firstDigest || unanchored.Receipt.ReceiptID != "h1" {
		t.Fatalf(
			"restored local history is not exact H1: exists=%t digest=%s receipt=%+v",
			exists,
			unanchoredDigest,
			unanchored.Receipt,
		)
	}

	restoredState, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read restored H1 anchor state: ok=%t err=%v", ok, err)
	}
	if restoredState.Generation != stateAtH1.Generation ||
		restoredState.Sequence != stateAtH1.Sequence ||
		restoredState.HeadDigest != firstDigest {
		t.Fatalf("companion state was not restored to exact H1: %+v", restoredState)
	}
	counterAfterRestore, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfterRestore != counterAtH2 {
		t.Fatalf(
			"TPM counter unexpectedly rolled back with writable volume: got=%d want=%d",
			counterAfterRestore,
			counterAtH2,
		)
	}

	if _, err := anchor.Current(context.Background()); !errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("TPM did not detect restored companion state: %v", err)
	}
	if _, _, _, err := store.Current(
		context.Background(),
		publicKey,
	); err == nil || !errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("restored signed history was not rejected fail-closed: %v", err)
	}
}

func TestTPMNVHistoryAnchorRecoversCommittedPendingAfterInterruption(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-anchor.json"),
		IndexAuth:     []byte("aegis-history-anchor-crash"),
		HeadIndexAuth: []byte("aegis-history-head-crash"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { undefineTPMHistoryAnchorNV(t, device, cfg) })
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	current, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read initial history anchor: ok=%t err=%v", ok, err)
	}
	nextDigest := "sha256:" + strings.Repeat("a", 64)
	next := current
	next.PreviousGeneration = current.Generation
	next.Generation = current.Generation + 1
	next.PreviousSequence = current.Sequence
	next.Sequence = current.Sequence + 1
	next.PreviousHeadDigest = current.HeadDigest
	next.HeadDigest = nextDigest
	next.Digest = ""
	if err := writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath+".pending", next); err != nil {
		t.Fatal(err)
	}
	if err := anchor.writeProtectedHead(context.Background(), tpmNVHistoryProtectedHead{
		Generation: next.Generation,
		Sequence:   next.Sequence,
		HeadDigest: next.HeadDigest,
	}); err != nil {
		t.Fatal(err)
	}
	counter, err := anchor.helper.incrementCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counter != next.Generation {
		t.Fatalf("counter did not reach pending generation: got=%d want=%d", counter, next.Generation)
	}

	restarted, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Current(context.Background())
	if err != nil {
		t.Fatalf("post-increment pending state did not recover: %v", err)
	}
	if recovered.Sequence != next.Sequence || recovered.HeadDigest != nextDigest {
		t.Fatalf("pending head was not promoted: got=%+v want=(%d,%s)", recovered, next.Sequence, nextDigest)
	}
	if _, err := os.Stat(cfg.StatePath + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("pending state was not consumed: %v", err)
	}
}

func TestTPMNVHistoryAnchorRejectsSameGenerationCompanionRewrite(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-anchor.json"),
		IndexAuth:     []byte("aegis-history-anchor-same-generation"),
		HeadIndexAuth: []byte("aegis-history-head-same-generation"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { undefineTPMHistoryAnchorNV(t, device, cfg) })
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawStore := kernelfabric.TaintRecoveryHistoryStore{
		Dir: filepath.Join(dir, "recovery-history"),
	}
	store := kernelfabric.AnchoredTaintRecoveryHistoryStore{
		Store:  rawStore,
		Anchor: anchor,
	}
	receipt := tpmHistoryAnchorReceipt(
		"same-generation-h1",
		"",
		1,
		time.Date(2026, 10, 3, 2, 20, 0, 0, time.UTC),
	)
	signed, err := kernelfabric.SignTaintRecoveryHistoryReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := store.Append(context.Background(), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	state, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read committed companion state: ok=%t err=%v", ok, err)
	}
	protected, err := anchor.readProtectedHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !protectedTPMHistoryHeadMatches(protected, state) || protected.HeadDigest != digest {
		t.Fatalf("TPM exact head does not match committed H1: protected=%+v state=%+v", protected, state)
	}

	// Rewrite only the writable companion at the same TPM generation and
	// recompute its unkeyed self-hash. A counter-only design would accept this.
	forged := state
	forged.HeadDigest = "sha256:" + strings.Repeat("b", 64)
	if forged.HeadDigest == digest {
		t.Fatal("forged digest unexpectedly equals committed digest")
	}
	forged.Digest = ""
	if err := writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath, forged); err != nil {
		t.Fatal(err)
	}
	rewritten, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("rewritten companion did not remain internally valid: ok=%t err=%v", ok, err)
	}
	if rewritten.Generation != state.Generation || rewritten.HeadDigest != forged.HeadDigest {
		t.Fatalf("same-generation rewrite did not take effect: %+v", rewritten)
	}
	counter, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counter != state.Generation {
		t.Fatalf("same-generation rewrite unexpectedly changed TPM counter: got=%d want=%d", counter, state.Generation)
	}

	if _, err := anchor.Current(context.Background()); !errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("TPM exact head did not reject same-generation companion rewrite: %v", err)
	}
	if _, _, _, err := store.Current(context.Background(), publicKey); err == nil ||
		!errors.Is(err, ErrTPMHistoryAnchorRollback) {
		t.Fatalf("anchored store accepted same-generation companion rewrite: %v", err)
	}
}

func TestTPMNVHistoryAnchorRecoversExactHeadBeforeCounterInterruption(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Skipf("TPM simulator unavailable: %v", err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	device := transport.FromReadWriter(sim)

	dir := t.TempDir()
	cfg := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A151),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A161),
		StatePath:     filepath.Join(dir, "history-anchor.json"),
		IndexAuth:     []byte("aegis-history-anchor-head-first"),
		HeadIndexAuth: []byte("aegis-history-head-head-first"),
	}
	if err := ProvisionTPMNVHistoryAnchor(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { undefineTPMHistoryAnchorNV(t, device, cfg) })
	anchor, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	current, ok, err := readTPMNVHistoryAnchorState(cfg.StatePath)
	if err != nil || !ok {
		t.Fatalf("read initial history anchor: ok=%t err=%v", ok, err)
	}
	nextDigest := "sha256:" + strings.Repeat("c", 64)
	next := current
	next.PreviousGeneration = current.Generation
	next.Generation = current.Generation + 1
	next.PreviousSequence = current.Sequence
	next.Sequence = current.Sequence + 1
	next.PreviousHeadDigest = current.HeadDigest
	next.HeadDigest = nextDigest
	next.Digest = ""
	if err := writeTPMNVHistoryAnchorStateAtomic(cfg.StatePath+".pending", next); err != nil {
		t.Fatal(err)
	}
	if err := anchor.writeProtectedHead(context.Background(), tpmNVHistoryProtectedHead{
		Generation: next.Generation,
		Sequence:   next.Sequence,
		HeadDigest: next.HeadDigest,
	}); err != nil {
		t.Fatal(err)
	}

	counterBefore, err := anchor.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterBefore != current.Generation {
		t.Fatalf("counter advanced before simulated interruption: got=%d want=%d", counterBefore, current.Generation)
	}

	restarted, err := NewTPMNVHistoryAnchor(device, cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Current(context.Background())
	if err != nil {
		t.Fatalf("exact-head-before-counter interruption did not recover: %v", err)
	}
	if recovered.Sequence != next.Sequence || recovered.HeadDigest != nextDigest {
		t.Fatalf("recovered state=%+v want=(%d,%s)", recovered, next.Sequence, nextDigest)
	}
	counterAfter, err := restarted.helper.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfter != next.Generation {
		t.Fatalf("recovery did not finish TPM counter: got=%d want=%d", counterAfter, next.Generation)
	}
	if _, err := os.Stat(cfg.StatePath + ".pending"); !os.IsNotExist(err) {
		t.Fatalf("pending state was not promoted: %v", err)
	}
}

func undefineTPMHistoryAnchorNV(
	t *testing.T,
	device transport.TPM,
	cfg TPMNVHistoryAnchorConfig,
) {
	t.Helper()
	for _, handle := range []tpm2.TPMHandle{cfg.HeadNVIndex, cfg.NVIndex} {
		response, err := (tpm2.NVReadPublic{NVIndex: handle}).Execute(device)
		if err != nil {
			t.Logf("read TPM history NV public 0x%x during cleanup: %v", uint32(handle), err)
			continue
		}
		if _, err := (tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(cfg.OwnerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: handle,
				Name:   response.NVName,
			},
		}).Execute(device); err != nil {
			t.Logf("undefine TPM history NV 0x%x during cleanup: %v", uint32(handle), err)
		}
	}
}

func tpmHistoryAnchorReceipt(
	id,
	previous string,
	epoch uint64,
	recordedAt time.Time,
) kernelfabric.TaintRecoveryHistoryReceipt {
	boot := sha256.Sum256([]byte("tpm-history-boot-" + id))
	plan := sha256.Sum256([]byte("tpm-history-plan-" + id))
	return kernelfabric.TaintRecoveryHistoryReceipt{
		Version:               kernelfabric.TaintRecoveryHistoryReceiptVersion,
		ReceiptID:             id,
		Event:                 kernelfabric.TaintRecoveryHistoryEventRecoveryCommitted,
		BootIDHash:            fmt.Sprintf("sha256:%x", boot[:]),
		PlanDigest:            fmt.Sprintf("sha256:%x", plan[:]),
		CgroupID:              77,
		EnrollmentEpoch:       epoch,
		DirtyGeneration:       epoch,
		CleanGeneration:       epoch,
		CleanEffectAllowed:    true,
		TaintedEffectDenied:   true,
		PreviousReceiptDigest: previous,
		RecordedAt:            recordedAt,
	}
}
