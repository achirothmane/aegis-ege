//go:build linux

package kernelfabric

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeBPFToolRunner struct {
	calls  [][]string
	err    error
	output []byte
}

func (f *fakeBPFToolRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.err != nil {
		return []byte("bpftool failure"), f.err
	}
	return append([]byte(nil), f.output...), nil
}

func TestBPFToolStoreUsesPinnedMapsWithoutShell(t *testing.T) {
	store, err := NewBPFToolStore(
		"/usr/sbin/bpftool",
		"/sys/fs/bpf/aegis/maps/aegis_capsules",
		"/sys/fs/bpf/aegis/maps/aegis_fences",
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeBPFToolRunner{}
	store.Runner = runner

	req := testInstallRequest(t)
	result, err := (Installer{Store: store}).Install(
		context.Background(),
		req,
		testClock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected fence+capsule updates, got %d calls", len(runner.calls))
	}
	if !containsSequence(runner.calls[0], "map", "update", "pinned", store.FenceMapPath, "key", "hex") {
		t.Fatalf("unexpected fence command: %v", runner.calls[0])
	}
	if !containsSequence(runner.calls[1], "map", "update", "pinned", store.CapsuleMapPath, "key", "hex") {
		t.Fatalf("unexpected capsule command: %v", runner.calls[1])
	}

	if err := store.DeleteCapsule(context.Background(), result.Scope); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 || !containsSequence(
		runner.calls[2],
		"map", "delete", "pinned", store.CapsuleMapPath, "key", "hex",
	) {
		t.Fatalf("unexpected delete command: %v", runner.calls)
	}
}

func TestBPFToolStorePropagatesKernelMapFailure(t *testing.T) {
	store, err := NewBPFToolStore(
		"/usr/sbin/bpftool",
		"/sys/fs/bpf/aegis/maps/aegis_capsules",
		"/sys/fs/bpf/aegis/maps/aegis_fences",
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeBPFToolRunner{err: errors.New("exit status 1")}
	store.Runner = runner

	fenceKey, err := FenceKey(42, ActionClassNetworkConnect)
	if err != nil {
		t.Fatal(err)
	}
	var boot [32]byte
	boot[0] = 1
	err = store.PutFence(context.Background(), fenceKey, ScopeFenceState{
		BootIDHash:      boot,
		AuthorityTerm:   1,
		DecisionEpoch:   1,
		RevocationEpoch: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "bpftool failure") {
		t.Fatalf("expected command output in error, got %v", err)
	}
}

func containsSequence(got []string, want ...string) bool {
	if len(want) > len(got) {
		return false
	}
	for i := 0; i <= len(got)-len(want); i++ {
		ok := true
		for j := range want {
			if got[i+j] != want[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}


func TestBPFToolStoreReadsPinnedFenceJSON(t *testing.T) {
	store, err := NewBPFToolStore(
		"/usr/sbin/bpftool",
		"/sys/fs/bpf/aegis/maps/aegis_capsules",
		"/sys/fs/bpf/aegis/maps/aegis_fences",
	)
	if err != nil {
		t.Fatal(err)
	}
	var boot [32]byte
	for i := range boot {
		boot[i] = byte(i + 1)
	}
	want := ScopeFenceState{
		BootIDHash:      boot,
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	raw, err := MarshalScopeFenceState(want)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([]string, 0, len(raw))
	for _, b := range raw {
		parts = append(parts, fmt.Sprintf("%q", "0x"+hex.EncodeToString([]byte{b})))
	}
	runner := &fakeBPFToolRunner{
		output: []byte(`{"key":[],"value":[` + strings.Join(parts, ",") + `]}`),
	}
	store.Runner = runner

	key, err := FenceKey(42, ActionClassNetworkConnect)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetFence(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fence=%+v want=%+v", got, want)
	}
	if len(runner.calls) != 1 ||
		!containsSequence(runner.calls[0], "-j", "map", "lookup", "pinned", store.FenceMapPath, "key", "hex") {
		t.Fatalf("unexpected lookup command: %v", runner.calls)
	}
}

func TestDecodeBPFToolLookupValueAcceptsNumericBytes(t *testing.T) {
	got, err := decodeBPFToolLookupValue([]byte(`{"value":[0,1,254,255]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 1, 254, 255}
	if len(got) != len(want) {
		t.Fatalf("value=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("value=%v want=%v", got, want)
		}
	}
}

func TestDecodeBPFToolLookupValueRejectsMalformedByte(t *testing.T) {
	_, err := decodeBPFToolLookupValue([]byte(`{"value":["0x0011"]}`))
	if err == nil {
		t.Fatal("expected malformed bpftool byte rejection")
	}
}
