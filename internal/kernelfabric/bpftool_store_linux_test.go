//go:build linux

package kernelfabric

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeBPFToolRunner struct {
	calls [][]string
	err   error
}

func (f *fakeBPFToolRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.err != nil {
		return []byte("bpftool failure"), f.err
	}
	return nil, nil
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
