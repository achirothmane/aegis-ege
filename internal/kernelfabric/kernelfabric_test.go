package kernelfabric

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func digestOf(ch byte) string {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = ch
	}
	return "sha256:" + string(raw)
}

func testClock() ClockSnapshot {
	var boot [32]byte
	boot[0] = 1
	return ClockSnapshot{
		WallNow:    time.Date(2026, 9, 27, 20, 0, 0, 0, time.UTC),
		MonoNowNS:  10_000,
		BootIDHash: boot,
	}
}

func testInstallRequest(t *testing.T) InstallRequest {
	t.Helper()
	scope, err := (NetworkScope{
		CgroupID:    42,
		Destination: netip.MustParseAddr("203.0.113.10"),
		Port:        443,
		Protocol:    6,
	}).ExactKey()
	if err != nil {
		t.Fatal(err)
	}
	return InstallRequest{
		Scope:           scope,
		DecisionID:      "decision-1",
		Subject:         "workload/api",
		Action:          "network.connect",
		PolicyDigest:    digestOf('a'),
		EvidenceDigest:  digestOf('b'),
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
		Decision:        KernelDecisionAllow,
		Lease: ExternalLease{
			IssuedAt:    testClock().WallNow.Add(-time.Second),
			NotAfter:    testClock().WallNow.Add(30 * time.Second),
			MaxLifetime: 10 * time.Second,
		},
	}
}

func TestKernelABIFixedSizes(t *testing.T) {
	req := testInstallRequest(t)
	scopeBytes, err := MarshalScopeKey(req.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopeBytes) != ScopeKeySize {
		t.Fatalf("scope key size=%d want=%d", len(scopeBytes), ScopeKeySize)
	}
	fenceKey, err := FenceKey(req.Scope.CgroupID, req.Scope.ActionClass)
	if err != nil {
		t.Fatal(err)
	}
	fenceKeyBytes, err := MarshalScopeFenceKey(fenceKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(fenceKeyBytes) != ScopeFenceKeySize {
		t.Fatalf("fence key size=%d want=%d", len(fenceKeyBytes), ScopeFenceKeySize)
	}

	store := &recordingKernelStore{}
	result, err := (Installer{Store: store}).Install(context.Background(), req, testClock())
	if err != nil {
		t.Fatal(err)
	}
	fenceBytes, err := MarshalScopeFenceState(result.Fence)
	if err != nil {
		t.Fatal(err)
	}
	if len(fenceBytes) != ScopeFenceStateSize {
		t.Fatalf("fence state size=%d want=%d", len(fenceBytes), ScopeFenceStateSize)
	}
	capsuleBytes, err := MarshalDecisionCapsule(result.Capsule)
	if err != nil {
		t.Fatal(err)
	}
	if len(capsuleBytes) != DecisionCapsuleSize {
		t.Fatalf("capsule size=%d want=%d", len(capsuleBytes), DecisionCapsuleSize)
	}
}

func TestNetworkScopeExactAndWildcard(t *testing.T) {
	key, err := (NetworkScope{
		CgroupID:    99,
		Destination: netip.MustParseAddr("2001:db8::10"),
		Port:        8443,
		Protocol:    6,
	}).ExactKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.AddressFamily != AddressFamilyIPv6 || key.DestinationPort != 8443 || key.Protocol != 6 {
		t.Fatalf("unexpected exact key: %+v", key)
	}
	wildcard, err := WildcardNetworkKey(99)
	if err != nil {
		t.Fatal(err)
	}
	if wildcard.AddressFamily != 0 || wildcard.DestinationPort != 0 || wildcard.DestinationAddr != [16]byte{} {
		t.Fatalf("unexpected wildcard key: %+v", wildcard)
	}
}

func TestBindExternalLeaseUsesLocalMonotonicDeadlineAndCapsLifetime(t *testing.T) {
	clock := testClock()
	lease := ExternalLease{
		IssuedAt:    clock.WallNow.Add(-time.Second),
		NotAfter:    clock.WallNow.Add(time.Minute),
		MaxLifetime: 5 * time.Second,
	}
	local, err := BindExternalLease(lease, clock)
	if err != nil {
		t.Fatal(err)
	}
	if local.InstalledAtMonoNS != clock.MonoNowNS {
		t.Fatalf("installed mono=%d want=%d", local.InstalledAtMonoNS, clock.MonoNowNS)
	}
	if local.DeadlineMonoNS != clock.MonoNowNS+uint64((5*time.Second).Nanoseconds()) {
		t.Fatalf("deadline=%d", local.DeadlineMonoNS)
	}
	if local.BootIDHash != clock.BootIDHash {
		t.Fatal("boot identity was not bound")
	}
}

func TestBindExternalLeaseRejectsExpiredAuthorization(t *testing.T) {
	clock := testClock()
	_, err := BindExternalLease(ExternalLease{
		NotAfter:    clock.WallNow.Add(-time.Nanosecond),
		MaxLifetime: time.Second,
	}, clock)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expected expired lease, got %v", err)
	}
}

func TestReadBootIDHashStableWithinBootID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(path, []byte("abc-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := ReadBootIDHash(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadBootIDHash(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first == [32]byte{} {
		t.Fatalf("unexpected boot id hash: %x %x", first, second)
	}
}

type recordingKernelStore struct {
	ops          []string
	fence        ScopeFenceState
	capsule      DecisionCapsule
	failCapsule  error
}

func (s *recordingKernelStore) PutFence(context.Context, ScopeFenceKey, ScopeFenceState) error {
	s.ops = append(s.ops, "fence")
	return nil
}

func (s *recordingKernelStore) PutCapsule(_ context.Context, _ ScopeKey, capsule DecisionCapsule) error {
	s.ops = append(s.ops, "capsule")
	s.capsule = capsule
	return s.failCapsule
}

func (s *recordingKernelStore) DeleteCapsule(context.Context, ScopeKey) error {
	s.ops = append(s.ops, "delete")
	return nil
}

func TestInstallerAdvancesFenceBeforePublishingAllow(t *testing.T) {
	store := &recordingKernelStore{}
	result, err := (Installer{Store: store}).Install(
		context.Background(),
		testInstallRequest(t),
		testClock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.ops) != 2 || store.ops[0] != "fence" || store.ops[1] != "capsule" {
		t.Fatalf("unsafe install ordering: %v", store.ops)
	}
	if result.Capsule.Decision != KernelDecisionAllow {
		t.Fatalf("unexpected decision: %d", result.Capsule.Decision)
	}
	if result.Capsule.DeadlineMonoNS <= result.Capsule.InstalledAtMonoNS {
		t.Fatal("capsule deadline was not locally bound")
	}
}

func TestInstallerCapsuleFailureLeavesFenceAdvancedAndCleansStaleEntry(t *testing.T) {
	store := &recordingKernelStore{failCapsule: errors.New("map write failed")}
	_, err := (Installer{Store: store}).Install(
		context.Background(),
		testInstallRequest(t),
		testClock(),
	)
	if err == nil {
		t.Fatal("expected capsule installation failure")
	}
	want := []string{"fence", "capsule", "delete"}
	if len(store.ops) != len(want) {
		t.Fatalf("ops=%v", store.ops)
	}
	for i := range want {
		if store.ops[i] != want[i] {
			t.Fatalf("ops=%v want=%v", store.ops, want)
		}
	}
}

func TestReferenceEvaluatorFailsClosedAcrossEveryFenceDimension(t *testing.T) {
	store := &recordingKernelStore{}
	result, err := (Installer{Store: store}).Install(
		context.Background(),
		testInstallRequest(t),
		testClock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	capsule := result.Capsule
	fence := result.Fence
	now := capsule.InstalledAtMonoNS + 1

	if got := EvaluateReference(&capsule, &fence, now); got.Verdict != VerdictAllow {
		t.Fatalf("matching capsule rejected: %+v", got)
	}

	cases := []struct {
		name string
		mutate func(*DecisionCapsule, *ScopeFenceState)
		reason DenyReason
	}{
		{"boot", func(c *DecisionCapsule, _ *ScopeFenceState) { c.BootIDHash[0] ^= 0xff }, DenyBootMismatch},
		{"authority", func(c *DecisionCapsule, _ *ScopeFenceState) { c.AuthorityTerm++ }, DenyAuthorityTermMismatch},
		{"decision", func(c *DecisionCapsule, _ *ScopeFenceState) { c.DecisionEpoch++ }, DenyDecisionSuperseded},
		{"revocation", func(c *DecisionCapsule, _ *ScopeFenceState) { c.RevocationEpoch++ }, DenyRevoked},
		{"blocked", func(c *DecisionCapsule, _ *ScopeFenceState) { c.Decision = KernelDecisionBlock }, DenyBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := capsule
			f := fence
			tc.mutate(&c, &f)
			got := EvaluateReference(&c, &f, now)
			if got.Verdict != VerdictDeny || got.Reason != tc.reason {
				t.Fatalf("got %+v want reason=%v", got, tc.reason)
			}
		})
	}

	if got := EvaluateReference(&capsule, &fence, capsule.DeadlineMonoNS+1); got.Reason != DenyExpired {
		t.Fatalf("expired capsule got %+v", got)
	}
	if got := EvaluateReference(&capsule, nil, now); got.Reason != DenyMissingFence {
		t.Fatalf("missing fence got %+v", got)
	}
	if got := EvaluateReference(nil, &fence, now); got.Reason != DenyMissingCapsule {
		t.Fatalf("missing capsule got %+v", got)
	}
}
