package governedaction_test

import (
	"errors"
	"testing"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

func approvalFixture() ga.ApprovalUseBinding {
	return ga.ApprovalUseBinding{
		ApprovalRef:    "sha256:approval-attestation-17",
		ActionRevision: "action-revision-abc",
		EffectID:       "effect-001",
		Target:         "kubernetes://cluster-a/ns/default/pod/pod-a",
		Scope:          "delete",
		Nonce:          "approval-use-nonce-001",
		MaxEffects:     1,
		ValidUntil:     time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC),
	}
}

func TestCheckApprovalUsePositiveAndReplay(t *testing.T) {
	admitted := approvalFixture()
	current := admitted
	at := admitted.ValidUntil.Add(-time.Minute)

	if err := ga.CheckApprovalUse(admitted, current, at, 0); err != nil {
		t.Fatalf("fresh one-time approval rejected: %v", err)
	}

	if err := ga.CheckApprovalUse(admitted, current, at, 1); !errors.Is(err, ga.ErrApprovalExhausted) {
		t.Fatalf("replay error=%v; want exhausted", err)
	}
}

func TestCheckApprovalUseRejectsScopeSubstitution(t *testing.T) {
	base := approvalFixture()
	at := base.ValidUntil.Add(-time.Minute)

	cases := []struct {
		name   string
		mutate func(*ga.ApprovalUseBinding)
		cause  error
	}{
		{"approval-ref", func(v *ga.ApprovalUseBinding) { v.ApprovalRef = "sha256:other" }, ga.ErrApprovalBindingChanged},
		{"action-revision", func(v *ga.ApprovalUseBinding) { v.ActionRevision = "action-revision-other" }, ga.ErrApprovalBindingChanged},
		{"effect-id", func(v *ga.ApprovalUseBinding) { v.EffectID = "effect-002" }, ga.ErrApprovalBindingChanged},
		{"target", func(v *ga.ApprovalUseBinding) { v.Target = "kubernetes://cluster-a/ns/default/pod/pod-b" }, ga.ErrApprovalBindingChanged},
		{"scope", func(v *ga.ApprovalUseBinding) { v.Scope = "patch" }, ga.ErrApprovalBindingChanged},
		{"nonce", func(v *ga.ApprovalUseBinding) { v.Nonce = "approval-use-nonce-002" }, ga.ErrApprovalBindingChanged},
		{"limit-expanded", func(v *ga.ApprovalUseBinding) { v.MaxEffects = 2 }, ga.ErrApprovalBindingChanged},
		{"expiry-changed", func(v *ga.ApprovalUseBinding) { v.ValidUntil = v.ValidUntil.Add(time.Hour) }, ga.ErrApprovalBindingChanged},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			tc.mutate(&current)
			err := ga.CheckApprovalUse(base, current, at, 0)
			if !errors.Is(err, tc.cause) {
				t.Fatalf("error=%v; want=%v", err, tc.cause)
			}
		})
	}
}

func TestCheckApprovalUseFailsClosedOnMissingOrExpiredState(t *testing.T) {
	base := approvalFixture()

	missing := base
	missing.Target = ""
	if err := ga.CheckApprovalUse(base, missing, base.ValidUntil.Add(-time.Minute), 0); !errors.Is(err, ga.ErrMissingApprovalBinding) {
		t.Fatalf("missing error=%v", err)
	}

	zeroLimit := base
	zeroLimit.MaxEffects = 0
	if err := ga.CheckApprovalUse(zeroLimit, zeroLimit, base.ValidUntil.Add(-time.Minute), 0); !errors.Is(err, ga.ErrApprovalEffectLimit) {
		t.Fatalf("zero limit error=%v", err)
	}

	if err := ga.CheckApprovalUse(base, base, base.ValidUntil, 0); !errors.Is(err, ga.ErrExpired) {
		t.Fatalf("expiry error=%v; want expired", err)
	}

	if err := ga.CheckApprovalUse(base, base, time.Time{}, 0); !errors.Is(err, ga.ErrUnknownTime) {
		t.Fatalf("unknown-time error=%v; want unknown time", err)
	}
}

func TestCheckApprovalUseDoesNotClaimConcurrencySafety(t *testing.T) {
	// Two callers both presenting effectsUsed=0 could both pass this pure
	// relation. The adapter must make durable charge + effect safe using native
	// transactions/CAS/fencing. This test freezes that claim boundary.
	base := approvalFixture()
	at := base.ValidUntil.Add(-time.Minute)

	if err := ga.CheckApprovalUse(base, base, at, 0); err != nil {
		t.Fatalf("first boundary rejected: %v", err)
	}
	if err := ga.CheckApprovalUse(base, base, at, 0); err != nil {
		t.Fatalf("second independent pre-charge boundary rejected: %v", err)
	}
}
