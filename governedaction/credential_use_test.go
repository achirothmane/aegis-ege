package governedaction_test

import (
	"errors"
	"testing"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

func credentialFixture() ga.CredentialUseBinding {
	return ga.CredentialUseBinding{
		HandleID:       "credh_01",
		ActionRevision: "action-revision-abc",
		EffectID:       "effect-001",
		Audience:       "github-api",
		Destination:    "https://api.github.com",
		Scope:          "actions:write",
		TrustEpoch:     "credential-epoch-4",
		ValidUntil:     time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC),
	}
}

func TestCheckCredentialUseExact(t *testing.T) {
	base := credentialFixture()
	if err := ga.CheckCredentialUse(base, base, base.ValidUntil.Add(-time.Minute)); err != nil {
		t.Fatalf("exact credential use rejected: %v", err)
	}
}

func TestCheckCredentialUseRejectsReplayAndAudienceConfusion(t *testing.T) {
	base := credentialFixture()
	at := base.ValidUntil.Add(-time.Minute)

	cases := []struct {
		name   string
		mutate func(*ga.CredentialUseBinding)
	}{
		{"handle", func(v *ga.CredentialUseBinding) { v.HandleID = "credh_02" }},
		{"action", func(v *ga.CredentialUseBinding) { v.ActionRevision = "action-revision-other" }},
		{"effect-replay", func(v *ga.CredentialUseBinding) { v.EffectID = "effect-002" }},
		{"audience-confusion", func(v *ga.CredentialUseBinding) { v.Audience = "calendar-api" }},
		{"destination", func(v *ga.CredentialUseBinding) { v.Destination = "https://evil.example" }},
		{"scope", func(v *ga.CredentialUseBinding) { v.Scope = "repo:admin" }},
		{"trust-epoch", func(v *ga.CredentialUseBinding) { v.TrustEpoch = "credential-epoch-5" }},
		{"expiry", func(v *ga.CredentialUseBinding) { v.ValidUntil = v.ValidUntil.Add(time.Hour) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			tc.mutate(&current)
			err := ga.CheckCredentialUse(base, current, at)
			if !errors.Is(err, ga.ErrCredentialBindingChanged) {
				t.Fatalf("error=%v; want binding changed", err)
			}
		})
	}
}

func TestCheckCredentialUseFailsClosedOnMissingOrExpiredState(t *testing.T) {
	base := credentialFixture()

	missing := base
	missing.Audience = ""
	if err := ga.CheckCredentialUse(base, missing, base.ValidUntil.Add(-time.Minute)); !errors.Is(err, ga.ErrMissingCredentialBinding) {
		t.Fatalf("missing error=%v", err)
	}
	if err := ga.CheckCredentialUse(base, base, base.ValidUntil); !errors.Is(err, ga.ErrExpired) {
		t.Fatalf("expiry error=%v; want expired", err)
	}
	if err := ga.CheckCredentialUse(base, base, time.Time{}); !errors.Is(err, ga.ErrUnknownTime) {
		t.Fatalf("unknown-time error=%v; want unknown time", err)
	}
}
