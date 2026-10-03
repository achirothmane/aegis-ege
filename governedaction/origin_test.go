package governedaction_test

import (
	"errors"
	"testing"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

func originFixture() ga.OriginBinding {
	return ga.OriginBinding{
		OriginID:     "repo:achirothmane/example@tool",
		OriginType:   "repository",
		SourceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustDomain:  "owner-controlled-github",
		TrustEpoch:   "epoch-7",
		Capabilities: ga.OriginSupplyInstructions | ga.OriginRegisterTools,
	}
}

func TestCheckOriginExactAndSubset(t *testing.T) {
	admitted := originFixture()

	t.Run("exact", func(t *testing.T) {
		if err := ga.CheckOrigin(admitted, admitted); err != nil {
			t.Fatalf("exact origin rejected: %v", err)
		}
	})

	t.Run("capability-subset", func(t *testing.T) {
		current := admitted
		current.Capabilities = ga.OriginSupplyInstructions
		if err := ga.CheckOrigin(admitted, current); err != nil {
			t.Fatalf("capability subset rejected: %v", err)
		}
	})
}

func TestCheckOriginRejectsSilentChange(t *testing.T) {
	base := originFixture()

	cases := []struct {
		name   string
		mutate func(*ga.OriginBinding)
		cause  error
	}{
		{
			name: "missing-origin-id",
			mutate: func(v *ga.OriginBinding) {
				v.OriginID = ""
			},
			cause: ga.ErrMissingOrigin,
		},
		{
			name: "origin-id-changed",
			mutate: func(v *ga.OriginBinding) {
				v.OriginID = "plugin:other"
			},
			cause: ga.ErrOriginChanged,
		},
		{
			name: "origin-type-changed",
			mutate: func(v *ga.OriginBinding) {
				v.OriginType = "mcp"
			},
			cause: ga.ErrOriginChanged,
		},
		{
			name: "artifact-changed",
			mutate: func(v *ga.OriginBinding) {
				v.SourceDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			cause: ga.ErrOriginChanged,
		},
		{
			name: "trust-domain-changed",
			mutate: func(v *ga.OriginBinding) {
				v.TrustDomain = "downloaded-untrusted"
			},
			cause: ga.ErrOriginChanged,
		},
		{
			name: "trust-epoch-changed",
			mutate: func(v *ga.OriginBinding) {
				v.TrustEpoch = "epoch-8"
			},
			cause: ga.ErrOriginChanged,
		},
		{
			name: "silent-tool-registration",
			mutate: func(v *ga.OriginBinding) {
				v.Capabilities |= ga.OriginRegisterConnectors
			},
			cause: ga.ErrOriginCapabilityExpanded,
		},
		{
			name: "silent-network-egress",
			mutate: func(v *ga.OriginBinding) {
				v.Capabilities |= ga.OriginNetworkEgress
			},
			cause: ga.ErrOriginCapabilityExpanded,
		},
		{
			name: "unknown-capability-bit",
			mutate: func(v *ga.OriginBinding) {
				v.Capabilities |= ga.OriginCapability(1 << 31)
			},
			cause: ga.ErrUnknownOriginCapability,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			tc.mutate(&current)
			err := ga.CheckOrigin(base, current)
			if !errors.Is(err, tc.cause) {
				t.Fatalf("error=%v; want cause=%v", err, tc.cause)
			}
		})
	}
}

func TestCheckOriginDoesNotTreatDigestAsAuthority(t *testing.T) {
	admitted := originFixture()
	current := admitted

	// Same artifact bytes under a different trust authority are not the same
	// admitted origin. Integrity and authority remain separate.
	current.TrustDomain = "attacker-self-signed"
	if err := ga.CheckOrigin(admitted, current); !errors.Is(err, ga.ErrOriginChanged) {
		t.Fatalf("error=%v; want origin change", err)
	}
}
