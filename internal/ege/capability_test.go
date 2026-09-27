package ege

import (
	"errors"
	"testing"
)

func testCapabilityStateBinding() CapabilityStateBinding {
	return CapabilityStateBinding{
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		TargetIdentity:  "uid-7",
		ResourceVersion: "100",
		PlanDigest:      "sha256:plan",
	}
}

func testCapabilityClaims(t *testing.T) CapabilityFenceClaims {
	t.Helper()
	binding := testCapabilityStateBinding()
	digest, err := DigestCapabilityStateBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	return CapabilityFenceClaims{
		Version:            CapabilityFenceVersion,
		AuthorityDomain:    "cluster-a/control-plane",
		AuthorityTerm:      9,
		DecisionEpoch:      41,
		RevocationEpoch:    3,
		TargetIdentity:     binding.TargetIdentity,
		StateBindingDigest: digest,
	}
}

func TestCapabilityFenceAcceptsMatchingAuthorityAndState(t *testing.T) {
	claims := testCapabilityClaims(t)
	current := CapabilityAuthoritySnapshot{
		AuthorityDomain: claims.AuthorityDomain,
		AuthorityTerm:   claims.AuthorityTerm,
		RevocationEpoch: claims.RevocationEpoch,
	}
	if err := ValidateCapabilityFence(claims, current, testCapabilityStateBinding()); err != nil {
		t.Fatalf("matching capability fence rejected: %v", err)
	}
}

func TestCapabilityFenceRejectsAuthorityTermChange(t *testing.T) {
	claims := testCapabilityClaims(t)
	current := CapabilityAuthoritySnapshot{
		AuthorityDomain: claims.AuthorityDomain,
		AuthorityTerm:   claims.AuthorityTerm + 1,
		RevocationEpoch: claims.RevocationEpoch,
	}
	if err := ValidateCapabilityFence(claims, current, testCapabilityStateBinding()); !errors.Is(err, ErrCapabilityAuthorityChanged) {
		t.Fatalf("expected authority change, got %v", err)
	}
}

func TestCapabilityFenceRejectsRevocationEpochChange(t *testing.T) {
	claims := testCapabilityClaims(t)
	current := CapabilityAuthoritySnapshot{
		AuthorityDomain: claims.AuthorityDomain,
		AuthorityTerm:   claims.AuthorityTerm,
		RevocationEpoch: claims.RevocationEpoch + 1,
	}
	if err := ValidateCapabilityFence(claims, current, testCapabilityStateBinding()); !errors.Is(err, ErrCapabilityRevoked) {
		t.Fatalf("expected revocation rejection, got %v", err)
	}
}

func TestCapabilityFenceRejectsTargetReplacementWithSameName(t *testing.T) {
	claims := testCapabilityClaims(t)
	current := CapabilityAuthoritySnapshot{
		AuthorityDomain: claims.AuthorityDomain,
		AuthorityTerm:   claims.AuthorityTerm,
		RevocationEpoch: claims.RevocationEpoch,
	}
	state := testCapabilityStateBinding()
	state.TargetIdentity = "replacement-uid"
	if err := ValidateCapabilityFence(claims, current, state); !errors.Is(err, ErrCapabilityTargetChanged) {
		t.Fatalf("expected target identity rejection, got %v", err)
	}
}

func TestCapabilityFenceRejectsStateBindingChange(t *testing.T) {
	claims := testCapabilityClaims(t)
	current := CapabilityAuthoritySnapshot{
		AuthorityDomain: claims.AuthorityDomain,
		AuthorityTerm:   claims.AuthorityTerm,
		RevocationEpoch: claims.RevocationEpoch,
	}
	state := testCapabilityStateBinding()
	state.ResourceVersion = "101"
	if err := ValidateCapabilityFence(claims, current, state); !errors.Is(err, ErrCapabilityStateChanged) {
		t.Fatalf("expected state change rejection, got %v", err)
	}
}
