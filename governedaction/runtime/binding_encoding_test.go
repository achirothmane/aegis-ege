package runtime_test

import (
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

func TestOpaqueFieldBoundariesRemainDistinct(t *testing.T) {
	a := defaultRequest(t)
	b := a
	a.Subject = gaRuntime.Identity{ID: "agent\x00worker", Kind: "service"}
	b.Subject = gaRuntime.Identity{ID: "agent", Kind: "worker\x00service"}
	aEffect, err := gaRuntime.EffectIdentity(a)
	if err != nil {
		t.Fatal(err)
	}
	bEffect, err := gaRuntime.EffectIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if aEffect == bEffect {
		t.Fatal("distinct subject fields share an effect binding")
	}
	aAdmission, err := gaRuntime.AdmissionBindingDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	bAdmission, err := gaRuntime.AdmissionBindingDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if aAdmission == bAdmission {
		t.Fatal("distinct subject fields share an admission binding")
	}
	aState := gaRuntime.State{Target: "target\x00revision", Revision: "v1", Digest: "digest"}
	bState := gaRuntime.State{Target: "target", Revision: "revision\x00v1", Digest: "digest"}
	if gaRuntime.ObservationBindingDigest(aEffect, aState) == gaRuntime.ObservationBindingDigest(aEffect, bState) {
		t.Fatal("distinct observed state fields share an observation binding")
	}
}

func TestBindingEncodingPreservesExactOpaqueBytes(t *testing.T) {
	a := gaRuntime.State{Target: "target", Revision: "revision", Digest: "\xff"}
	b := a
	b.Digest = "\xfe"
	if gaRuntime.ObservationBindingDigest("effect", a) == gaRuntime.ObservationBindingDigest("effect", b) {
		t.Fatal("distinct opaque bytes share a binding")
	}
	if gaRuntime.ObservationBindingDigest("effect", a) != gaRuntime.ObservationBindingDigest("effect", a) {
		t.Fatal("binding is not deterministic")
	}
}
