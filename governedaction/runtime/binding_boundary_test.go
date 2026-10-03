package runtime_test

import (
	"context"
	"errors"
	"testing"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

type boundObservationAdapter struct {
	*fakeAdapter
	observationEffect string
}

func (a *boundObservationAdapter) Observe(ctx context.Context, transition gaRuntime.Transition, custody gaRuntime.Custody) (gaRuntime.Observation, error) {
	observation, err := a.fakeAdapter.Observe(ctx, transition, custody)
	observation.Attestation.BindingDigest = gaRuntime.ObservationBindingDigest(a.observationEffect, observation.State)
	return observation, err
}

func TestExactBindingAtAdmissionAndClosureBoundaries(t *testing.T) {
	for _, domain := range []string{"github", "kubernetes", "postgresql", "terraform"} {
		t.Run(domain, func(t *testing.T) {
			a := requestFor(t, domain+":target", "before:1", "digest:before", "mutate", "after:2", "digest:after")
			a.Subject = gaRuntime.Identity{ID: "agent\x00worker", Kind: "service"}
			binding, err := gaRuntime.AdmissionBindingDigest(a)
			if err != nil {
				t.Fatal(err)
			}
			a.Admission.BindingDigest = binding
			b := a
			b.Subject = gaRuntime.Identity{ID: "agent", Kind: "worker\x00service"}

			t.Run("foreign_admission_has_no_effect", func(t *testing.T) {
				adapter := newAdapter(b.Current, b.Transition.To)
				result := gaRuntime.Run(context.Background(), b, adapter)
				if result.Disposition != gaRuntime.DispositionRejected || !errors.Is(result.Cause, gaRuntime.ErrAdmissionBinding) {
					t.Fatalf("foreign admission must be rejected: %+v", result)
				}
				if result.CustodyRecorded || result.BoundaryEntered || adapter.retainCalls != 0 || adapter.effectCalls != 0 || adapter.observeCalls != 0 {
					t.Fatal("foreign admission reached custody, execution, or observation")
				}
			})

			bBinding, err := gaRuntime.AdmissionBindingDigest(b)
			if err != nil {
				t.Fatal(err)
			}
			b.Admission.BindingDigest = bBinding
			aEffect, err := gaRuntime.EffectIdentity(a)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("foreign_observation_cannot_close", func(t *testing.T) {
				adapter := &boundObservationAdapter{fakeAdapter: newAdapter(b.Current, b.Transition.To), observationEffect: aEffect}
				result := gaRuntime.Run(context.Background(), b, adapter)
				if result.Disposition != gaRuntime.DispositionUnknown || !errors.Is(result.Cause, gaRuntime.ErrObservationBinding) {
					t.Fatalf("foreign observation must leave UNKNOWN: %+v", result)
				}
				if !result.CustodyRecorded || !result.BoundaryEntered || adapter.effectCalls != 1 || adapter.observeCalls != 1 {
					t.Fatal("expected one admitted effect and one observation, without retry")
				}
			})

			t.Run("exact_bindings_remain_useful", func(t *testing.T) {
				for _, req := range []gaRuntime.Request{a, b} {
					adapter := newAdapter(req.Current, req.Transition.To)
					result := gaRuntime.Run(context.Background(), req, adapter)
					if result.Disposition != gaRuntime.DispositionClosed || adapter.effectCalls != 1 {
						t.Fatalf("exact binding must close after one effect: %+v", result)
					}
				}
			})
		})
	}
}
