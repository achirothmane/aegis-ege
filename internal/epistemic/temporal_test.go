package epistemic

import (
	"testing"
	"time"
)

func TestSensitivityAwareValidityRejectsCriticalEvidenceBaselineAccepts(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	now := evaluatedAt.Add(20 * time.Second)
	assumption := Assumption{
		ID:          "A-HEALTH",
		Status:      AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
	policy := TemporalPolicy{
		LowMaxAge:      60 * time.Second,
		MediumMaxAge:   30 * time.Second,
		HighMaxAge:     10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}

	baseline := AssessFixedTTL(assumption, now, 60*time.Second)
	if !baseline.Valid {
		t.Fatalf("fixed TTL baseline should accept 20s-old evidence under 60s TTL, got %+v", baseline)
	}

	critical := AssessTemporalValidity(assumption, now, SensitivityCritical, policy)
	if critical.Validity != ValidityExpired {
		t.Fatalf("critical action should reject 20s-old evidence, got %+v", critical)
	}
	if critical.MaxAge != 5*time.Second || critical.Reason != TemporalReasonAgeExceeded {
		t.Fatalf("unexpected critical assessment: %+v", critical)
	}

	low := AssessTemporalValidity(assumption, now, SensitivityLow, policy)
	if low.Validity != ValidityValid {
		t.Fatalf("low-sensitivity action should still accept same evidence, got %+v", low)
	}
}

func TestEventInvalidationDominatesFreshTemporalWindow(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	tracker := NewTracker()
	resource := ResourceRef{
		APIVersion: "v1",
		Kind: "Service",
		Namespace: "production",
		Name: "api",
		UID: "svc-1",
		ResourceVersion: "10",
	}
	tracker.PutAssumption(Assumption{
		ID: "A-ROUTING",
		Status: AssumptionSupported,
		Dependencies: []ResourceRef{resource},
		EvaluatedAt: evaluatedAt,
	})

	tracker.Handle(ResourceEvent{
		Type: "MODIFIED",
		Resource: ResourceRef{
			APIVersion: resource.APIVersion,
			Kind: resource.Kind,
			Namespace: resource.Namespace,
			Name: resource.Name,
			UID: resource.UID,
			ResourceVersion: "11",
		},
		At: evaluatedAt.Add(time.Millisecond),
	})

	assumption, _ := tracker.GetAssumption("A-ROUTING")
	policy := TemporalPolicy{CriticalMaxAge: 5 * time.Second}
	got := AssessTemporalValidity(
		assumption,
		evaluatedAt.Add(2*time.Millisecond),
		SensitivityCritical,
		policy,
	)

	if got.Validity != ValidityInvalidated {
		t.Fatalf("event invalidation must dominate fresh age window, got %+v", got)
	}
	if got.Reason != TemporalReasonEventInvalidated {
		t.Fatalf("expected event invalidation reason, got %+v", got)
	}
}

func TestTemporalValidityUsesExplicitSensitivityWindows(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	now := evaluatedAt.Add(12 * time.Second)
	assumption := Assumption{
		ID: "A",
		Status: AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
	policy := TemporalPolicy{
		LowMaxAge: 60 * time.Second,
		MediumMaxAge: 30 * time.Second,
		HighMaxAge: 10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}

	cases := []struct {
		sensitivity ActionSensitivity
		want TemporalValidity
	}{
		{SensitivityLow, ValidityValid},
		{SensitivityMedium, ValidityValid},
		{SensitivityHigh, ValidityExpired},
		{SensitivityCritical, ValidityExpired},
	}

	for _, tc := range cases {
		t.Run(string(tc.sensitivity), func(t *testing.T) {
			got := AssessTemporalValidity(assumption, now, tc.sensitivity, policy)
			if got.Validity != tc.want {
				t.Fatalf("expected %s, got %+v", tc.want, got)
			}
		})
	}
}

func TestTemporalValidityFailsUnknownOnClockSkew(t *testing.T) {
	evaluatedAt := time.Date(2026, 9, 23, 18, 0, 10, 0, time.UTC)
	assumption := Assumption{
		ID: "A",
		Status: AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
	got := AssessTemporalValidity(
		assumption,
		evaluatedAt.Add(-time.Second),
		SensitivityHigh,
		TemporalPolicy{HighMaxAge: 10 * time.Second},
	)
	if got.Validity != ValidityUnknown || got.Reason != TemporalReasonClockSkew {
		t.Fatalf("clock skew must fail unknown, got %+v", got)
	}
}

func TestTemporalValidityFailsUnknownWithoutPolicy(t *testing.T) {
	now := time.Now().UTC()
	assumption := Assumption{
		ID: "A",
		Status: AssumptionSupported,
		EvaluatedAt: now,
	}
	got := AssessTemporalValidity(assumption, now, SensitivityCritical, TemporalPolicy{})
	if got.Validity != ValidityUnknown || got.Reason != TemporalReasonUndefinedPolicy {
		t.Fatalf("undefined temporal window must fail unknown, got %+v", got)
	}
}
