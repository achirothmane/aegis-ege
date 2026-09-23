package epistemic

import "time"

type ActionSensitivity string

const (
	SensitivityLow      ActionSensitivity = "LOW"
	SensitivityMedium   ActionSensitivity = "MEDIUM"
	SensitivityHigh     ActionSensitivity = "HIGH"
	SensitivityCritical ActionSensitivity = "CRITICAL"
)

type TemporalValidity string

const (
	ValidityValid       TemporalValidity = "VALID"
	ValidityExpired     TemporalValidity = "EXPIRED"
	ValidityInvalidated TemporalValidity = "INVALIDATED"
	ValidityUnknown     TemporalValidity = "UNKNOWN"
)

const (
	TemporalReasonWithinWindow       = "WITHIN_VALIDITY_WINDOW"
	TemporalReasonAgeExceeded        = "ASSUMPTION_AGE_EXCEEDED"
	TemporalReasonEventInvalidated   = "EVENT_INVALIDATED"
	TemporalReasonMissingTimestamp   = "MISSING_EVALUATED_AT"
	TemporalReasonClockSkew          = "CLOCK_SKEW"
	TemporalReasonUndefinedPolicy    = "UNDEFINED_TEMPORAL_POLICY"
)

type TemporalPolicy struct {
	LowMaxAge      time.Duration
	MediumMaxAge   time.Duration
	HighMaxAge     time.Duration
	CriticalMaxAge time.Duration
}

func (p TemporalPolicy) MaxAgeFor(sensitivity ActionSensitivity) time.Duration {
	switch sensitivity {
	case SensitivityLow:
		return p.LowMaxAge
	case SensitivityMedium:
		return p.MediumMaxAge
	case SensitivityHigh:
		return p.HighMaxAge
	case SensitivityCritical:
		return p.CriticalMaxAge
	default:
		return 0
	}
}

type TemporalAssessment struct {
	Validity    TemporalValidity
	Reason      string
	Sensitivity ActionSensitivity
	Age         time.Duration
	MaxAge      time.Duration
	Assumption  string
}

func AssessTemporalValidity(
	assumption Assumption,
	now time.Time,
	sensitivity ActionSensitivity,
	policy TemporalPolicy,
) TemporalAssessment {
	assessment := TemporalAssessment{
		Sensitivity: sensitivity,
		Assumption:  assumption.ID,
	}

	if assumption.Status == AssumptionInvalidated {
		assessment.Validity = ValidityInvalidated
		assessment.Reason = TemporalReasonEventInvalidated
		return assessment
	}

	if assumption.EvaluatedAt.IsZero() {
		assessment.Validity = ValidityUnknown
		assessment.Reason = TemporalReasonMissingTimestamp
		return assessment
	}

	maxAge := policy.MaxAgeFor(sensitivity)
	assessment.MaxAge = maxAge
	if maxAge <= 0 {
		assessment.Validity = ValidityUnknown
		assessment.Reason = TemporalReasonUndefinedPolicy
		return assessment
	}

	age := now.UTC().Sub(assumption.EvaluatedAt.UTC())
	assessment.Age = age
	if age < 0 {
		assessment.Validity = ValidityUnknown
		assessment.Reason = TemporalReasonClockSkew
		return assessment
	}

	if age > maxAge {
		assessment.Validity = ValidityExpired
		assessment.Reason = TemporalReasonAgeExceeded
		return assessment
	}

	assessment.Validity = ValidityValid
	assessment.Reason = TemporalReasonWithinWindow
	return assessment
}

type FixedTTLAssessment struct {
	Valid  bool
	Age    time.Duration
	MaxAge time.Duration
	Reason string
}

func AssessFixedTTL(assumption Assumption, now time.Time, maxAge time.Duration) FixedTTLAssessment {
	if assumption.Status == AssumptionInvalidated {
		return FixedTTLAssessment{
			Valid:  false,
			MaxAge: maxAge,
			Reason: TemporalReasonEventInvalidated,
		}
	}
	if assumption.EvaluatedAt.IsZero() || maxAge <= 0 {
		return FixedTTLAssessment{
			Valid:  false,
			MaxAge: maxAge,
			Reason: TemporalReasonUndefinedPolicy,
		}
	}

	age := now.UTC().Sub(assumption.EvaluatedAt.UTC())
	if age < 0 {
		return FixedTTLAssessment{
			Valid:  false,
			Age:    age,
			MaxAge: maxAge,
			Reason: TemporalReasonClockSkew,
		}
	}
	if age > maxAge {
		return FixedTTLAssessment{
			Valid:  false,
			Age:    age,
			MaxAge: maxAge,
			Reason: TemporalReasonAgeExceeded,
		}
	}
	return FixedTTLAssessment{
		Valid:  true,
		Age:    age,
		MaxAge: maxAge,
		Reason: TemporalReasonWithinWindow,
	}
}
