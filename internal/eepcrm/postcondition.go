package eepcrm

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/journal"
)

const PostconditionProfileVersion = "aegis.eep/crm-postcondition/v1"

type PostconditionResult string

const (
	PostconditionVerified   PostconditionResult = "VERIFIED"
	PostconditionPartial    PostconditionResult = "PARTIAL"
	PostconditionUnsatisfied PostconditionResult = "UNSATISFIED"
	PostconditionUnknown    PostconditionResult = "UNKNOWN"
	PostconditionAlreadySatisfied PostconditionResult = "ALREADY_SATISFIED"
)

type RequestAcceptance string

const (
	RequestNotDispatched RequestAcceptance = "NOT_DISPATCHED"
	RequestAccepted      RequestAcceptance = "ACCEPTED"
	RequestAcceptanceUnknown RequestAcceptance = "UNKNOWN"
)

type ObservationStatus string

const (
	ObservationPreMutation   ObservationStatus = "PRE_MUTATION"
	ObservationStable        ObservationStatus = "OBSERVED_STABLE"
	ObservationUnavailable   ObservationStatus = "UNAVAILABLE"
	ObservationContradictory ObservationStatus = "CONTRADICTORY"
)

type FieldPostcondition struct {
	Path           string `json:"path"`
	ExpectedDigest string `json:"expected_digest"`
	ObservedDigest string `json:"observed_digest,omitempty"`
	Present        bool   `json:"present"`
	Satisfied      bool   `json:"satisfied"`
}

type PostconditionEvaluation struct {
	ProfileVersion string               `json:"profile_version"`
	Result         PostconditionResult  `json:"result"`
	MatchedFields  int                  `json:"matched_fields"`
	TotalFields    int                  `json:"total_fields"`
	Fields         []FieldPostcondition `json:"fields"`
}

func EvaluateCustomerUpdatePostcondition(
	plan CustomerUpdatePlan,
	state map[string]any,
) (PostconditionEvaluation, error) {
	if strings.TrimSpace(plan.CustomerID) == "" {
		return PostconditionEvaluation{}, errors.New("customer_id is required")
	}
	if len(plan.Patch) == 0 {
		return PostconditionEvaluation{}, errors.New("customer patch is required")
	}
	if state == nil {
		return PostconditionEvaluation{}, errors.New("customer observation is required")
	}

	keys := make([]string, 0, len(plan.Patch))
	for key := range plan.Patch {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	evaluation := PostconditionEvaluation{
		ProfileVersion: PostconditionProfileVersion,
		TotalFields:    len(keys),
		Fields:         make([]FieldPostcondition, 0, len(keys)),
	}
	for _, key := range keys {
		expected := plan.Patch[key]
		expectedBytes, err := canonicalComparableValue(expected)
		if err != nil {
			return PostconditionEvaluation{}, fmt.Errorf("canonicalize expected field %q: %w", key, err)
		}
		expectedDigest, err := journal.DigestPayload(map[string]any{"value": expected})
		if err != nil {
			return PostconditionEvaluation{}, err
		}
		field := FieldPostcondition{
			Path:           "/" + escapeJSONPointerToken(key),
			ExpectedDigest: expectedDigest,
		}
		observed, present := state[key]
		field.Present = present
		if present {
			observedBytes, err := canonicalComparableValue(observed)
			if err != nil {
				return PostconditionEvaluation{}, fmt.Errorf("canonicalize observed field %q: %w", key, err)
			}
			field.ObservedDigest, err = journal.DigestPayload(map[string]any{"value": observed})
			if err != nil {
				return PostconditionEvaluation{}, err
			}
			field.Satisfied = bytes.Equal(expectedBytes, observedBytes)
		}
		if field.Satisfied {
			evaluation.MatchedFields++
		}
		evaluation.Fields = append(evaluation.Fields, field)
	}

	switch {
	case evaluation.MatchedFields == evaluation.TotalFields:
		evaluation.Result = PostconditionVerified
	case evaluation.MatchedFields == 0:
		evaluation.Result = PostconditionUnsatisfied
	default:
		evaluation.Result = PostconditionPartial
	}
	return evaluation, nil
}

func EquivalentPostconditionObservation(a, b PostconditionEvaluation) bool {
	if a.ProfileVersion != b.ProfileVersion ||
		a.MatchedFields != b.MatchedFields ||
		a.TotalFields != b.TotalFields ||
		len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i] != b.Fields[i] {
			return false
		}
	}
	return true
}

func ValidatePostconditionEvaluation(evaluation PostconditionEvaluation) error {
	if evaluation.ProfileVersion != PostconditionProfileVersion {
		return fmt.Errorf("unsupported postcondition profile %q", evaluation.ProfileVersion)
	}
	if evaluation.TotalFields <= 0 || len(evaluation.Fields) != evaluation.TotalFields {
		return errors.New("postcondition field cardinality invalid")
	}
	matched := 0
	previousPath := ""
	for _, field := range evaluation.Fields {
		if field.Path == "" || field.ExpectedDigest == "" {
			return errors.New("postcondition field identity/digest missing")
		}
		if previousPath != "" && field.Path <= previousPath {
			return errors.New("postcondition fields must be uniquely sorted")
		}
		previousPath = field.Path
		if field.Satisfied {
			if !field.Present || field.ObservedDigest == "" ||
				field.ObservedDigest != field.ExpectedDigest {
				return errors.New("satisfied field lacks matching observed evidence")
			}
			matched++
		}
	}
	if matched != evaluation.MatchedFields {
		return errors.New("postcondition matched field count invalid")
	}
	switch evaluation.Result {
	case PostconditionVerified:
		if matched != evaluation.TotalFields {
			return errors.New("VERIFIED requires every intended field")
		}
	case PostconditionPartial:
		if matched <= 0 || matched >= evaluation.TotalFields {
			return errors.New("PARTIAL requires some but not all intended fields")
		}
	case PostconditionUnsatisfied:
		if matched != 0 {
			return errors.New("UNSATISFIED requires zero intended fields")
		}
	case PostconditionUnknown:
		return errors.New("UNKNOWN is an outcome disposition, not a state evaluation")
	default:
		return fmt.Errorf("unsupported postcondition result %q", evaluation.Result)
	}
	return nil
}

func canonicalComparableValue(value any) ([]byte, error) {
	// The current CRM patch profile defines equality by JSON value semantics
	// after the same encoding used on the HTTP boundary. This preserves object
	// key-order irrelevance without introducing type coercion beyond JSON.
	return jsonMarshalValue(value)
}

func jsonMarshalValue(value any) ([]byte, error) {
	return json.Marshal(value)
}

func escapeJSONPointerToken(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}
