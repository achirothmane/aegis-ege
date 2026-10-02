package governedaction

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMissingCredentialBinding = errors.New("credential use binding is incomplete")
	ErrCredentialBindingChanged = errors.New("credential use binding changed")
)

// CredentialUseBinding is an experimental effect-boundary relation for an
// opaque credential handle. Raw credential material is intentionally absent.
//
// The binding answers:
//   - which opaque handle may be used,
//   - for which exact action/effect,
//   - against which destination and credential audience,
//   - under which scope/trust epoch,
//   - until when.
//
// It does not resolve the handle or return a secret. Resolution/injection belongs
// in a broker outside the untrusted actor runtime.
type CredentialUseBinding struct {
	HandleID       string
	ActionRevision string
	EffectID       string
	Audience       string
	Destination    string
	Scope          string
	TrustEpoch     string
	ValidUntil     time.Time
}

type CredentialUseField string

const (
	CredentialHandleField      CredentialUseField = "handle_id"
	CredentialActionField      CredentialUseField = "action_revision"
	CredentialEffectField      CredentialUseField = "effect_id"
	CredentialAudienceField    CredentialUseField = "audience"
	CredentialDestinationField CredentialUseField = "destination"
	CredentialScopeField       CredentialUseField = "scope"
	CredentialTrustEpochField  CredentialUseField = "trust_epoch"
	CredentialExpiryField      CredentialUseField = "valid_until"
)

type CredentialUseError struct {
	Field CredentialUseField
	Cause error
}

func (e *CredentialUseError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Cause) }
func (e *CredentialUseError) Unwrap() error { return e.Cause }

// CheckCredentialUse rejects a surrogate/opaque handle when any material
// boundary binding changed. An effect identifier change is therefore a replay
// outside the admitted effect, even when the same handle string is presented.
//
// Destination and Audience are distinct on purpose. A connector can target the
// same network endpoint while requesting a credential minted for a different
// logical audience; that must not inherit authority silently.
//
// ValidUntil is exclusive and uses the trusted adapter/broker clock.
func CheckCredentialUse(admitted, current CredentialUseBinding, at time.Time) error {
	fields := []struct {
		name              CredentialUseField
		admitted, current string
	}{
		{CredentialHandleField, admitted.HandleID, current.HandleID},
		{CredentialActionField, admitted.ActionRevision, current.ActionRevision},
		{CredentialEffectField, admitted.EffectID, current.EffectID},
		{CredentialAudienceField, admitted.Audience, current.Audience},
		{CredentialDestinationField, admitted.Destination, current.Destination},
		{CredentialScopeField, admitted.Scope, current.Scope},
		{CredentialTrustEpochField, admitted.TrustEpoch, current.TrustEpoch},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.admitted) == "" || strings.TrimSpace(field.current) == "" {
			return &CredentialUseError{Field: field.name, Cause: ErrMissingCredentialBinding}
		}
		if field.admitted != field.current {
			return &CredentialUseError{Field: field.name, Cause: ErrCredentialBindingChanged}
		}
	}

	if admitted.ValidUntil.IsZero() || current.ValidUntil.IsZero() {
		return &CredentialUseError{Field: CredentialExpiryField, Cause: ErrMissingCredentialBinding}
	}
	if !admitted.ValidUntil.Equal(current.ValidUntil) {
		return &CredentialUseError{Field: CredentialExpiryField, Cause: ErrCredentialBindingChanged}
	}
	if err := CheckValidity(admitted.ValidUntil, at); err != nil {
		return &CredentialUseError{Field: CredentialExpiryField, Cause: err}
	}
	return nil
}
