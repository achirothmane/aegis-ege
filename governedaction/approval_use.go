package governedaction

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMissingApprovalBinding = errors.New("approval use binding is incomplete")
	ErrApprovalBindingChanged = errors.New("approval use binding changed")
	ErrApprovalEffectLimit    = errors.New("approval effect limit is invalid")
	ErrApprovalExhausted      = errors.New("approval effect limit exhausted")
)

// ApprovalUseBinding is an experimental execution-boundary relation for using
// an already authenticated approval.
//
// ApprovalRef should identify an independently authenticated approval artifact
// (for example the digest of a signed ApprovalAttestation). This package does
// not authenticate the approver or signature. ActionRevision, EffectID and
// Target bind the approval to the exact effect interpretation at the boundary.
//
// Nonce is an opaque approval-use identity. It is not sufficient by itself to
// prevent replay: adapters must retain use accounting durably under their
// declared failure model and use native CAS/fencing/transactions when concurrent
// consumers could race.
//
// MaxEffects is the maximum number of effects this approval may authorize.
// ValidUntil is exclusive, as with CheckValidity.
type ApprovalUseBinding struct {
	ApprovalRef    string
	ActionRevision string
	EffectID       string
	Target         string
	Scope          string
	Nonce          string
	MaxEffects     uint32
	ValidUntil     time.Time
}

type ApprovalUseField string

const (
	ApprovalRefField    ApprovalUseField = "approval_ref"
	ApprovalActionField ApprovalUseField = "action_revision"
	ApprovalEffectField ApprovalUseField = "effect_id"
	ApprovalTargetField ApprovalUseField = "target"
	ApprovalScopeField  ApprovalUseField = "scope"
	ApprovalNonceField  ApprovalUseField = "nonce"
	ApprovalLimitField  ApprovalUseField = "max_effects"
	ApprovalExpiryField ApprovalUseField = "valid_until"
)

type ApprovalUseError struct {
	Field ApprovalUseField
	Cause error
}

func (e *ApprovalUseError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Cause) }
func (e *ApprovalUseError) Unwrap() error { return e.Cause }

// CheckApprovalUse enforces exact approval scope and bounded replay.
//
// effectsUsed is the number of effects already durably charged to this approval
// use identity. The caller is responsible for reading/updating that value from a
// trusted durable store and for making the read/charge/effect sequence safe
// against concurrent races with native transactions/CAS/fencing.
//
// A one-time approval therefore has MaxEffects=1. If effectsUsed is already 1,
// another effect is rejected even if every other field still matches.
func CheckApprovalUse(admitted, current ApprovalUseBinding, at time.Time, effectsUsed uint32) error {
	fields := []struct {
		name              ApprovalUseField
		admitted, current string
	}{
		{ApprovalRefField, admitted.ApprovalRef, current.ApprovalRef},
		{ApprovalActionField, admitted.ActionRevision, current.ActionRevision},
		{ApprovalEffectField, admitted.EffectID, current.EffectID},
		{ApprovalTargetField, admitted.Target, current.Target},
		{ApprovalScopeField, admitted.Scope, current.Scope},
		{ApprovalNonceField, admitted.Nonce, current.Nonce},
	}

	for _, field := range fields {
		if strings.TrimSpace(field.admitted) == "" || strings.TrimSpace(field.current) == "" {
			return &ApprovalUseError{Field: field.name, Cause: ErrMissingApprovalBinding}
		}
		if field.admitted != field.current {
			return &ApprovalUseError{Field: field.name, Cause: ErrApprovalBindingChanged}
		}
	}

	if admitted.MaxEffects == 0 || current.MaxEffects == 0 {
		return &ApprovalUseError{Field: ApprovalLimitField, Cause: ErrApprovalEffectLimit}
	}
	if admitted.MaxEffects != current.MaxEffects {
		return &ApprovalUseError{Field: ApprovalLimitField, Cause: ErrApprovalBindingChanged}
	}
	if admitted.ValidUntil.IsZero() || current.ValidUntil.IsZero() {
		return &ApprovalUseError{Field: ApprovalExpiryField, Cause: ErrMissingApprovalBinding}
	}
	if !admitted.ValidUntil.Equal(current.ValidUntil) {
		return &ApprovalUseError{Field: ApprovalExpiryField, Cause: ErrApprovalBindingChanged}
	}
	if err := CheckValidity(admitted.ValidUntil, at); err != nil {
		return &ApprovalUseError{Field: ApprovalExpiryField, Cause: err}
	}
	if effectsUsed >= admitted.MaxEffects {
		return &ApprovalUseError{Field: ApprovalLimitField, Cause: ErrApprovalExhausted}
	}
	return nil
}
