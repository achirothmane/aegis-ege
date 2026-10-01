// Package governedaction implements small executable relations from the frozen
// governed-action v1 contract. Adapters own trusted profiles, native revisions,
// current evidence, destination enforcement, custody storage and typed outcomes.
// This package neither issues authority nor establishes complete mediation.
package governedaction

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMissingBinding = errors.New("governed action binding is incomplete")
	ErrBindingChanged = errors.New("governed action binding changed")
	ErrUnknownTime = errors.New("boundary time is unknown")
	ErrMissingExpiry = errors.New("authority has no finite expiry")
	ErrExpired = errors.New("authority expired at the effect boundary")
	ErrMissingCheck = errors.New("effect boundary check is required")
	ErrMissingCustody = errors.New("durable custody recorder is required")
	ErrMissingEffect = errors.New("effect callback is required")
)

// Binding contains opaque, exact native references. The adapter must produce
// them from its trusted profile; caller-selected labels are not evidence. Target
// must include the native destination/account scope. ActionRevision must cover
// all consequential payload and plan semantics. No canonicalizer is imposed.
type Binding struct {
	ActionRevision string
	Target string
	Profile string
}

type BindingField string

const (
	ActionRevisionField BindingField = "action_revision"
	TargetField BindingField = "target"
	ProfileField BindingField = "profile"
)

type BindingError struct {
	Field BindingField
	Cause error
}

func (e *BindingError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Cause) }
func (e *BindingError) Unwrap() error { return e.Cause }

// CheckBinding refuses missing references even when both sides are empty.
// It compares exact native references without normalizing or resolving aliases.
func CheckBinding(admitted, current Binding) error {
	fields := []struct {
		name BindingField
		admitted, current string
	}{
		{ActionRevisionField, admitted.ActionRevision, current.ActionRevision},
		{TargetField, admitted.Target, current.Target},
		{ProfileField, admitted.Profile, current.Profile},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.admitted) == "" || strings.TrimSpace(field.current) == "" {
			return &BindingError{Field: field.name, Cause: ErrMissingBinding}
		}
		if field.admitted != field.current {
			return &BindingError{Field: field.name, Cause: ErrBindingChanged}
		}
	}
	return nil
}

// CheckValidity uses the adapter's boundary clock, not a clock owned by the
// library. Expiry is exclusive. A missing clock or expiry cannot grant authority.
// This checks boundary entry, not the time a remote effect becomes durable.
func CheckValidity(until, at time.Time) error {
	if at.IsZero() {
		return ErrUnknownTime
	}
	if until.IsZero() {
		return ErrMissingExpiry
	}
	if !at.Before(until) {
		return ErrExpired
	}
	return nil
}

// Preparation reports only in-process callback facts. CustodyRecorded means the
// adapter acknowledged its durable write. It is not a portable authorization or
// a receipt proving dispatch, destination acceptance or intended postconditions.
type Preparation struct {
	CustodyRecorded bool
}

// PrepareEffect checks current admission, records native recoverable custody,
// then checks admission again. The second check prevents a slow custody write
// from carrying expired or invalidated authority across the effect boundary.
// Retain must durably preserve the same EffectIdentity/ExecutionAttempt and
// accountable owner under the adapter's declared failure/retention model.
// Check must establish current witnesses and native enforcement assumptions,
// not just signature validity. Neither callback may itself dispatch the effect.
// Native transactions/CAS/fencing must close any check-to-use race at the target.
func PrepareEffect(ctx context.Context, check, retain func(context.Context) error) (Preparation, error) {
	result := Preparation{}
	if check == nil {
		return result, ErrMissingCheck
	}
	if retain == nil {
		return result, ErrMissingCustody
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := check(ctx); err != nil {
		return result, fmt.Errorf("before custody: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := retain(ctx); err != nil {
		return result, fmt.Errorf("retain custody: %w", err)
	}
	result.CustodyRecorded = true
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := check(ctx); err != nil {
		return result, fmt.Errorf("after custody: %w", err)
	}
	return result, ctx.Err()
}

// DispatchResult retains local call facts separately from native result values.
// BoundaryEntered is conservative: the effect callback was invoked. An error
// after entry does not establish no-effect and never authorizes a blind retry.
type DispatchResult[T any] struct {
	Preparation
	BoundaryEntered bool
	Value T
}

// Dispatch performs one callback invocation after PrepareEffect. It does not
// retry, deduplicate, transfer custody, grant recovery mutation authority, or
// classify the domain outcome. Adapters enforce cardinality in durable native
// storage; invoking Dispatch again is not proof that another effect is safe.
func Dispatch[T any](ctx context.Context, check, retain func(context.Context) error, effect func(context.Context) (T, error)) (DispatchResult[T], error) {
	result := DispatchResult[T]{}
	if effect == nil {
		return result, ErrMissingEffect
	}
	prepared, err := PrepareEffect(ctx, check, retain)
	result.Preparation = prepared
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.BoundaryEntered = true
	result.Value, err = effect(ctx)
	return result, err
}
