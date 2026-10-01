package kubeadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/achirothmane/aegis-ege/governedaction"
	"github.com/achirothmane/aegis-ege/internal/decision"
)

// drainBoundaryDenial carries the native adapter disposition through the shared
// library. A preparation failure is not a rejected destination mutation.
type drainBoundaryDenial struct {
	decision decision.Decision
	reasons  []decision.ReasonCode
	cause    error
}

func (e *drainBoundaryDenial) Error() string {
	return fmt.Sprintf("drain boundary %s: %v: %v", e.decision, e.reasons, e.cause)
}

func (e *drainBoundaryDenial) Unwrap() error { return e.cause }

func drainAdmission(result decision.Decision, reasons []decision.ReasonCode, err error) error {
	if err != nil {
		return err
	}
	if result != decision.Allow {
		return &drainBoundaryDenial{decision: result, reasons: reasons}
	}
	return nil
}

func drainBoundaryDisposition(report *GuardedDrainExecutionReport, err error) bool {
	var denial *drainBoundaryDenial
	if !errors.As(err, &denial) {
		return false
	}
	report.Decision = denial.decision
	report.ReasonCodes = append([]decision.ReasonCode(nil), denial.reasons...)
	return true
}

// dispatchDrainMutation extracts only the checkpointed execution path. Native
// lease checks, node resourceVersion, Pod UID preconditions and recovery remain
// the adapter's responsibility. Legacy execution without a checkpoint keeps its
// existing semantics; it is not represented as durable-custody library use.
func (a *Adapter) dispatchDrainMutation(
	ctx context.Context,
	store DrainCheckpointStore,
	checkpoint *DrainExecutionCheckpoint,
	check func(context.Context) error,
	mutation func(context.Context) error,
) (bool, error) {
	if store == nil {
		return true, mutation(ctx)
	}
	if checkpoint == nil {
		return false, &drainBoundaryDenial{
			decision: decision.Escalate,
			reasons:  []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
		}
	}
	result, err := governedaction.Dispatch(ctx, check, func(ctx context.Context) error {
		// The original action/node/authorized Pod UID set remains recoverable.
		// This timestamp records custody retention, never destination acceptance.
		checkpoint.UpdatedAt = a.now().UTC()
		if err := saveDrainCheckpoint(ctx, store, checkpoint); err != nil {
			return &drainBoundaryDenial{
				decision: decision.Escalate,
				reasons:  []decision.ReasonCode{ReasonExecutionCheckpointUnavailable},
				cause:   err,
			}
		}
		return nil
	}, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, mutation(ctx)
	})
	return result.BoundaryEntered, err
}

func (a *Adapter) checkDrainLeaseAndTime(ctx context.Context, guard *executionLeaseGuard, auth decision.Authorization) error {
	if err := guard.EnsureHeld(ctx); err != nil {
		return &drainBoundaryDenial{
			decision: decision.Escalate,
			reasons:  []decision.ReasonCode{ReasonExecutionLockLost},
			cause:   err,
		}
	}
	// Check again after native reads/lease renewal; those calls can consume the
	// remaining authorization window. Target-side CAS still owns check-to-use.
	if err := governedaction.CheckValidity(auth.ValidUntil, a.now().UTC()); err != nil {
		return &drainBoundaryDenial{
			decision: decision.Escalate,
			reasons:  []decision.ReasonCode{decision.AuthorizationExpired},
			cause:   err,
		}
	}
	return nil
}
