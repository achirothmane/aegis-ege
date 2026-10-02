package primitivereduction

import "errors"

type RecoveryAction string

const (
	RecoveryStopUnknown    RecoveryAction = "STOP_UNKNOWN"
	RecoveryRetrySameEffect RecoveryAction = "RETRY_SAME_EFFECT"
	RecoveryCloseApplied    RecoveryAction = "CLOSE_APPLIED"
)

type ProviderObservationStatus string

const (
	ProviderApplied ProviderObservationStatus = "APPLIED"
	ProviderAbsent  ProviderObservationStatus = "ABSENT"
	ProviderUnknown ProviderObservationStatus = "UNKNOWN"
)

// ProviderContract is a derived, evidence-bound description of destination
// semantics relevant to recovery. It is not a primitive and it does not grant
// authority by itself.
type ProviderContract struct {
	ProviderID               string
	SupportsAtomicDedup       bool
	SupportsFinalObservation bool
	IdempotencyKey            string
	Evidence                  Evidence
}

type ProviderObservation struct {
	EffectID string
	Status   ProviderObservationStatus
	Evidence Evidence
}

func validUnknownCustody(custody StateRef) bool {
	return custody.Complete() &&
		custody.Namespace == custodyNamespace &&
		custody.Digest == custodyDigest(custody) &&
		custody.Facts[factCustodyPhase] == CustodyUnknown
}

func validateProviderContract(p Proposal, custody StateRef, contract ProviderContract) (string, error) {
	if !validUnknownCustody(custody) {
		return "", errors.New("recovery requires valid UNKNOWN effect custody")
	}
	effectID, err := EffectIdentity(p)
	if err != nil {
		return "", err
	}
	if contract.ProviderID == "" ||
		!contract.Evidence.Complete() ||
		!contract.Evidence.Valid ||
		contract.Evidence.StateDigest != custody.Digest {
		return "", errors.New("provider contract is incomplete, invalid, or stale")
	}
	if contract.SupportsAtomicDedup && contract.IdempotencyKey != effectID {
		return "", errors.New("atomic dedup contract is not bound to the exact logical effect identity")
	}
	return effectID, nil
}

func validProviderObservation(
	effectID string,
	custody StateRef,
	contract ProviderContract,
	observation ProviderObservation,
) bool {
	if !contract.SupportsFinalObservation {
		return false
	}
	if observation.EffectID != effectID ||
		observation.Status == "" ||
		!observation.Evidence.Complete() ||
		!observation.Evidence.Valid ||
		observation.Evidence.StateDigest != custody.Digest {
		return false
	}
	switch observation.Status {
	case ProviderApplied, ProviderAbsent, ProviderUnknown:
		return true
	default:
		return false
	}
}

// EvaluateUnknownRecovery defines the strongest automatic action justified by
// destination cooperation after an ambiguous non-idempotent effect.
//
// Important impossibility boundary:
//
//   - exact final APPLIED evidence permits truthful closure;
//   - exact final ABSENT evidence permits replay of the same logical effect;
//   - atomic destination dedup permits retry with the exact same effect identity;
//   - otherwise UNKNOWN remains STOP_UNKNOWN.
//
// The kernel never converts missing observability into replay permission.
func EvaluateUnknownRecovery(
	p Proposal,
	custody StateRef,
	contract ProviderContract,
	observation *ProviderObservation,
) RecoveryAction {
	effectID, err := validateProviderContract(p, custody, contract)
	if err != nil {
		return RecoveryStopUnknown
	}

	if observation != nil && validProviderObservation(effectID, custody, contract, *observation) {
		switch observation.Status {
		case ProviderApplied:
			return RecoveryCloseApplied
		case ProviderAbsent:
			return RecoveryRetrySameEffect
		case ProviderUnknown:
			// fall through to dedup semantics
		}
	}

	if contract.SupportsAtomicDedup && contract.IdempotencyKey == effectID {
		return RecoveryRetrySameEffect
	}

	return RecoveryStopUnknown
}

// ApplyRecoveryObservation converts a justified final APPLIED observation into
// a CLOSED custody Transition. ABSENT does not close the custody; it only
// justifies retrying the same logical effect.
func ApplyRecoveryObservation(
	p Proposal,
	custody StateRef,
	contract ProviderContract,
	observation ProviderObservation,
) (Transition, error) {
	if EvaluateUnknownRecovery(p, custody, contract, &observation) != RecoveryCloseApplied {
		return Transition{}, errors.New("provider observation does not justify truthful closure")
	}
	return AdvanceEffectCustody(custody, CustodyClosed)
}
