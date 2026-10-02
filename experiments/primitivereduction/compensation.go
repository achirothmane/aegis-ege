package primitivereduction

import "errors"

type CompensationStatus string

const (
	CompensationNotJustified CompensationStatus = "NOT_JUSTIFIED"
	CompensationRequired     CompensationStatus = "REQUIRED"
	CompensationUnknown      CompensationStatus = "UNKNOWN"
	CompensationClosed       CompensationStatus = "CLOSED"
)

// CompensationBinding proves which already-observed effect a distinct
// compensating effect is intended to address. Compensation is a new governed
// effect; it is never represented as erasing or rewinding the original effect.
type CompensationBinding struct {
	OriginalEffectID     string
	CompensationEffectID string
	Evidence             Evidence
}

func BuildCompensationBinding(
	original Proposal,
	originalCustody StateRef,
	compensation Proposal,
) (CompensationBinding, error) {
	if !originalCustody.Complete() ||
		originalCustody.Namespace != custodyNamespace ||
		originalCustody.Digest != custodyDigest(originalCustody) ||
		originalCustody.Facts[factCustodyPhase] != CustodyClosed {
		return CompensationBinding{}, errors.New("compensation requires truthfully CLOSED original effect custody")
	}

	originalID, err := EffectIdentity(original)
	if err != nil {
		return CompensationBinding{}, err
	}
	compensationID, err := EffectIdentity(compensation)
	if err != nil {
		return CompensationBinding{}, err
	}
	if originalID == compensationID {
		return CompensationBinding{}, errors.New("compensation must be a distinct logical effect")
	}
	if originalCustody.ObjectID != originalID ||
		originalCustody.Facts[factEffectID] != originalID {
		return CompensationBinding{}, errors.New("original custody does not match original logical effect")
	}

	return CompensationBinding{
		OriginalEffectID:     originalID,
		CompensationEffectID: compensationID,
		Evidence: Evidence{
			ID:          originalID + "->" + compensationID,
			Type:        "compensation-binding-attestation",
			StateDigest: originalCustody.Digest,
			Valid:       true,
		},
	}, nil
}

func validCompensationBinding(
	original Proposal,
	originalCustody StateRef,
	compensation Proposal,
	binding CompensationBinding,
) bool {
	if !binding.Evidence.Complete() ||
		!binding.Evidence.Valid ||
		binding.Evidence.Type != "compensation-binding-attestation" ||
		binding.Evidence.StateDigest != originalCustody.Digest {
		return false
	}

	originalID, err := EffectIdentity(original)
	if err != nil {
		return false
	}
	compensationID, err := EffectIdentity(compensation)
	if err != nil {
		return false
	}
	return binding.OriginalEffectID == originalID &&
		binding.CompensationEffectID == compensationID &&
		originalID != compensationID &&
		originalCustody.ObjectID == originalID &&
		originalCustody.Facts[factEffectID] == originalID
}

// EvaluateCompensationBoundary admits compensation only after the original
// effect is truthfully CLOSED and the compensation relationship is bound by
// evidence. UNKNOWN original effects are never "rolled back" automatically.
func EvaluateCompensationBoundary(
	original Proposal,
	originalCustody StateRef,
	compensation Proposal,
	executor Identity,
	compensationCustody StateRef,
	binding CompensationBinding,
) AdmissionResult {
	if !originalCustody.Complete() ||
		originalCustody.Namespace != custodyNamespace ||
		originalCustody.Digest != custodyDigest(originalCustody) {
		return deny(ReasonMissingState, "original effect custody is incomplete or invalid")
	}
	if originalCustody.Facts[factCustodyPhase] != CustodyClosed {
		return deny(ReasonConstraintViolated, "original effect is not truthfully CLOSED; compensation is not justified")
	}
	if !validCompensationBinding(original, originalCustody, compensation, binding) {
		return deny(ReasonEvidenceInvalid, "compensation binding is invalid, stale, or belongs to another effect")
	}
	return EvaluateNonIdempotentBoundary(compensation, executor, compensationCustody)
}

// DeriveCompensationStatus never rewrites history. CLOSED means the new
// compensating effect is closed; it does not mean the original effect never
// happened.
func DeriveCompensationStatus(originalCustody, compensationCustody StateRef) CompensationStatus {
	if !originalCustody.Complete() ||
		originalCustody.Namespace != custodyNamespace ||
		originalCustody.Digest != custodyDigest(originalCustody) {
		return CompensationUnknown
	}
	if originalCustody.Facts[factCustodyPhase] != CustodyClosed {
		return CompensationNotJustified
	}
	if !compensationCustody.Complete() ||
		compensationCustody.Namespace != custodyNamespace ||
		compensationCustody.Digest != custodyDigest(compensationCustody) {
		return CompensationUnknown
	}

	switch compensationCustody.Facts[factCustodyPhase] {
	case CustodyReserved:
		return CompensationRequired
	case CustodyCrossing, CustodyUnknown:
		return CompensationUnknown
	case CustodyClosed:
		return CompensationClosed
	default:
		return CompensationUnknown
	}
}
