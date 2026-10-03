package primitivereduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

const (
	planNamespace         = "governance.effect_plan"
	planEvidenceType      = "effect-plan-attestation"
	planFactStepPrefix    = "step."
	planFactDependsSuffix = ".depends"
)

type PlanStatus string

const (
	PlanOpen    PlanStatus = "OPEN"
	PlanPartial PlanStatus = "PARTIAL"
	PlanUnknown PlanStatus = "UNKNOWN"
	PlanClosed  PlanStatus = "CLOSED"
)

type EffectPlanStep struct {
	Proposal  Proposal
	Executor  Identity
	Custody   StateRef
	DependsOn []string
}

type EffectPlan struct {
	State    StateRef
	Evidence Evidence
	Steps    []EffectPlanStep
}

// BuildEffectPlan constructs a plan as another ordinary State instance. The
// dependency graph is bound into the State digest and an Evidence item. The
// plan is therefore derived composition over the six candidate primitives,
// not a seventh primitive.
func BuildEffectPlan(steps []EffectPlanStep, sequence string) (EffectPlan, error) {
	if len(steps) == 0 {
		return EffectPlan{}, errors.New("effect plan requires at least one step")
	}
	if sequence == "" {
		return EffectPlan{}, errors.New("effect plan sequence is required")
	}

	effectIDs := make([]string, len(steps))
	known := make(map[string]struct{}, len(steps))
	for i := range steps {
		id, err := EffectIdentity(steps[i].Proposal)
		if err != nil {
			return EffectPlan{}, err
		}
		if !steps[i].Executor.Complete() {
			return EffectPlan{}, errors.New("effect plan step executor is incomplete")
		}
		if !steps[i].Custody.Complete() || steps[i].Custody.Namespace != custodyNamespace {
			return EffectPlan{}, errors.New("effect plan step custody is incomplete")
		}
		if steps[i].Custody.ObjectID != id || steps[i].Custody.Facts[factEffectID] != id {
			return EffectPlan{}, errors.New("effect plan step custody does not match logical effect")
		}
		if _, dup := known[id]; dup {
			return EffectPlan{}, errors.New("effect plan contains duplicate logical effect")
		}
		effectIDs[i] = id
		known[id] = struct{}{}
	}

	facts := make(map[string]string, len(steps))
	for i := range steps {
		deps := append([]string(nil), steps[i].DependsOn...)
		sort.Strings(deps)
		for _, dep := range deps {
			if _, ok := known[dep]; !ok {
				return EffectPlan{}, errors.New("effect plan dependency references unknown logical effect")
			}
			if dep == effectIDs[i] {
				return EffectPlan{}, errors.New("effect plan step cannot depend on itself")
			}
		}
		facts[planFactStepPrefix+effectIDs[i]+planFactDependsSuffix] = strings.Join(deps, ",")
	}

	state := StateRef{
		Namespace: planNamespace,
		ObjectID:  derivePlanObjectID(effectIDs),
		Version:   "plan:" + sequence,
		Facts:     facts,
	}
	state.Digest = planDigest(state)
	evidence := Evidence{
		ID:          state.ObjectID,
		Type:        planEvidenceType,
		StateDigest: state.Digest,
		Valid:       true,
	}
	return EffectPlan{State: state, Evidence: evidence, Steps: steps}, nil
}

func derivePlanObjectID(effectIDs []string) string {
	ids := append([]string(nil), effectIDs...)
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return hex.EncodeToString(sum[:])
}

func planDigest(state StateRef) string {
	keys := make([]string, 0, len(state.Facts))
	for key := range state.Facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := []string{state.Namespace, state.ObjectID, state.Version}
	for _, key := range keys {
		parts = append(parts, key, state.Facts[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validPlanBinding(plan EffectPlan) bool {
	if !plan.State.Complete() ||
		plan.State.Namespace != planNamespace ||
		plan.State.Digest != planDigest(plan.State) ||
		!plan.Evidence.Complete() ||
		!plan.Evidence.Valid ||
		plan.Evidence.Type != planEvidenceType ||
		plan.Evidence.ID != plan.State.ObjectID ||
		plan.Evidence.StateDigest != plan.State.Digest {
		return false
	}
	return true
}

func dependencyIDs(plan EffectPlan, effectID string) ([]string, bool) {
	raw, ok := plan.State.Facts[planFactStepPrefix+effectID+planFactDependsSuffix]
	if !ok {
		return nil, false
	}
	if raw == "" {
		return nil, true
	}
	return strings.Split(raw, ","), true
}

func custodyByEffectID(plan EffectPlan) map[string]StateRef {
	out := make(map[string]StateRef, len(plan.Steps))
	for _, step := range plan.Steps {
		out[step.Custody.Facts[factEffectID]] = step.Custody
	}
	return out
}

// EvaluatePlannedEffectBoundary requires an intact plan attestation, all
// predecessor effects CLOSED, and ordinary non-idempotent boundary admission
// for the selected step. This prevents restart/retry from reordering causal
// effects or replaying a previously closed effect.
func EvaluatePlannedEffectBoundary(plan EffectPlan, stepIndex int) AdmissionResult {
	if !validPlanBinding(plan) {
		return deny(ReasonEvidenceInvalid, "effect plan state or attestation is invalid")
	}
	if stepIndex < 0 || stepIndex >= len(plan.Steps) {
		return deny(ReasonMissingTransition, "effect plan step index is out of range")
	}
	step := plan.Steps[stepIndex]
	effectID, err := EffectIdentity(step.Proposal)
	if err != nil {
		return deny(ReasonMissingTransition, err.Error())
	}
	deps, ok := dependencyIDs(plan, effectID)
	if !ok {
		return deny(ReasonBindingMismatch, "effect plan does not bind selected logical effect")
	}

	custodies := custodyByEffectID(plan)
	for _, dep := range deps {
		custody, exists := custodies[dep]
		if !exists || custody.Facts[factCustodyPhase] != CustodyClosed || custody.Digest != custodyDigest(custody) {
			return deny(ReasonConstraintViolated, "predecessor effect is not truthfully CLOSED")
		}
	}

	return EvaluateNonIdempotentBoundary(step.Proposal, step.Executor, step.Custody)
}

// PlanDisposition is fully derived from custody State values. A single
// ambiguous/crossing effect makes the whole plan UNKNOWN. CLOSED requires all
// effects CLOSED. PARTIAL means some effects are closed and remaining effects
// are still safely RESERVED.
func PlanDisposition(plan EffectPlan) PlanStatus {
	if !validPlanBinding(plan) || len(plan.Steps) == 0 {
		return PlanUnknown
	}

	closed := 0
	reserved := 0
	for _, step := range plan.Steps {
		custody := step.Custody
		if !custody.Complete() || custody.Digest != custodyDigest(custody) {
			return PlanUnknown
		}
		switch custody.Facts[factCustodyPhase] {
		case CustodyClosed:
			closed++
		case CustodyReserved:
			reserved++
		case CustodyCrossing, CustodyUnknown:
			return PlanUnknown
		default:
			return PlanUnknown
		}
	}

	switch {
	case closed == len(plan.Steps):
		return PlanClosed
	case closed > 0 && closed+reserved == len(plan.Steps):
		return PlanPartial
	case reserved == len(plan.Steps):
		return PlanOpen
	default:
		return PlanUnknown
	}
}

// ReplaceStepCustody models crash recovery/reconstruction from durable custody
// State. It refuses a custody object for another logical effect.
func ReplaceStepCustody(plan EffectPlan, stepIndex int, custody StateRef) (EffectPlan, error) {
	if stepIndex < 0 || stepIndex >= len(plan.Steps) {
		return EffectPlan{}, errors.New("effect plan step index is out of range")
	}
	effectID, err := EffectIdentity(plan.Steps[stepIndex].Proposal)
	if err != nil {
		return EffectPlan{}, err
	}
	if !custody.Complete() ||
		custody.Namespace != custodyNamespace ||
		custody.ObjectID != effectID ||
		custody.Facts[factEffectID] != effectID ||
		custody.Digest != custodyDigest(custody) {
		return EffectPlan{}, errors.New("replacement custody does not belong to selected logical effect")
	}

	out := plan
	out.Steps = append([]EffectPlanStep(nil), plan.Steps...)
	out.Steps[stepIndex].Custody = custody
	return out, nil
}
