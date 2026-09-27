package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/achirothmane/easl"
)

func DigestEvidence(evidence []EvidenceObservation) string {
	canonical := make([]string, 0, len(evidence))
	for _, observation := range evidence {
		canonical = append(canonical, strings.Join([]string{
			observation.Claim,
			observation.Source,
			observation.Value,
			observation.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		}, "\x1f"))
	}
	sort.Strings(canonical)

	hash := sha256.Sum256([]byte(strings.Join(canonical, "\x1e")))
	return "sha256:" + hex.EncodeToString(hash[:])
}

const (
	authorizationResourceVersionBinding easl.StateBindingID = "authorization-resource-version"
	authorizationPlanDigestBinding      easl.StateBindingID = "authorization-plan-digest"
	authorizationStateAssumption        easl.AssumptionID   = "authorization-subject-state-unchanged"
)

func ValidateAuthorization(auth Authorization, attempt ExecutionAttempt) AuthorizationValidation {
	reasons := make([]ReasonCode, 0, 5)

	if !attempt.Now.Before(auth.ValidUntil) {
		reasons = append(reasons, AuthorizationExpired)
	}
	reasons = append(reasons, validateAuthorizationStateBindings(auth, attempt)...)
	if attempt.Action != auth.Action || attempt.ActionID != auth.ActionID {
		reasons = append(reasons, ActionChanged)
	}
	if attempt.Target != auth.Target {
		reasons = append(reasons, TargetChanged)
	}

	return AuthorizationValidation{
		Valid:       len(reasons) == 0,
		ReasonCodes: reasons,
	}
}

func validateAuthorizationStateBindings(auth Authorization, attempt ExecutionAttempt) []ReasonCode {
	reasons := make([]ReasonCode, 0, 2)
	bindings := make([]easl.StateBinding, 0, 2)
	required := make([]easl.StateBindingID, 0, 2)

	if auth.ResourceVersion != "" && attempt.ResourceVersion != "" {
		bindings = append(bindings, easl.StateBinding{
			ID:       authorizationResourceVersionBinding,
			Expected: auth.ResourceVersion,
			Observed: attempt.ResourceVersion,
		})
		required = append(required, authorizationResourceVersionBinding)
	} else if auth.ResourceVersion != attempt.ResourceVersion {
		reasons = append(reasons, ResourceVersionChanged)
	}

	if auth.PlanDigest != "" {
		if attempt.PlanDigest != "" {
			bindings = append(bindings, easl.StateBinding{
				ID:       authorizationPlanDigestBinding,
				Expected: auth.PlanDigest,
				Observed: attempt.PlanDigest,
			})
			required = append(required, authorizationPlanDigestBinding)
		} else {
			reasons = append(reasons, ExecutionPlanChanged)
		}
	}

	if len(bindings) == 0 {
		return reasons
	}

	evaluation, err := easl.Evaluate(easl.Snapshot{
		At:            attempt.Now,
		StateBindings: bindings,
		Assumptions: []easl.Assumption{{
			ID:                    authorizationStateAssumption,
			RequiresStateBindings: required,
		}},
	})
	if err != nil {
		return append(reasons, InsufficientStateBinding)
	}

	for _, invalidation := range evaluation.Invalidations {
		if invalidation.AssumptionID != authorizationStateAssumption ||
			invalidation.Reason != easl.ReasonSubjectStateChanged {
			continue
		}
		switch invalidation.StateBindingID {
		case authorizationResourceVersionBinding:
			reasons = append(reasons, ResourceVersionChanged)
		case authorizationPlanDigestBinding:
			reasons = append(reasons, ExecutionPlanChanged)
		default:
			reasons = append(reasons, InsufficientStateBinding)
		}
	}

	return reasons
}
