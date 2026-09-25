package assurance

import (
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/epistemic"
)

type TemporalGateResult struct {
	Decision   decision.Result
	Assessment epistemic.TemporalAssessment
}

func EvaluateWithTemporalAssumption(
	req decision.Request,
	assumption epistemic.Assumption,
	now time.Time,
	sensitivity epistemic.ActionSensitivity,
	policy epistemic.TemporalPolicy,
) TemporalGateResult {
	assessment := epistemic.AssessTemporalValidity(
		assumption,
		now,
		sensitivity,
		policy,
	)

	switch assessment.Validity {
	case epistemic.ValidityValid:
		return TemporalGateResult{
			Decision:   decision.Evaluate(req),
			Assessment: assessment,
		}
	case epistemic.ValidityExpired:
		return TemporalGateResult{
			Decision: decision.Result{
				Decision:    decision.Block,
				ReasonCodes: []decision.ReasonCode{decision.AssumptionExpired},
			},
			Assessment: assessment,
		}
	case epistemic.ValidityInvalidated:
		return TemporalGateResult{
			Decision: decision.Result{
				Decision:    decision.Block,
				ReasonCodes: []decision.ReasonCode{decision.AssumptionInvalidated},
			},
			Assessment: assessment,
		}
	default:
		return TemporalGateResult{
			Decision: decision.Result{
				Decision:    decision.Escalate,
				ReasonCodes: []decision.ReasonCode{decision.AssumptionValidityUnknown},
			},
			Assessment: assessment,
		}
	}
}
