package falsification

import (
	"context"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/assurance"
	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/epistemic"
	"github.com/achirothmane/aegis-ege/internal/outcome"
)

type GroundTruth string

const (
	GroundSafe    GroundTruth = "SAFE"
	GroundUnsafe  GroundTruth = "UNSAFE"
	GroundUnknown GroundTruth = "UNKNOWN"
)

type Scenario struct {
	Name       string
	Category   string
	GroundTruth GroundTruth

	Now         time.Time
	EvidenceAge time.Duration
	FixedTTL    time.Duration
	Sensitivity epistemic.ActionSensitivity
	TemporalPolicy epistemic.TemporalPolicy

	PrimaryValue   string
	SecondaryValue string
	RequireIndependent bool

	EventInvalidated      bool
	DependencyInvalidated bool

	ProbeAvailable bool
	ProbeValue     string

	ReconcileContradiction bool
	FreshPrimaryValue      string
	FreshSecondaryValue    string

	StaticPolicyBlock bool

	ResourceVersion        string
	AttemptResourceVersion string
	PlanDigest             string
	AttemptPlanDigest      string
	Action                 string
	AttemptAction          string
	Target                 string
	AttemptTarget          string

	ExpectedOutcome map[string]string
	ObservedOutcome map[string]string
}

type Evaluation struct {
	Decision            decision.Decision
	Reasons             []decision.ReasonCode
	OutcomeDivergence   bool
	OutcomeUnknown      bool
	ProbeAttempts       int
}

type SystemMetrics struct {
	Total                 int
	UnsafeAllows          int
	UnknownAllows         int
	SafeBlocks            int
	SafeEscalations       int
	UnsafePrevented       int
	UnknownPrevented      int
	OutcomeDivergences    int
	OutcomeDivergencesDetected int
	ProbeAttempts         int
	Allows                int
	Blocks                int
	Escalates             int
}

type Comparison struct {
	Baseline   SystemMetrics
	StateLatch SystemMetrics
	Cases      []CaseResult
}

type CaseResult struct {
	Name       string
	Category   string
	GroundTruth GroundTruth
	Baseline   Evaluation
	StateLatch Evaluation
}

func EvaluateCorpus(corpus []Scenario) Comparison {
	comparison := Comparison{
		Baseline:   SystemMetrics{Total: len(corpus)},
		StateLatch: SystemMetrics{Total: len(corpus)},
		Cases:      make([]CaseResult, 0, len(corpus)),
	}

	for _, scenario := range corpus {
		baseline := EvaluateBaseline(scenario)
		stateLatch := EvaluateStateLatch(scenario)

		accumulate(&comparison.Baseline, scenario, baseline)
		accumulate(&comparison.StateLatch, scenario, stateLatch)

		comparison.Cases = append(comparison.Cases, CaseResult{
			Name:        scenario.Name,
			Category:    scenario.Category,
			GroundTruth: scenario.GroundTruth,
			Baseline:    baseline,
			StateLatch:  stateLatch,
		})
	}

	return comparison
}

// EvaluateBaseline models the falsification baseline defined for v1:
//
//   live primary lookup + fixed TTL + static policy + request-time decision
//
// It intentionally has no continuous invalidation graph, independent-source
// contradiction handling, active evidence acquisition, action-sensitive
// temporal windows, action-bound execution revalidation, or postflight
// outcome comparison.
func EvaluateBaseline(s Scenario) Evaluation {
	if s.StaticPolicyBlock {
		return Evaluation{Decision: decision.Block}
	}

	if s.EvidenceAge > s.FixedTTL {
		return Evaluation{
			Decision: decision.Block,
			Reasons:  []decision.ReasonCode{decision.EvidenceStale},
		}
	}

	if s.PrimaryValue == "unhealthy" {
		return Evaluation{Decision: decision.Block}
	}

	if effectiveAction(s) == "" || effectiveTarget(s) == "" || effectiveResourceVersion(s) == "" {
		return Evaluation{
			Decision: decision.Escalate,
			Reasons:  []decision.ReasonCode{decision.InsufficientStateBinding},
		}
	}

	return Evaluation{Decision: decision.Allow}
}

func EvaluateStateLatch(s Scenario) Evaluation {
	if s.StaticPolicyBlock {
		return Evaluation{Decision: decision.Block}
	}

	req := baseRequest(s)
	assumption := buildAssumption(s)

	var result decision.Result
	probeAttempts := 0

	switch {
	case s.SecondaryValue != "":
		req.Evidence = append(req.Evidence, observation(
			"node_health",
			"independent-source",
			s.SecondaryValue,
			s.Now.Add(-s.EvidenceAge),
		))
		req.RequiredSourceCount = 2
		result = decision.Evaluate(req)

		if result.Decision == decision.Block &&
			hasReason(result.ReasonCodes, decision.EvidenceContradicted) &&
			s.ReconcileContradiction {
			freshPrimary := s.FreshPrimaryValue
			if freshPrimary == "" {
				freshPrimary = s.PrimaryValue
			}
			freshSecondary := s.FreshSecondaryValue
			if freshSecondary == "" {
				freshSecondary = s.SecondaryValue
			}

			reconciled := decision.ReconcileContradiction(
				context.Background(),
				req,
				[]decision.EvidenceProbe{
					&scenarioProbe{
						name:   "fresh-primary",
						value:  freshPrimary,
						source: "primary-live",
						at:     s.Now,
						rv:     effectiveResourceVersion(s),
					},
					&scenarioProbe{
						name:   "fresh-secondary",
						value:  freshSecondary,
						source: "independent-live",
						at:     s.Now,
					},
				},
				2,
			)
			probeAttempts += executedAttempts(reconciled.Attempts)
			req = reconciled.EffectiveRequest
			result = reconciled.Final
		}

	case s.RequireIndependent:
		req.RequiredSourceCount = 2
		result = decision.Evaluate(req)
		if result.Decision == decision.Escalate &&
			hasReason(result.ReasonCodes, decision.InsufficientEvidence) &&
			s.ProbeAvailable {
			resolved := decision.ResolveUnknown(
				context.Background(),
				req,
				[]decision.EvidenceProbe{
					&scenarioProbe{
						name:   "safe-independent-probe",
						value:  s.ProbeValue,
						source: "independent-live",
						at:     s.Now,
						rv:     effectiveResourceVersion(s),
					},
				},
				1,
			)
			probeAttempts += executedAttempts(resolved.Attempts)
			req = resolved.EffectiveRequest
			result = resolved.Final
		}

	default:
		result = decision.Evaluate(req)
	}

	if result.Decision == decision.Allow {
		temporal := assurance.EvaluateWithTemporalAssumption(
			req,
			assumption,
			s.Now,
			effectiveSensitivity(s),
			effectiveTemporalPolicy(s),
		)
		result = temporal.Decision
	}

	if result.Decision == decision.Allow && result.Authorization != nil {
		auth := *result.Authorization
		auth.PlanDigest = effectivePlanDigest(s)

		validation := decision.ValidateAuthorization(
			auth,
			decision.ExecutionAttempt{
				ActionID:        req.ActionID,
				Action:          effectiveAttemptAction(s),
				Target:          effectiveAttemptTarget(s),
				ResourceVersion: effectiveAttemptResourceVersion(s),
				PlanDigest:      effectiveAttemptPlanDigest(s),
				Now:             s.Now,
			},
		)
		if !validation.Valid {
			result = decision.Result{
				Decision:    decision.Escalate,
				ReasonCodes: validation.ReasonCodes,
			}
		}
	}

	evaluation := Evaluation{
		Decision:      result.Decision,
		Reasons:       append([]decision.ReasonCode(nil), result.ReasonCodes...),
		ProbeAttempts: probeAttempts,
	}

	if len(s.ExpectedOutcome) > 0 {
		record := outcome.Compare(
			"benchmark",
			"",
			effectivePlanDigest(s),
			s.ExpectedOutcome,
			s.ObservedOutcome,
			nil,
			s.Now,
		)
		evaluation.OutcomeDivergence = record.Verdict == outcome.Diverged
		evaluation.OutcomeUnknown = record.Verdict == outcome.Unknown
	}

	return evaluation
}

func baseRequest(s Scenario) decision.Request {
	observedAt := s.Now.Add(-s.EvidenceAge)
	return decision.Request{
		ActionID:            "benchmark-action",
		Action:              effectiveAction(s),
		Target:              effectiveTarget(s),
		ResourceVersion:     effectiveResourceVersion(s),
		RequestedAt:         s.Now,
		AuthorizationTTL:    30 * time.Second,
		MaxEvidenceAge:      s.FixedTTL,
		RequiredSourceCount: 1,
		BlastRadius:         1,
		MaxBlastRadius:      5,
		Evidence: []decision.EvidenceObservation{
			observation("node_health", "primary-live-or-cache", s.PrimaryValue, observedAt),
		},
	}
}

func buildAssumption(s Scenario) epistemic.Assumption {
	evaluatedAt := s.Now.Add(-s.EvidenceAge)

	if s.DependencyInvalidated {
		tracker := epistemic.NewTracker()
		resource := epistemic.ResourceRef{
			APIVersion:      "policy/v1",
			Kind:            "PodDisruptionBudget",
			Namespace:       "benchmark",
			Name:            "budget",
			UID:             "pdb-uid",
			ResourceVersion: "10",
		}
		tracker.PutAssumption(epistemic.Assumption{
			ID:           "A-DEPENDENCY",
			Status:       epistemic.AssumptionSupported,
			Dependencies: []epistemic.ResourceRef{resource},
			EvaluatedAt:  evaluatedAt,
		})
		tracker.PutAssumption(epistemic.Assumption{
			ID:                     "A-ACTION",
			Status:                 epistemic.AssumptionSupported,
			AssumptionDependencies: []string{"A-DEPENDENCY"},
			EvaluatedAt:            evaluatedAt,
		})
		tracker.Handle(epistemic.ResourceEvent{
			Type: "MODIFIED",
			Resource: epistemic.ResourceRef{
				APIVersion:      resource.APIVersion,
				Kind:            resource.Kind,
				Namespace:       resource.Namespace,
				Name:            resource.Name,
				UID:             resource.UID,
				ResourceVersion: "11",
			},
			At: s.Now,
		})
		assumption, _ := tracker.GetAssumption("A-ACTION")
		return assumption
	}

	if s.EventInvalidated {
		tracker := epistemic.NewTracker()
		resource := epistemic.ResourceRef{
			APIVersion:      "apps/v1",
			Kind:            "Deployment",
			Namespace:       "benchmark",
			Name:            "api",
			UID:             "dep-uid",
			ResourceVersion: "10",
		}
		tracker.PutAssumption(epistemic.Assumption{
			ID:           "A-ACTION",
			Status:       epistemic.AssumptionSupported,
			Dependencies: []epistemic.ResourceRef{resource},
			EvaluatedAt:  evaluatedAt,
		})
		tracker.Handle(epistemic.ResourceEvent{
			Type: "MODIFIED",
			Resource: epistemic.ResourceRef{
				APIVersion:      resource.APIVersion,
				Kind:            resource.Kind,
				Namespace:       resource.Namespace,
				Name:            resource.Name,
				UID:             resource.UID,
				ResourceVersion: "11",
			},
			At: s.Now,
		})
		assumption, _ := tracker.GetAssumption("A-ACTION")
		return assumption
	}

	return epistemic.Assumption{
		ID:          "A-ACTION",
		Status:      epistemic.AssumptionSupported,
		EvaluatedAt: evaluatedAt,
	}
}

type scenarioProbe struct {
	name   string
	value  string
	source string
	at     time.Time
	rv     string
}

func (p *scenarioProbe) Name() string { return p.name }
func (p *scenarioProbe) SafetyClass() decision.ProbeSafetyClass { return decision.ProbeReadOnly }
func (p *scenarioProbe) Supports(decision.Request, decision.Result) bool { return true }
func (p *scenarioProbe) Acquire(context.Context, decision.Request) (decision.ProbeOutcome, error) {
	if p.value == "" {
		return decision.ProbeOutcome{}, fmt.Errorf("probe evidence unavailable")
	}
	return decision.ProbeOutcome{
		ResourceVersion: p.rv,
		Evidence: []decision.EvidenceObservation{
			observation("node_health", p.source, p.value, p.at),
		},
	}, nil
}

func observation(claim, source, value string, at time.Time) decision.EvidenceObservation {
	return decision.EvidenceObservation{
		Claim:      claim,
		Source:     source,
		Value:      value,
		ObservedAt: at,
	}
}

func accumulate(metrics *SystemMetrics, scenario Scenario, eval Evaluation) {
	switch eval.Decision {
	case decision.Allow:
		metrics.Allows++
	case decision.Block:
		metrics.Blocks++
	case decision.Escalate:
		metrics.Escalates++
	}

	switch scenario.GroundTruth {
	case GroundUnsafe:
		if eval.Decision == decision.Allow {
			metrics.UnsafeAllows++
		} else {
			metrics.UnsafePrevented++
		}
	case GroundUnknown:
		if eval.Decision == decision.Allow {
			metrics.UnknownAllows++
		} else {
			metrics.UnknownPrevented++
		}
	case GroundSafe:
		if eval.Decision == decision.Block {
			metrics.SafeBlocks++
		}
		if eval.Decision == decision.Escalate {
			metrics.SafeEscalations++
		}
	}

	if len(scenario.ExpectedOutcome) > 0 {
		expectedRecord := outcome.Compare(
			"truth",
			"",
			"",
			scenario.ExpectedOutcome,
			scenario.ObservedOutcome,
			nil,
			scenario.Now,
		)
		if expectedRecord.Verdict == outcome.Diverged {
			metrics.OutcomeDivergences++
			if eval.OutcomeDivergence {
				metrics.OutcomeDivergencesDetected++
			}
		}
	}

	metrics.ProbeAttempts += eval.ProbeAttempts
}

func hasReason(reasons []decision.ReasonCode, target decision.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}

func executedAttempts(attempts []decision.ProbeAttempt) int {
	count := 0
	for _, attempt := range attempts {
		if !attempt.Skipped {
			count++
		}
	}
	return count
}

func effectiveSensitivity(s Scenario) epistemic.ActionSensitivity {
	if s.Sensitivity != "" {
		return s.Sensitivity
	}
	return epistemic.SensitivityMedium
}

func effectiveTemporalPolicy(s Scenario) epistemic.TemporalPolicy {
	if s.TemporalPolicy.LowMaxAge != 0 ||
		s.TemporalPolicy.MediumMaxAge != 0 ||
		s.TemporalPolicy.HighMaxAge != 0 ||
		s.TemporalPolicy.CriticalMaxAge != 0 {
		return s.TemporalPolicy
	}
	return epistemic.TemporalPolicy{
		LowMaxAge:      60 * time.Second,
		MediumMaxAge:   30 * time.Second,
		HighMaxAge:     10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}
}

func effectiveAction(s Scenario) string {
	if s.Action != "" {
		return s.Action
	}
	return "drain"
}

func effectiveAttemptAction(s Scenario) string {
	if s.AttemptAction != "" {
		return s.AttemptAction
	}
	return effectiveAction(s)
}

func effectiveTarget(s Scenario) string {
	if s.Target != "" {
		return s.Target
	}
	return "node/node-7"
}

func effectiveAttemptTarget(s Scenario) string {
	if s.AttemptTarget != "" {
		return s.AttemptTarget
	}
	return effectiveTarget(s)
}

func effectiveResourceVersion(s Scenario) string {
	if s.ResourceVersion != "" {
		return s.ResourceVersion
	}
	return "100"
}

func effectiveAttemptResourceVersion(s Scenario) string {
	if s.AttemptResourceVersion != "" {
		return s.AttemptResourceVersion
	}
	return effectiveResourceVersion(s)
}

func effectivePlanDigest(s Scenario) string {
	if s.PlanDigest != "" {
		return s.PlanDigest
	}
	return "plan-v1"
}

func effectiveAttemptPlanDigest(s Scenario) string {
	if s.AttemptPlanDigest != "" {
		return s.AttemptPlanDigest
	}
	return effectivePlanDigest(s)
}
