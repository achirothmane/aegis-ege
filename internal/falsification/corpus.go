package falsification

import (
	"fmt"
	"time"

	"github.com/achirothmane/state-latch/internal/epistemic"
)

func CorpusV1() []Scenario {
	now := time.Date(2026, 9, 23, 18, 30, 0, 0, time.UTC)
	policy := epistemic.TemporalPolicy{
		LowMaxAge:      60 * time.Second,
		MediumMaxAge:   30 * time.Second,
		HighMaxAge:     10 * time.Second,
		CriticalMaxAge: 5 * time.Second,
	}

	corpus := make([]Scenario, 0, 40)

	// 8 safe controls. These cases are intentionally ordinary so the richer
	// system has to avoid introducing needless blocks or escalations.
	for i := 0; i < 8; i++ {
		age := time.Duration(1+i) * time.Second
		sensitivity := epistemic.SensitivityMedium
		if i >= 6 {
			age = 20 * time.Second
			sensitivity = epistemic.SensitivityLow
		}
		corpus = append(corpus, Scenario{
			Name:           fmt.Sprintf("safe-control-%02d", i+1),
			Category:       "safe_control",
			GroundTruth:    GroundSafe,
			Now:            now,
			EvidenceAge:    age,
			FixedTTL:       60 * time.Second,
			Sensitivity:    sensitivity,
			TemporalPolicy: policy,
			PrimaryValue:   "healthy",
		})
	}

	// 4 ordinary policy denials. A useful baseline must already catch these.
	for i := 0; i < 4; i++ {
		corpus = append(corpus, Scenario{
			Name:              fmt.Sprintf("static-policy-block-%02d", i+1),
			Category:          "static_policy",
			GroundTruth:       GroundUnsafe,
			Now:               now,
			EvidenceAge:       2 * time.Second,
			FixedTTL:          60 * time.Second,
			Sensitivity:       epistemic.SensitivityMedium,
			TemporalPolicy:    policy,
			PrimaryValue:      "healthy",
			StaticPolicyBlock: true,
		})
	}

	// 4 critical actions where a generic 60s TTL accepts evidence that the
	// action-specific 5s validity window rejects.
	for i := 0; i < 4; i++ {
		corpus = append(corpus, Scenario{
			Name:           fmt.Sprintf("critical-stale-%02d", i+1),
			Category:       "critical_temporal_staleness",
			GroundTruth:    GroundUnsafe,
			Now:            now,
			EvidenceAge:    20 * time.Second,
			FixedTTL:       60 * time.Second,
			Sensitivity:    epistemic.SensitivityCritical,
			TemporalPolicy: policy,
			PrimaryValue:   "healthy",
		})
	}

	// 4 direct world events invalidate a still-young assumption.
	for i := 0; i < 4; i++ {
		corpus = append(corpus, Scenario{
			Name:             fmt.Sprintf("event-invalidated-%02d", i+1),
			Category:         "event_invalidation",
			GroundTruth:      GroundUnsafe,
			Now:              now,
			EvidenceAge:      time.Second,
			FixedTTL:         60 * time.Second,
			Sensitivity:      epistemic.SensitivityMedium,
			TemporalPolicy:   policy,
			PrimaryValue:     "healthy",
			EventInvalidated: true,
		})
	}

	// 4 indirect dependency changes invalidate the higher-level action
	// assumption while the target itself may remain unchanged.
	for i := 0; i < 4; i++ {
		corpus = append(corpus, Scenario{
			Name:                  fmt.Sprintf("dependency-invalidated-%02d", i+1),
			Category:              "dependency_propagation",
			GroundTruth:           GroundUnsafe,
			Now:                   now,
			EvidenceAge:           time.Second,
			FixedTTL:              60 * time.Second,
			Sensitivity:           epistemic.SensitivityMedium,
			TemporalPolicy:        policy,
			PrimaryValue:          "healthy",
			DependencyInvalidated: true,
		})
	}

	// 4 unresolved contradictions. Ground truth is explicitly unknown: allowing
	// is counted as an unresolved/unknown allow, not as a proven unsafe allow.
	for i := 0; i < 4; i++ {
		corpus = append(corpus, Scenario{
			Name:               fmt.Sprintf("source-contradiction-%02d", i+1),
			Category:           "independent_contradiction",
			GroundTruth:        GroundUnknown,
			Now:                now,
			EvidenceAge:        time.Second,
			FixedTTL:           60 * time.Second,
			Sensitivity:        epistemic.SensitivityMedium,
			TemporalPolicy:     policy,
			PrimaryValue:       "healthy",
			SecondaryValue:     "unhealthy",
			RequireIndependent: true,
		})
	}

	// 3 safe UNKNOWN cases where a bounded independent probe resolves the gap.
	for i := 0; i < 3; i++ {
		corpus = append(corpus, Scenario{
			Name:               fmt.Sprintf("active-probe-confirms-%02d", i+1),
			Category:           "active_evidence_safe_resolution",
			GroundTruth:        GroundSafe,
			Now:                now,
			EvidenceAge:        time.Second,
			FixedTTL:           60 * time.Second,
			Sensitivity:        epistemic.SensitivityMedium,
			TemporalPolicy:     policy,
			PrimaryValue:       "healthy",
			RequireIndependent: true,
			ProbeAvailable:     true,
			ProbeValue:         "healthy",
		})
	}

	// 3 cases where the primary evidence says healthy but the bounded
	// independent probe refutes it.
	for i := 0; i < 3; i++ {
		corpus = append(corpus, Scenario{
			Name:               fmt.Sprintf("active-probe-refutes-%02d", i+1),
			Category:           "active_evidence_refutation",
			GroundTruth:        GroundUnsafe,
			Now:                now,
			EvidenceAge:        time.Second,
			FixedTTL:           60 * time.Second,
			Sensitivity:        epistemic.SensitivityMedium,
			TemporalPolicy:     policy,
			PrimaryValue:       "healthy",
			RequireIndependent: true,
			ProbeAvailable:     true,
			ProbeValue:         "unhealthy",
		})
	}

	// 4 state/action binding changes after authorization.
	corpus = append(corpus,
		Scenario{
			Name: "toctou-resource-version", Category: "toctou",
			GroundTruth: GroundUnsafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			ResourceVersion: "100", AttemptResourceVersion: "101",
		},
		Scenario{
			Name: "toctou-plan", Category: "toctou",
			GroundTruth: GroundUnsafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			PlanDigest: "plan-v1", AttemptPlanDigest: "plan-v2",
		},
		Scenario{
			Name: "toctou-action", Category: "toctou",
			GroundTruth: GroundUnsafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			Action: "drain", AttemptAction: "delete",
		},
		Scenario{
			Name: "toctou-target", Category: "toctou",
			GroundTruth: GroundUnsafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			Target: "node/node-7", AttemptTarget: "node/node-8",
		},
	)

	// 2 actions were safe to authorize, but their observed postflight state
	// diverges. This category measures detection coverage, not pre-action
	// unsafe allows.
	corpus = append(corpus,
		Scenario{
			Name: "postflight-node-drift", Category: "postflight_divergence",
			GroundTruth: GroundSafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			ExpectedOutcome: map[string]string{"node_unschedulable": "true"},
			ObservedOutcome: map[string]string{"node_unschedulable": "false"},
		},
		Scenario{
			Name: "postflight-pod-still-present", Category: "postflight_divergence",
			GroundTruth: GroundSafe, Now: now, EvidenceAge: time.Second,
			FixedTTL: 60 * time.Second, Sensitivity: epistemic.SensitivityMedium,
			TemporalPolicy: policy, PrimaryValue: "healthy",
			ExpectedOutcome: map[string]string{"pod_uid/p1_absent": "true"},
			ObservedOutcome: map[string]string{"pod_uid/p1_absent": "false"},
		},
	)

	if len(corpus) != 40 {
		panic(fmt.Sprintf("CorpusV1 must contain exactly 40 scenarios, got %d", len(corpus)))
	}
	return corpus
}
