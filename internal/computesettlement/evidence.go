package computesettlement

import (
	"strings"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

// EvidenceRequirement binds settlement observations to the exact evidence
// sources whose independence is being claimed.
type EvidenceRequirement struct {
	Subject      string
	Independence egeproto.EvidenceIndependenceRequirement
}

// EvidenceBoundReconciliation preserves the generic independence assessment
// alongside the commercial disposition.
type EvidenceBoundReconciliation struct {
	Reconciliation
	EvidenceComposition egeproto.EvidenceCompositionAssessment
}

// ReconcileWithEvidence refuses to produce a conclusive commercial disposition
// unless the settlement observations are exactly bound to the assessed evidence
// sources and the configured independence predicate is satisfied.
func ReconcileWithEvidence(
	actionID string,
	planDigest string,
	contractFacts map[string]string,
	observations []Observation,
	sources []egeproto.EvidenceSource,
	requirement EvidenceRequirement,
) EvidenceBoundReconciliation {
	subject := strings.TrimSpace(requirement.Subject)
	assessment := egeproto.AssessEvidenceIndependence(
		sources,
		requirement.Independence,
	)

	unknown := func(detail string) EvidenceBoundReconciliation {
		return EvidenceBoundReconciliation{
			Reconciliation: Reconciliation{
				Disposition: Unknown,
				Detail:      detail,
			},
			EvidenceComposition: assessment,
		}
	}

	if subject == "" {
		return unknown("settlement evidence subject is required")
	}
	if len(observations) == 0 || len(sources) != len(observations) {
		return unknown("settlement observations and assessed evidence sources must have identical cardinality")
	}

	byName := make(map[string]egeproto.EvidenceSource, len(sources))
	for _, source := range sources {
		name := strings.TrimSpace(source.Name)
		if name == "" || strings.TrimSpace(source.Digest) == "" || source.ObservedAt.IsZero() {
			return unknown("assessed settlement evidence source has incomplete binding")
		}
		if _, duplicate := byName[name]; duplicate {
			return unknown("assessed settlement evidence source name is duplicated")
		}
		if source.Declaration == nil || strings.TrimSpace(source.Declaration.Subject) != subject {
			return unknown("assessed settlement evidence source is not bound to the required subject")
		}
		byName[name] = source
	}

	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		source, ok := byName[observation.Source]
		if !ok {
			return unknown("settlement observation has no assessed evidence source")
		}
		if _, duplicate := seen[observation.Source]; duplicate {
			return unknown("settlement observation source is duplicated")
		}
		seen[observation.Source] = struct{}{}
		if source.Digest != observation.EvidenceDigest {
			return unknown("settlement observation digest does not match assessed evidence")
		}
		if !source.ObservedAt.Equal(observation.ObservedAt) {
			return unknown("settlement observation time does not match assessed evidence")
		}
	}

	if !egeproto.EvidenceIndependenceSatisfied(
		assessment,
		requirement.Independence,
	) {
		return unknown("required evidence independence is not established")
	}

	reconciled := Reconcile(
		actionID,
		planDigest,
		contractFacts,
		observations,
	)
	return EvidenceBoundReconciliation{
		Reconciliation:      reconciled,
		EvidenceComposition: assessment,
	}
}
