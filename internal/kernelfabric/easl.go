package kernelfabric

import (
	"errors"
	"time"

	"github.com/achirothmane/easl"
)

func (a ContinuityAssessment) ToEASLEvidence(
	evidenceID easl.EvidenceID,
	continuityAssumption easl.AssumptionID,
	observedAt time.Time,
	validFor time.Duration,
) (easl.Evidence, error) {
	if evidenceID == "" {
		return easl.Evidence{}, errors.New("kernel continuity evidence id is required")
	}
	if continuityAssumption == "" {
		return easl.Evidence{}, errors.New("kernel continuity assumption id is required")
	}
	if observedAt.IsZero() {
		return easl.Evidence{}, errors.New("kernel continuity observed_at is required")
	}
	if validFor <= 0 {
		return easl.Evidence{}, errors.New("kernel continuity validity must be positive")
	}
	if a.Status != EvidenceContinuityIntact && a.Status != EvidenceContinuityDegraded {
		return easl.Evidence{}, errors.New("unsupported kernel continuity status")
	}

	expiresAt := observedAt.UTC().Add(validFor)
	evidence := easl.Evidence{
		ID:         evidenceID,
		ObservedAt: observedAt.UTC(),
		ExpiresAt:  &expiresAt,
	}
	if a.Status == EvidenceContinuityDegraded {
		evidence.Contradicts = []easl.AssumptionID{continuityAssumption}
	}
	return evidence, nil
}
