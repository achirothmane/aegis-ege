package computesettlement

import (
	"time"

	"github.com/achirothmane/aegis-ege/internal/outcome"
)

// Disposition is a commercial reconciliation result owned by the compute
// adapter. It is intentionally not part of the governance kernel contract.
type Disposition string

const (
	Settled   Disposition = "SETTLED"
	CreditDue Disposition = "CREDIT_DUE"
	Disputed  Disposition = "DISPUTED"
	Unknown   Disposition = "UNKNOWN"
)

// Observation is one post-execution view of the measurable contract facts.
// Facts remain opaque to the kernel; the adapter chooses their domain meaning.
type Observation struct {
	Source         string
	EvidenceDigest string
	Facts          map[string]string
	Contributors   []outcome.Contributor
	ObservedAt     time.Time
}

// Reconciliation preserves every source comparison so the settlement result
// can be audited back to the generic outcome primitive.
type Reconciliation struct {
	Disposition Disposition
	Records     []outcome.Record
	Detail      string
}

// Reconcile compares each observation with the same immutable contract facts.
// The generic kernel primitive classifies MATCH/DIVERGED/UNKNOWN. This adapter
// then applies the minimal commercial policy needed by VCS-01:
//
//   - any incomplete/UNKNOWN observation => UNKNOWN;
//   - mixed MATCH and DIVERGED => DISPUTED;
//   - all MATCH => SETTLED;
//   - all sources agree on the same divergent facts => CREDIT_DUE;
//   - divergent sources that disagree with each other => DISPUTED.
//
// No GPU, topology, ECC, metering, price or SLA semantics are embedded here.
func Reconcile(
	actionID string,
	planDigest string,
	contractFacts map[string]string,
	observations []Observation,
) Reconciliation {
	if len(observations) == 0 {
		return Reconciliation{
			Disposition: Unknown,
			Detail:      "no settlement observations",
		}
	}

	records := make([]outcome.Record, 0, len(observations))
	matches := 0
	divergences := 0

	for _, observation := range observations {
		if observation.Source == "" ||
			observation.EvidenceDigest == "" ||
			observation.ObservedAt.IsZero() {
			return Reconciliation{
				Disposition: Unknown,
				Records:     records,
				Detail:      "incomplete evidence provenance",
			}
		}

		record := outcome.Compare(
			actionID,
			observation.EvidenceDigest,
			planDigest,
			contractFacts,
			observation.Facts,
			observation.Contributors,
			observation.ObservedAt,
		)
		records = append(records, record)

		switch record.Verdict {
		case outcome.Match:
			matches++
		case outcome.Diverged:
			divergences++
		case outcome.Unknown:
			return Reconciliation{
				Disposition: Unknown,
				Records:     records,
				Detail:      "at least one source cannot establish the contracted facts",
			}
		default:
			return Reconciliation{
				Disposition: Unknown,
				Records:     records,
				Detail:      "unsupported outcome verdict",
			}
		}
	}

	switch {
	case matches == len(records):
		return Reconciliation{
			Disposition: Settled,
			Records:     records,
			Detail:      "all observations match the contracted facts",
		}
	case matches > 0 && divergences > 0:
		return Reconciliation{
			Disposition: Disputed,
			Records:     records,
			Detail:      "post-execution observations contradict on contract satisfaction",
		}
	case divergences == len(records):
		if observationsAgree(observations) {
			return Reconciliation{
				Disposition: CreditDue,
				Records:     records,
				Detail:      "all observations agree on the same contract divergence",
			}
		}
		return Reconciliation{
			Disposition: Disputed,
			Records:     records,
			Detail:      "observations agree that the contract diverged but disagree on delivered facts",
		}
	default:
		return Reconciliation{
			Disposition: Unknown,
			Records:     records,
			Detail:      "settlement state is not established",
		}
	}
}

func observationsAgree(observations []Observation) bool {
	if len(observations) < 2 {
		return true
	}
	reference := observations[0].Facts
	for _, observation := range observations[1:] {
		if !factsEqual(reference, observation.Facts) {
			return false
		}
	}
	return true
}

func factsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
