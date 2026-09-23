package outcome

import (
	"sort"
	"sync"
	"time"
)

type Verdict string

const (
	Match    Verdict = "MATCH"
	Diverged Verdict = "DIVERGED"
	Unknown  Verdict = "UNKNOWN"
)

type ContributorKind string

const (
	ContributorSource     ContributorKind = "SOURCE"
	ContributorAssumption ContributorKind = "ASSUMPTION"
)

type Contributor struct {
	Kind ContributorKind
	ID   string
}

type Attribution string

const (
	AttributionUnattributed          Attribution = "UNATTRIBUTED"
	AttributionContributors          Attribution = "CONTRIBUTOR_ATTRIBUTABLE"
)

func (c Contributor) Key() string {
	return string(c.Kind) + "/" + c.ID
}

type Record struct {
	ActionID       string
	EvidenceDigest string
	PlanDigest     string
	Expected       map[string]string
	Observed       map[string]string
	Verdict        Verdict
	Contributors   []Contributor
	Attribution    Attribution
	ObservedAt     time.Time
	Detail         string
}

func Compare(
	actionID string,
	evidenceDigest string,
	planDigest string,
	expected map[string]string,
	observed map[string]string,
	contributors []Contributor,
	observedAt time.Time,
) Record {
	record := Record{
		ActionID:       actionID,
		EvidenceDigest: evidenceDigest,
		PlanDigest:     planDigest,
		Expected:       cloneFacts(expected),
		Observed:       cloneFacts(observed),
		Contributors:   append([]Contributor(nil), contributors...),
		ObservedAt:     observedAt.UTC(),
		Verdict:        Match,
	}

	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		want := expected[key]
		got, ok := observed[key]
		if !ok {
			record.Verdict = Unknown
			record.Detail = "missing observed fact: " + key
			return record
		}
		if got != want {
			record.Verdict = Diverged
			record.Detail = "fact diverged: " + key + " expected=" + want + " observed=" + got
			return record
		}
	}

	return record
}

func cloneFacts(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

type AdvisoryStatus string

const (
	AdvisoryInsufficientHistory AdvisoryStatus = "INSUFFICIENT_HISTORY"
	AdvisoryHealthy             AdvisoryStatus = "HEALTHY"
	AdvisoryDegraded            AdvisoryStatus = "DEGRADED"
)

type AdvisoryPolicy struct {
	MinResolvedSamples int
	MaxDivergenceRate  float64
}

type ReliabilitySnapshot struct {
	Contributor     Contributor
	Matches         int
	Divergences     int
	Unknowns        int
	Unattributed    int
	ResolvedSamples int
	DivergenceRate  float64
	Reliability     float64
	Status          AdvisoryStatus
}

type counters struct {
	matches      int
	divergences  int
	unknowns     int
	unattributed int
}

type Ledger struct {
	mu      sync.RWMutex
	policy  AdvisoryPolicy
	records []Record
	counts  map[string]counters
	refs    map[string]Contributor
}

func NewLedger(policy AdvisoryPolicy) *Ledger {
	return &Ledger{
		policy: policy,
		counts: make(map[string]counters),
		refs:   make(map[string]Contributor),
	}
}

func (l *Ledger) Record(record Record) {
	l.mu.Lock()
	defer l.mu.Unlock()

	record.Expected = cloneFacts(record.Expected)
	record.Observed = cloneFacts(record.Observed)
	record.Contributors = append([]Contributor(nil), record.Contributors...)
	l.records = append(l.records, record)

	seen := make(map[string]struct{}, len(record.Contributors))
	for _, contributor := range record.Contributors {
		if contributor.ID == "" {
			continue
		}
		key := contributor.Key()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		l.refs[key] = contributor

		count := l.counts[key]
		if record.Attribution != AttributionContributors {
			count.unattributed++
			l.counts[key] = count
			continue
		}
		switch record.Verdict {
		case Match:
			count.matches++
		case Diverged:
			count.divergences++
		default:
			count.unknowns++
		}
		l.counts[key] = count
	}
}

func (l *Ledger) Snapshot(contributor Contributor) ReliabilitySnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()

	count := l.counts[contributor.Key()]
	resolved := count.matches + count.divergences
	snapshot := ReliabilitySnapshot{
		Contributor:     contributor,
		Matches:         count.matches,
		Divergences:     count.divergences,
		Unknowns:        count.unknowns,
		Unattributed:    count.unattributed,
		ResolvedSamples: resolved,
		Status:          AdvisoryInsufficientHistory,
	}

	if resolved > 0 {
		snapshot.DivergenceRate = float64(count.divergences) / float64(resolved)
		snapshot.Reliability = 1 - snapshot.DivergenceRate
	}

	if l.policy.MinResolvedSamples <= 0 || resolved < l.policy.MinResolvedSamples {
		return snapshot
	}
	if snapshot.DivergenceRate > l.policy.MaxDivergenceRate {
		snapshot.Status = AdvisoryDegraded
	} else {
		snapshot.Status = AdvisoryHealthy
	}
	return snapshot
}

func (l *Ledger) Records() []Record {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]Record, 0, len(l.records))
	for _, record := range l.records {
		copyRecord := record
		copyRecord.Expected = cloneFacts(record.Expected)
		copyRecord.Observed = cloneFacts(record.Observed)
		copyRecord.Contributors = append([]Contributor(nil), record.Contributors...)
		out = append(out, copyRecord)
	}
	return out
}
