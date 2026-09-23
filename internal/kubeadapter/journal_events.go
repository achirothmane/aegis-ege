package kubeadapter

import (
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
	"github.com/achirothmane/state-latch/internal/journal"
	"github.com/achirothmane/state-latch/internal/outcome"
)

func JournalAuthorizationEvent(auth decision.Authorization, occurredAt time.Time) journal.Event {
	return journal.Event{
		Type:           journal.EventAuthorization,
		ActionID:       auth.ActionID,
		Target:         auth.Target,
		Decision:       string(decision.Allow),
		EvidenceDigest: auth.EvidenceDigest,
		PlanDigest:     auth.PlanDigest,
		OccurredAt:     occurredAt.UTC(),
	}
}

func JournalExecutionEvent(
	auth decision.Authorization,
	report GuardedDrainExecutionReport,
	occurredAt time.Time,
) (journal.Event, error) {
	payloadDigest, err := journal.DigestPayload(report)
	if err != nil {
		return journal.Event{}, err
	}

	return journal.Event{
		Type:           journal.EventExecution,
		ActionID:       auth.ActionID,
		Target:         auth.Target,
		Decision:       string(report.Decision),
		ReasonCodes:    reasonCodeStrings(report.ReasonCodes),
		EvidenceDigest: auth.EvidenceDigest,
		PlanDigest:     report.PlanDigest,
		PayloadDigest:  payloadDigest,
		OccurredAt:     occurredAt.UTC(),
	}, nil
}

func JournalOutcomeEvent(record outcome.Record) (journal.Event, error) {
	payloadDigest, err := journal.DigestPayload(record)
	if err != nil {
		return journal.Event{}, err
	}

	return journal.Event{
		Type:           journal.EventOutcome,
		ActionID:       record.ActionID,
		EvidenceDigest: record.EvidenceDigest,
		PlanDigest:     record.PlanDigest,
		OutcomeVerdict: string(record.Verdict),
		PayloadDigest:  payloadDigest,
		OccurredAt:     record.ObservedAt.UTC(),
	}, nil
}

func reasonCodeStrings(reasons []decision.ReasonCode) []string {
	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, string(reason))
	}
	return out
}
