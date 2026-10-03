package journal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const quorumHeadStoreVersion = "aegis-ege/quorum-head-store/v1"

var ErrExternalHeadQuorum = errors.New("external journal head quorum unavailable")

type QuorumHeadMember struct {
	ID    string
	Store ExternalHeadStore
}

type QuorumHeadStore struct {
	members   []QuorumHeadMember
	threshold int
}

type quorumSemanticHead struct {
	JournalID string
	Sequence  uint64
	HeadHash  string
	KeyID     string
}

type quorumMemberObservation struct {
	member   QuorumHeadMember
	head     ExternalHead
	err      error
	notFound bool
}

type quorumAdvanceResult struct {
	member QuorumHeadMember
	head   ExternalHead
	err    error
}

type quorumStoreVersion struct {
	Protocol  string                     `json:"protocol"`
	Threshold int                        `json:"threshold"`
	Members   []quorumMemberStoreVersion `json:"members"`
}

type quorumMemberStoreVersion struct {
	MemberID     string `json:"member_id"`
	StoreVersion string `json:"store_version"`
}

func NewQuorumHeadStore(members []QuorumHeadMember, threshold int) (*QuorumHeadStore, error) {
	if len(members) == 0 {
		return nil, errors.New("quorum head store requires members")
	}
	if threshold <= len(members)/2 || threshold > len(members) {
		return nil, fmt.Errorf(
			"quorum threshold must be a strict majority: members=%d threshold=%d",
			len(members),
			threshold,
		)
	}
	seen := make(map[string]struct{}, len(members))
	copied := make([]QuorumHeadMember, 0, len(members))
	for _, member := range members {
		member.ID = strings.TrimSpace(member.ID)
		if member.ID == "" {
			return nil, errors.New("quorum witness member id is required")
		}
		if member.Store == nil {
			return nil, fmt.Errorf("quorum witness %q store is required", member.ID)
		}
		if _, ok := seen[member.ID]; ok {
			return nil, fmt.Errorf("duplicate quorum witness member id %q", member.ID)
		}
		seen[member.ID] = struct{}{}
		copied = append(copied, member)
	}
	sort.Slice(copied, func(i, j int) bool { return copied[i].ID < copied[j].ID })
	return &QuorumHeadStore{members: copied, threshold: threshold}, nil
}

func (s *QuorumHeadStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	if s == nil || len(s.members) == 0 {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	journalID = strings.TrimSpace(journalID)
	if journalID == "" {
		return ExternalHead{}, errors.New("journal id is required")
	}

	results := s.loadAll(ctx, journalID)
	groups := make(map[quorumSemanticHead][]quorumMemberObservation)
	notFound := 0
	remaining := len(s.members)

	for remaining > 0 {
		select {
		case <-ctx.Done():
			return ExternalHead{}, fmt.Errorf("%w: %v", ErrExternalHeadQuorum, ctx.Err())
		case observation := <-results:
			remaining--
			switch {
			case observation.notFound:
				notFound++
				if notFound >= s.threshold {
					return ExternalHead{}, ErrExternalHeadNotFound
				}
			case observation.err != nil:
				// A minority witness can be unavailable or malformed without
				// changing the quorum state.
			default:
				semantic := semanticExternalHead(observation.head)
				if semantic.JournalID != journalID {
					continue
				}
				groups[semantic] = append(groups[semantic], observation)
				if len(groups[semantic]) >= s.threshold {
					return aggregateQuorumHead(semantic, groups[semantic], s.threshold)
				}
			}
		}
	}

	return ExternalHead{}, ErrExternalHeadQuorum
}

func (s *QuorumHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if s == nil || len(s.members) == 0 {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	if strings.TrimSpace(next.JournalID) == "" {
		return ExternalHead{}, errors.New("journal id is required")
	}
	if previous.JournalID != "" && previous.JournalID != next.JournalID {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if previous.JournalID == "" {
		if next.Sequence != 0 {
			return ExternalHead{}, ErrExternalHeadConflict
		}
	} else {
		if next.Sequence < previous.Sequence {
			return ExternalHead{}, ErrExternalHeadConflict
		}
		if next.Sequence == previous.Sequence &&
			(next.HeadHash != previous.HeadHash || next.KeyID != previous.KeyID) {
			return ExternalHead{}, ErrExternalHeadConflict
		}
	}

	loadResults := s.loadAll(ctx, next.JournalID)
	advanceResults := make(chan quorumAdvanceResult, len(s.members))
	candidates := make([]quorumMemberObservation, 0, len(s.members))
	launched := make(map[string]struct{}, len(s.members))
	successes := make([]quorumMemberObservation, 0, s.threshold)
	loadReturned := 0
	advancePending := 0
	quorumEstablished := false

	launch := func(observation quorumMemberObservation) {
		if _, ok := launched[observation.member.ID]; ok {
			return
		}
		launched[observation.member.ID] = struct{}{}
		advancePending++
		go func() {
			memberPrevious := ExternalHead{}
			if !observation.notFound {
				memberPrevious = observation.head
			}
			memberNext := next
			memberNext.StoreVersion = ""
			head, err := observation.member.Store.CompareAndAdvance(
				ctx,
				memberPrevious,
				memberNext,
			)
			advanceResults <- quorumAdvanceResult{
				member: observation.member,
				head:   head,
				err:    err,
			}
		}()
	}

	for {
		if len(successes) >= s.threshold {
			return aggregateQuorumHead(
				semanticExternalHead(next),
				successes,
				s.threshold,
			)
		}
		if loadReturned == len(s.members) && advancePending == 0 {
			if !quorumEstablished {
				return ExternalHead{}, ErrExternalHeadConflict
			}
			return ExternalHead{}, ErrExternalHeadQuorum
		}

		select {
		case <-ctx.Done():
			return ExternalHead{}, fmt.Errorf("%w: %v", ErrExternalHeadQuorum, ctx.Err())

		case observation := <-loadResults:
			loadReturned++
			if observationMatchesExpected(observation, previous) {
				candidates = append(candidates, observation)
				if quorumEstablished {
					launch(observation)
				} else if len(candidates) >= s.threshold {
					quorumEstablished = true
					for _, candidate := range candidates {
						launch(candidate)
					}
				}
			}
			if !quorumEstablished &&
				len(candidates)+(len(s.members)-loadReturned) < s.threshold {
				return ExternalHead{}, ErrExternalHeadConflict
			}

		case result := <-advanceResults:
			advancePending--
			if result.err != nil {
				continue
			}
			if !sameSemanticHead(result.head, next) {
				continue
			}
			successes = append(successes, quorumMemberObservation{
				member: result.member,
				head:   result.head,
			})
		}
	}
}

func (s *QuorumHeadStore) loadAll(
	ctx context.Context,
	journalID string,
) <-chan quorumMemberObservation {
	results := make(chan quorumMemberObservation, len(s.members))
	for _, member := range s.members {
		member := member
		go func() {
			head, err := member.Store.Load(ctx, journalID)
			results <- quorumMemberObservation{
				member:   member,
				head:     head,
				err:      err,
				notFound: errors.Is(err, ErrExternalHeadNotFound),
			}
		}()
	}
	return results
}

func observationMatchesExpected(
	observation quorumMemberObservation,
	expected ExternalHead,
) bool {
	if expected.JournalID == "" {
		return observation.notFound
	}
	if observation.err != nil || observation.notFound {
		return false
	}
	return sameSemanticHead(observation.head, expected)
}

func sameSemanticHead(left ExternalHead, right ExternalHead) bool {
	return semanticExternalHead(left) == semanticExternalHead(right)
}

func semanticExternalHead(head ExternalHead) quorumSemanticHead {
	return quorumSemanticHead{
		JournalID: head.JournalID,
		Sequence:  head.Sequence,
		HeadHash:  head.HeadHash,
		KeyID:     head.KeyID,
	}
}

func aggregateQuorumHead(
	semantic quorumSemanticHead,
	observations []quorumMemberObservation,
	threshold int,
) (ExternalHead, error) {
	if len(observations) < threshold {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	version, err := encodeQuorumStoreVersion(observations, threshold)
	if err != nil {
		return ExternalHead{}, err
	}
	return ExternalHead{
		JournalID:    semantic.JournalID,
		Sequence:     semantic.Sequence,
		HeadHash:     semantic.HeadHash,
		KeyID:        semantic.KeyID,
		StoreVersion: version,
	}, nil
}

func encodeQuorumStoreVersion(
	observations []quorumMemberObservation,
	threshold int,
) (string, error) {
	members := make([]quorumMemberStoreVersion, 0, len(observations))
	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if _, ok := seen[observation.member.ID]; ok {
			continue
		}
		seen[observation.member.ID] = struct{}{}
		members = append(members, quorumMemberStoreVersion{
			MemberID:     observation.member.ID,
			StoreVersion: observation.head.StoreVersion,
		})
	}
	sort.Slice(members, func(i, j int) bool {
		return members[i].MemberID < members[j].MemberID
	})
	payload, err := json.Marshal(quorumStoreVersion{
		Protocol:  quorumHeadStoreVersion,
		Threshold: threshold,
		Members:   members,
	})
	if err != nil {
		return "", fmt.Errorf("encode quorum store version: %w", err)
	}
	return quorumHeadStoreVersion + ":" +
		base64.RawURLEncoding.EncodeToString(payload), nil
}
