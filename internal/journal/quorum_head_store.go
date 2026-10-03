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

type QuorumTrustIdentityProvider interface {
	QuorumTrustManifestHash() string
}

type QuorumHeadStore struct {
	members    []QuorumHeadMember
	threshold  int
	policyHash string
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
	Protocol   string                     `json:"protocol"`
	PolicyHash string                     `json:"policy_hash"`
	Threshold  int                        `json:"threshold"`
	Members    []quorumMemberStoreVersion `json:"members"`
}

type quorumMemberStoreVersion struct {
	MemberID     string `json:"member_id"`
	StoreVersion string `json:"store_version"`
}

func NewQuorumHeadStore(
	members []QuorumHeadMember,
	binding GenesisQuorumBinding,
) (*QuorumHeadStore, error) {
	if len(binding.members) == 0 ||
		binding.threshold <= len(binding.members)/2 ||
		binding.threshold > len(binding.members) ||
		!validSHA256Digest(binding.policyHash) ||
		!validSHA256Digest(binding.capabilityEnvelopeHash) {
		return nil, errors.New("valid Genesis quorum binding is required")
	}
	if len(members) != len(binding.members) {
		return nil, fmt.Errorf(
			"quorum membership does not match Genesis binding: configured=%d governed=%d",
			len(members),
			len(binding.members),
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
		wantTrustManifestHash, ok := binding.members[member.ID]
		if !ok {
			return nil, fmt.Errorf(
				"quorum witness %q is not authorized by Genesis binding",
				member.ID,
			)
		}
		identityProvider, ok := member.Store.(QuorumTrustIdentityProvider)
		if !ok {
			return nil, fmt.Errorf(
				"quorum witness %q store does not expose a governed trust identity",
				member.ID,
			)
		}
		actualTrustManifestHash := strings.TrimSpace(
			identityProvider.QuorumTrustManifestHash(),
		)
		if actualTrustManifestHash != wantTrustManifestHash {
			return nil, fmt.Errorf(
				"quorum witness %q store trust manifest hash %s does not match Genesis binding %s",
				member.ID,
				actualTrustManifestHash,
				wantTrustManifestHash,
			)
		}
		copied = append(copied, member)
	}
	sort.Slice(copied, func(i, j int) bool { return copied[i].ID < copied[j].ID })
	return &QuorumHeadStore{
		members:    copied,
		threshold:  binding.threshold,
		policyHash: binding.policyHash,
	}, nil
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
					return aggregateQuorumHead(semantic, groups[semantic], s.threshold, s.policyHash)
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
				s.policyHash,
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

// ConvergeAuthorizedTransition repairs a split quorum only when every
// readable member is inside an explicitly authorized transition chain.
//
// This is intentionally stronger than normal CompareAndAdvance recovery:
// callers must supply the exact finite set of admissible states and the exact
// target. Any readable third state fails closed. At least a strict majority of
// members must be readable and inside the chain before convergence is allowed.
//
// It is designed for higher-level signed recovery protocols where a process
// interruption may have left different quorum members at successive states of
// the same already-authorized transition.
func (s *QuorumHeadStore) ConvergeAuthorizedTransition(
	ctx context.Context,
	allowed []ExternalHead,
	target ExternalHead,
) (ExternalHead, error) {
	if s == nil || len(s.members) == 0 {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	if strings.TrimSpace(target.JournalID) == "" || len(allowed) == 0 {
		return ExternalHead{}, ErrExternalHeadConflict
	}

	allowedSet := make(map[quorumSemanticHead]struct{}, len(allowed))
	targetSemantic := semanticExternalHead(target)
	targetAllowed := false
	for _, head := range allowed {
		semantic := semanticExternalHead(head)
		if semantic.JournalID != target.JournalID ||
			semantic.Sequence > target.Sequence {
			return ExternalHead{}, ErrExternalHeadConflict
		}
		allowedSet[semantic] = struct{}{}
		if semantic == targetSemantic {
			targetAllowed = true
		}
	}
	if !targetAllowed {
		return ExternalHead{}, ErrExternalHeadConflict
	}

	results := s.loadAll(ctx, target.JournalID)
	observations := make([]quorumMemberObservation, 0, len(s.members))
	targetObservations := make([]quorumMemberObservation, 0, len(s.members))

	for remaining := len(s.members); remaining > 0; remaining-- {
		select {
		case <-ctx.Done():
			return ExternalHead{}, fmt.Errorf("%w: %v", ErrExternalHeadQuorum, ctx.Err())
		case observation := <-results:
			if observation.err != nil || observation.notFound {
				continue
			}
			semantic := semanticExternalHead(observation.head)
			if _, ok := allowedSet[semantic]; !ok {
				return ExternalHead{}, fmt.Errorf(
					"%w: witness %q is outside authorized transition chain",
					ErrExternalHeadConflict,
					observation.member.ID,
				)
			}
			observations = append(observations, observation)
			if semantic == targetSemantic {
				targetObservations = append(targetObservations, observation)
			}
		}
	}

	if len(observations) < s.threshold {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	if len(targetObservations) >= s.threshold {
		return aggregateQuorumHead(targetSemantic, targetObservations, s.threshold)
	}

	advanceResults := make(chan quorumAdvanceResult, len(observations))
	pending := 0
	for _, observation := range observations {
		if semanticExternalHead(observation.head) == targetSemantic {
			continue
		}
		pending++
		observation := observation
		go func() {
			memberTarget := target
			memberTarget.StoreVersion = ""
			head, err := observation.member.Store.CompareAndAdvance(
				ctx,
				observation.head,
				memberTarget,
			)
			advanceResults <- quorumAdvanceResult{
				member: observation.member,
				head:   head,
				err:    err,
			}
		}()
	}

	successes := append([]quorumMemberObservation(nil), targetObservations...)
	for pending > 0 {
		select {
		case <-ctx.Done():
			return ExternalHead{}, fmt.Errorf("%w: %v", ErrExternalHeadQuorum, ctx.Err())
		case result := <-advanceResults:
			pending--
			if result.err != nil || !sameSemanticHead(result.head, target) {
				continue
			}
			successes = append(successes, quorumMemberObservation{
				member: result.member,
				head:   result.head,
			})
		}
	}
	if len(successes) < s.threshold {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	return aggregateQuorumHead(targetSemantic, successes, s.threshold)
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
	policyHash string,
) (ExternalHead, error) {
	if len(observations) < threshold {
		return ExternalHead{}, ErrExternalHeadQuorum
	}
	version, err := encodeQuorumStoreVersion(observations, threshold, policyHash)
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
	policyHash string,
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
		Protocol:   quorumHeadStoreVersion,
		PolicyHash: policyHash,
		Threshold:  threshold,
		Members:    members,
	})
	if err != nil {
		return "", fmt.Errorf("encode quorum store version: %w", err)
	}
	return quorumHeadStoreVersion + ":" +
		base64.RawURLEncoding.EncodeToString(payload), nil
}
