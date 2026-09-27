package kernelfabric

import "bytes"

type Verdict uint32

const (
	VerdictDeny  Verdict = 0
	VerdictAllow Verdict = 1
)

type DenyReason uint32

const (
	DenyNone DenyReason = iota
	DenyMissingFence
	DenyMissingCapsule
	DenyBootMismatch
	DenyAuthorityTermMismatch
	DenyDecisionSuperseded
	DenyRevoked
	DenyExpired
	DenyBlocked
)

type Evaluation struct {
	Verdict Verdict
	Reason  DenyReason
}

func EvaluateReference(
	capsule *DecisionCapsule,
	fence *ScopeFenceState,
	nowMonoNS uint64,
) Evaluation {
	if fence == nil {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyMissingFence}
	}
	if capsule == nil {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyMissingCapsule}
	}
	if !bytes.Equal(capsule.BootIDHash[:], fence.BootIDHash[:]) {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyBootMismatch}
	}
	if capsule.AuthorityTerm != fence.AuthorityTerm {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyAuthorityTermMismatch}
	}
	if capsule.DecisionEpoch != fence.DecisionEpoch {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyDecisionSuperseded}
	}
	if capsule.RevocationEpoch != fence.RevocationEpoch {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyRevoked}
	}
	if capsule.DeadlineMonoNS == 0 || nowMonoNS > capsule.DeadlineMonoNS {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyExpired}
	}
	if capsule.Decision != KernelDecisionAllow {
		return Evaluation{Verdict: VerdictDeny, Reason: DenyBlocked}
	}
	return Evaluation{Verdict: VerdictAllow, Reason: DenyNone}
}
