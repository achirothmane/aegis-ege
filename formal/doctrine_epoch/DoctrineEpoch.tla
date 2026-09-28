---- MODULE DoctrineEpoch ----
EXTENDS Naturals, FiniteSets

CONSTANTS
    Epochs,
    Signers,
    Quorum,
    FreezeTicks,
    MaxTime,
    MaxDecisions,
    MaxAmendments,
    MaxRestarts,
    InitialEpoch,
    NullEpoch

ASSUME /\ InitialEpoch \in Epochs
       /\ NullEpoch \notin Epochs
       /\ Quorum > 1
       /\ Quorum <= Cardinality(Signers)
       /\ FreezeTicks > 0
       /\ MaxTime > FreezeTicks
       /\ MaxDecisions > 0
       /\ MaxAmendments > 0
       /\ MaxRestarts > 0

EpochStatuses == {"CURRENT", "SUPERSEDED", "COMPROMISED", "REVOKED"}
ProposalStates == {"NONE", "FROZEN", "RATIFIED"}

VARIABLES
    now,
    activeEpoch,
    epochStatus,
    proposalEpoch,
    proposalState,
    proposedAt,
    approvals,
    halted,
    restartApprovals,

    decisionCount,
    lastDecisionEpoch,
    lastDecisionAdmissible,

    amendmentCount,
    lastAmendmentFreeze,
    lastAmendmentApprovals,

    restartCount,
    lastRestartApprovals

vars ==
    << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
       proposedAt, approvals, halted, restartApprovals,
       decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
       amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
       restartCount, lastRestartApprovals >>

Init ==
    /\ now = 0
    /\ activeEpoch = InitialEpoch
    /\ epochStatus =
        [e \in Epochs |-> IF e = InitialEpoch THEN "CURRENT" ELSE "SUPERSEDED"]
    /\ proposalEpoch = NullEpoch
    /\ proposalState = "NONE"
    /\ proposedAt = 0
    /\ approvals = {}
    /\ halted = FALSE
    /\ restartApprovals = {}

    /\ decisionCount = 0
    /\ lastDecisionEpoch = NullEpoch
    /\ lastDecisionAdmissible = TRUE

    /\ amendmentCount = 0
    /\ lastAmendmentFreeze = 0
    /\ lastAmendmentApprovals = 0

    /\ restartCount = 0
    /\ lastRestartApprovals = 0

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED << activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, halted, restartApprovals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

Propose(e) ==
    /\ e \in Epochs
    /\ e # activeEpoch
    /\ proposalState = "NONE"
    /\ epochStatus[e] # "COMPROMISED"
    /\ epochStatus[e] # "REVOKED"
    /\ proposalEpoch' = e
    /\ proposalState' = "FROZEN"
    /\ proposedAt' = now
    /\ approvals' = {}
    /\ UNCHANGED << now, activeEpoch, epochStatus, halted, restartApprovals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

Approve(s) ==
    /\ s \in Signers
    /\ proposalState = "FROZEN"
    /\ approvals' = approvals \cup {s}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, halted, restartApprovals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

Ratify ==
    /\ proposalState = "FROZEN"
    /\ Cardinality(approvals) >= Quorum
    /\ now - proposedAt >= FreezeTicks
    /\ proposalState' = "RATIFIED"
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposedAt,
                     approvals, halted, restartApprovals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

Activate ==
    /\ amendmentCount < MaxAmendments
    /\ proposalState = "RATIFIED"
    /\ now - proposedAt >= FreezeTicks
    /\ epochStatus[proposalEpoch] # "COMPROMISED"
    /\ epochStatus[proposalEpoch] # "REVOKED"

    /\ epochStatus' =
        [epochStatus EXCEPT
            ![activeEpoch] = "SUPERSEDED",
            ![proposalEpoch] = "CURRENT"]
    /\ activeEpoch' = proposalEpoch

    /\ amendmentCount' = amendmentCount + 1
    /\ lastAmendmentFreeze' = now - proposedAt
    /\ lastAmendmentApprovals' = Cardinality(approvals)

    /\ proposalEpoch' = NullEpoch
    /\ proposalState' = "NONE"
    /\ proposedAt' = 0
    /\ approvals' = {}

    /\ UNCHANGED << now, halted, restartApprovals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     restartCount, lastRestartApprovals >>

Compromise(e) ==
    /\ e \in Epochs
    /\ epochStatus[e] # "COMPROMISED"
    /\ epochStatus' = [epochStatus EXCEPT ![e] = "COMPROMISED"]
    /\ IF e = activeEpoch
          THEN /\ halted' = TRUE
               /\ restartApprovals' = {}
          ELSE /\ UNCHANGED << halted, restartApprovals >>
    /\ UNCHANGED << now, activeEpoch, proposalEpoch, proposalState, proposedAt,
                     approvals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

EmergencyHalt ==
    /\ ~halted
    /\ halted' = TRUE
    /\ restartApprovals' = {}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

ApproveRestart(s) ==
    /\ halted
    /\ s \in Signers
    /\ restartApprovals' = restartApprovals \cup {s}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, halted,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals,
                     restartCount, lastRestartApprovals >>

Restart ==
    /\ restartCount < MaxRestarts
    /\ halted
    /\ epochStatus[activeEpoch] = "CURRENT"
    /\ Cardinality(restartApprovals) >= Quorum

    /\ halted' = FALSE
    /\ restartCount' = restartCount + 1
    /\ lastRestartApprovals' = Cardinality(restartApprovals)
    /\ restartApprovals' = {}

    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals,
                     decisionCount, lastDecisionEpoch, lastDecisionAdmissible,
                     amendmentCount, lastAmendmentFreeze, lastAmendmentApprovals >>

AttemptExecute(authorityOK, evidenceOK, sectorOK) ==
    /\ authorityOK \in BOOLEAN
    /\ evidenceOK \in BOOLEAN
    /\ sectorOK \in BOOLEAN
    /\ IF decisionCount < MaxDecisions
          /\ ~halted
          /\ epochStatus[activeEpoch] = "CURRENT"
          /\ authorityOK
          /\ evidenceOK
          /\ sectorOK
       THEN /\ decisionCount' = decisionCount + 1
            /\ lastDecisionEpoch' = activeEpoch
            /\ lastDecisionAdmissible' =
                    authorityOK /\ evidenceOK /\ sectorOK
            /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch,
                             proposalState, proposedAt, approvals, halted,
                             restartApprovals,
                             amendmentCount, lastAmendmentFreeze,
                             lastAmendmentApprovals,
                             restartCount, lastRestartApprovals >>
       ELSE UNCHANGED vars

Next ==
    \/ Tick
    \/ \E e \in Epochs : Propose(e)
    \/ \E s \in Signers : Approve(s)
    \/ Ratify
    \/ Activate
    \/ \E e \in Epochs : Compromise(e)
    \/ EmergencyHalt
    \/ \E s \in Signers : ApproveRestart(s)
    \/ Restart
    \/ \E a \in BOOLEAN, ev \in BOOLEAN, si \in BOOLEAN :
          AttemptExecute(a, ev, si)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 0..MaxTime
    /\ activeEpoch \in Epochs
    /\ epochStatus \in [Epochs -> EpochStatuses]
    /\ proposalEpoch \in Epochs \cup {NullEpoch}
    /\ proposalState \in ProposalStates
    /\ proposedAt \in 0..MaxTime
    /\ approvals \subseteq Signers
    /\ halted \in BOOLEAN
    /\ restartApprovals \subseteq Signers

    /\ decisionCount \in 0..MaxDecisions
    /\ lastDecisionEpoch \in Epochs \cup {NullEpoch}
    /\ lastDecisionAdmissible \in BOOLEAN

    /\ amendmentCount \in 0..MaxAmendments
    /\ lastAmendmentFreeze \in Nat
    /\ lastAmendmentApprovals \in Nat

    /\ restartCount \in 0..MaxRestarts
    /\ lastRestartApprovals \in Nat

ExecutedOnlyWhenAdmissible ==
    (decisionCount = 0) \/ lastDecisionAdmissible

AmendmentRequiresFrozenVisibility ==
    (amendmentCount = 0)
    \/ /\ lastAmendmentFreeze >= FreezeTicks
       /\ lastAmendmentApprovals >= Quorum

RestartRequiresIndependentQuorum ==
    (restartCount = 0) \/ (lastRestartApprovals >= Quorum)

DecisionHistoryMonotonicAction ==
    decisionCount' >= decisionCount

AmendmentHistoryMonotonicAction ==
    amendmentCount' >= amendmentCount

RestartHistoryMonotonicAction ==
    restartCount' >= restartCount

DecisionHistoryAppendOnly ==
    [][DecisionHistoryMonotonicAction]_vars

AmendmentHistoryAppendOnly ==
    [][AmendmentHistoryMonotonicAction]_vars

RestartHistoryAppendOnly ==
    [][RestartHistoryMonotonicAction]_vars

NoNewActionUnderCompromisedEpochAction ==
    (epochStatus[activeEpoch] = "COMPROMISED")
    => decisionCount' = decisionCount

NoNewActionUnderCompromisedEpoch ==
    [][NoNewActionUnderCompromisedEpochAction]_vars

====
