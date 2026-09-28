---- MODULE DoctrineEpoch ----
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Epochs, Signers, Quorum, FreezeTicks, InitialEpoch, NullEpoch

ASSUME /\ InitialEpoch \in Epochs
       /\ NullEpoch \notin Epochs
       /\ Quorum > 1
       /\ Quorum <= Cardinality(Signers)
       /\ FreezeTicks > 0

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
    decisionLog,
    amendmentLog,
    restartLog

vars ==
    << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
       proposedAt, approvals, halted, restartApprovals,
       decisionLog, amendmentLog, restartLog >>

DecisionRecordSet ==
    [ epoch : Epochs,
      authority : BOOLEAN,
      evidence : BOOLEAN,
      sector_isolated : BOOLEAN,
      epoch_status_at_execution : EpochStatuses ]

AmendmentRecordSet ==
    [ from_epoch : Epochs,
      to_epoch : Epochs,
      freeze_elapsed : Nat,
      approval_count : Nat ]

RestartRecordSet ==
    [ epoch : Epochs,
      approval_count : Nat ]

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
    /\ decisionLog = <<>>
    /\ amendmentLog = <<>>
    /\ restartLog = <<>>

Tick ==
    /\ now' = now + 1
    /\ UNCHANGED << activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, halted, restartApprovals,
                     decisionLog, amendmentLog, restartLog >>

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
                     decisionLog, amendmentLog, restartLog >>

Approve(s) ==
    /\ s \in Signers
    /\ proposalState = "FROZEN"
    /\ approvals' = approvals \cup {s}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, halted, restartApprovals,
                     decisionLog, amendmentLog, restartLog >>

Ratify ==
    /\ proposalState = "FROZEN"
    /\ Cardinality(approvals) >= Quorum
    /\ now - proposedAt >= FreezeTicks
    /\ proposalState' = "RATIFIED"
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposedAt,
                     approvals, halted, restartApprovals,
                     decisionLog, amendmentLog, restartLog >>

Activate ==
    /\ proposalState = "RATIFIED"
    /\ now - proposedAt >= FreezeTicks
    /\ epochStatus[proposalEpoch] # "COMPROMISED"
    /\ epochStatus[proposalEpoch] # "REVOKED"
    /\ amendmentLog' =
        Append(amendmentLog,
            [ from_epoch |-> activeEpoch,
              to_epoch |-> proposalEpoch,
              freeze_elapsed |-> now - proposedAt,
              approval_count |-> Cardinality(approvals) ])
    /\ epochStatus' =
        [epochStatus EXCEPT
            ![activeEpoch] = "SUPERSEDED",
            ![proposalEpoch] = "CURRENT"]
    /\ activeEpoch' = proposalEpoch
    /\ proposalEpoch' = NullEpoch
    /\ proposalState' = "NONE"
    /\ proposedAt' = 0
    /\ approvals' = {}
    /\ UNCHANGED << now, halted, restartApprovals, decisionLog, restartLog >>

Compromise(e) ==
    /\ e \in Epochs
    /\ epochStatus[e] # "COMPROMISED"
    /\ epochStatus' = [epochStatus EXCEPT ![e] = "COMPROMISED"]
    /\ IF e = activeEpoch
          THEN /\ halted' = TRUE
               /\ restartApprovals' = {}
          ELSE /\ UNCHANGED << halted, restartApprovals >>
    /\ UNCHANGED << now, activeEpoch, proposalEpoch, proposalState, proposedAt,
                     approvals, decisionLog, amendmentLog, restartLog >>

EmergencyHalt ==
    /\ ~halted
    /\ halted' = TRUE
    /\ restartApprovals' = {}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, decisionLog, amendmentLog, restartLog >>

ApproveRestart(s) ==
    /\ halted
    /\ s \in Signers
    /\ restartApprovals' = restartApprovals \cup {s}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, halted,
                     decisionLog, amendmentLog, restartLog >>

Restart ==
    /\ halted
    /\ epochStatus[activeEpoch] = "CURRENT"
    /\ Cardinality(restartApprovals) >= Quorum
    /\ halted' = FALSE
    /\ restartLog' =
        Append(restartLog,
            [ epoch |-> activeEpoch,
              approval_count |-> Cardinality(restartApprovals) ])
    /\ restartApprovals' = {}
    /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch, proposalState,
                     proposedAt, approvals, decisionLog, amendmentLog >>

AttemptExecute(authorityOK, evidenceOK, sectorOK) ==
    /\ authorityOK \in BOOLEAN
    /\ evidenceOK \in BOOLEAN
    /\ sectorOK \in BOOLEAN
    /\ IF ~halted
          /\ epochStatus[activeEpoch] = "CURRENT"
          /\ authorityOK
          /\ evidenceOK
          /\ sectorOK
       THEN /\ decisionLog' =
                    Append(decisionLog,
                        [ epoch |-> activeEpoch,
                          authority |-> authorityOK,
                          evidence |-> evidenceOK,
                          sector_isolated |-> sectorOK,
                          epoch_status_at_execution |-> epochStatus[activeEpoch] ])
            /\ UNCHANGED << now, activeEpoch, epochStatus, proposalEpoch,
                             proposalState, proposedAt, approvals, halted,
                             restartApprovals, amendmentLog, restartLog >>
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
    /\ now \in Nat
    /\ activeEpoch \in Epochs
    /\ epochStatus \in [Epochs -> EpochStatuses]
    /\ proposalEpoch \in Epochs \cup {NullEpoch}
    /\ proposalState \in ProposalStates
    /\ proposedAt \in Nat
    /\ approvals \subseteq Signers
    /\ halted \in BOOLEAN
    /\ restartApprovals \subseteq Signers
    /\ decisionLog \in Seq(DecisionRecordSet)
    /\ amendmentLog \in Seq(AmendmentRecordSet)
    /\ restartLog \in Seq(RestartRecordSet)

ExecutedOnlyWhenAdmissible ==
    \A i \in 1..Len(decisionLog) :
        /\ decisionLog[i].authority = TRUE
        /\ decisionLog[i].evidence = TRUE
        /\ decisionLog[i].sector_isolated = TRUE
        /\ decisionLog[i].epoch_status_at_execution = "CURRENT"

AmendmentRequiresFrozenVisibility ==
    \A i \in 1..Len(amendmentLog) :
        /\ amendmentLog[i].freeze_elapsed >= FreezeTicks
        /\ amendmentLog[i].approval_count >= Quorum

RestartRequiresIndependentQuorum ==
    \A i \in 1..Len(restartLog) :
        restartLog[i].approval_count >= Quorum

DecisionHistoryMonotonic ==
    Len(decisionLog') >= Len(decisionLog)

AmendmentHistoryMonotonic ==
    Len(amendmentLog') >= Len(amendmentLog)

RestartHistoryMonotonic ==
    Len(restartLog') >= Len(restartLog)

DecisionHistoryAppendOnly == [][DecisionHistoryMonotonic]_vars
AmendmentHistoryAppendOnly == [][AmendmentHistoryMonotonic]_vars
RestartHistoryAppendOnly == [][RestartHistoryMonotonic]_vars

NoNewActionUnderCompromisedEpochAction ==
    (epochStatus[activeEpoch] = "COMPROMISED")
    => decisionLog' = decisionLog

NoNewActionUnderCompromisedEpoch ==
    [][NoNewActionUnderCompromisedEpochAction]_vars

====
