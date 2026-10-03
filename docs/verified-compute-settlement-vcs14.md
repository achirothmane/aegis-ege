# VCS-14 — Cross-Genesis Successor-Governance Authority Rotation

Status: **EXPERIMENTAL / FORMALIZED EXECUTION PROOF**

VCS-13 pinned one successor-governance authority to one verified Genesis epoch. VCS-14 proves continuity when that authority itself changes across Genesis epochs.

## Governing invariant

    ACTIVE(A, Genesis N)
        -> JOINT_FROZEN(exact transition)
        -> ACTIVE(B, Genesis N+1)

There is no admissible state in which A and B are simultaneously current authorities.

## Composite transition

The authority transition is deliberately coupled to the existing Genesis-bound witness quorum rotation:

    Authority A ACTIVE on old quorum
            |
            | A and B co-sign exact transition
            v
    Authority JOINT_FROZEN
            |
            | existing OLD -> JOINT_FROZEN -> NEW
            | quorum rotation preserves the exact authority head
            v
    same authority JOINT_FROZEN on new quorum
            |
            | activate only under target Genesis epoch
            v
    Authority B ACTIVE

The authority head lives at:

    governance/enrollment-successor-authority

and is stored through the governed external quorum head substrate.

## Rotation authorization

The signed rotation commits:

- exact old and new Genesis epochs;
- exact old and new capability-envelope hashes;
- exact old and new successor-governance policy hashes;
- exact old and new authority identities and public-key IDs;
- exact authority-head predecessor sequence;
- journal identity;
- validity window.

Both the retiring authority and the incoming authority must sign the same canonical transition.

## Crash semantics

The transition is retryable without guessing.

- crash before freeze: A remains current;
- crash after authority freeze but before quorum handoff: neither A nor B is current;
- crash during quorum rotation: the existing quorum-rotation proof resumes only the same frozen head;
- crash after quorum handoff but before B activation: VCS-14 detects the exact frozen head on the new quorum and activates B without requiring the retired old quorum;
- retry after completion returns the same B head.

A different transition cannot replace an already frozen transition.

## Execution boundary

VCS-14 adds rotation-aware wrappers for:

- TPM successor commit;
- verified-compute settlement root capture.

Those paths require the supplied Genesis successor-governance binding to still be the current authority published by the quorum head. A historically valid VCS-13 binding is therefore insufficient after rotation.

## Claim boundary

VCS-14 composes successor-governance authority rotation with the already-proven Genesis quorum-rotation substrate. It does not claim that arbitrary Genesis changes automatically rotate successor governance. Only the exact jointly signed transition carried through the frozen authority head and the governed quorum handoff grants the new authority.
