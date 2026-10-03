# VCS-14 — Cross-Genesis Successor-Governance Authority Rotation

Status: **EXPERIMENTAL / EXECUTABLE UNIT AND FAILURE-ORDERING EVIDENCE**

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

- exact old and new Genesis epochs and manifest payload hashes;
- exact old and new capability-envelope hashes;
- exact old and new successor-governance policy hashes;
- exact old and new authority identities and public-key IDs;
- exact authority-head predecessor sequence, digest and logical key identity;
- journal identity;
- validity window.

Both the retiring authority and the incoming authority must sign the same canonical transition.

## Crash semantics

The transition is retryable without guessing.

- crash before freeze: A remains current;
- crash after authority freeze but before quorum handoff: neither A nor B is current;
- crash during quorum rotation: the existing quorum-rotation proof resumes only the same frozen head;
- crash after quorum handoff but before B activation: VCS-14 detects the exact frozen head on the new quorum and activates B without requiring the retired old quorum;
- retry after completion returns the same B head only for the exact transition whose digest the activated head retains;
- sequence exhaustion fails closed; interrupted handoff resumes only within the signed validity window.

A different transition cannot replace an already frozen transition.

## Execution and provenance boundary

This is a library protocol with executable proof callers, not a deployed runtime succession orchestrator. `VerifiedGenesisPin.ParseEnrollmentSuccessorGovernanceBinding` now carries the verified manifest hash as well as the epoch and envelope. Rotation rejects composition with a quorum plan from another manifest or envelope before any witness mutation. Low-level journal constructors require trusted inputs; they do not verify Genesis signatures themselves.

The two proposed wrappers that checked quorum authority and then performed TPM commit/capture have been removed. A prior userspace check cannot establish current authority at an independent destination commitment. No TPM effect-time fencing is claimed here.

Authorized convergence repairs readable minorities even when a target majority exists, and uses the witness's native policy-fenced CAS. Shared-handle convergence remains mandatory before quorum handoff. Unavailable shared witnesses can prevent safe progress; they are not silently bypassed.

## Counterexamples preserved

The old #230 head `f02826b395d85f06e3badda626997fb9f2b568f4` accepted mixed envelope/manifest provenance and attributed completed state to a different co-signed transition. Baseline output is retained in `testdata/successor-governance/baseline.log`; permanent executable regressions reject all three. Additional tests cover authority absence during interrupted handoff, manifest substitution despite valid co-signatures, sequence exhaustion, readable-minority convergence, and policy changes between convergence read and CAS.

## Upgrade and rollback

This reconciles an unmerged experimental protocol. Old experimental authorization payloads and authority-state digests must be regenerated with manifest and exact predecessor bindings. Do not downgrade a deployed head or reinitialize around retained history. No production data migration or physical TPM execution was performed.

## Claim boundary

The claim is exact successor-authority rotation composed with the existing governed quorum protocol under honest, policy-fenced witness custody and stable overlap assumptions. It is supported by executable unit and race tests, not physical hardware or independent reproduction. Arbitrary Genesis changes and an earlier authority check do not grant effect authority.
