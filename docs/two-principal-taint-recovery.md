# Two-principal live taint recovery

Status: executable recovery-authority proof.

Source-continuity recovery is stronger than historical verification. It changes live kernel authority by advancing the admitted CLEAN watermark until it catches the monotonic DIRTY generation.

The recovery path therefore requires two distinct cryptographic principals over the exact same recovery authorization payload.

## Boundary

Historical and boot-bound recovery records may still use the existing single-signature envelope for evidence verification. They cannot be passed to `RecoverTaintSourceContinuity`.

Live recovery accepts only:

```text
TaintRecoveryAuthorization
        |
        +-- recovery authority signature
        |
        +-- independent recovery witness signature
        |
        v
joint authorization commitment
        |
        v
RecoverTaintSourceContinuity
        |
        v
epoch advance
        |
        v
CLEAN watermark advance
```

Both signatures use the joint-recovery domain separator and cover the same canonical authorization fields:

- activation-plan digest;
- cgroup identity;
- bpffs root;
- boot identity;
- exact DIRTY generation;
- current and next enrollment epoch;
- validity window;
- authorization identity.

The two public keys must resolve to distinct key IDs. Reusing the same key for both roles fails closed.

## Crash and replay semantics

The pinned `aegis_trecover` commitment now binds:

- joint-envelope version;
- exact authorization payload;
- recovery-authority key ID and signature;
- recovery-witness key ID and signature.

Therefore an interrupted recovery can be resumed only with the exact jointly signed authorization that began it. A second witness signature, a changed authorization identity, or another otherwise valid pair produces a different commitment and cannot claim the in-flight transition.

Existing ordering remains unchanged:

```text
joint authorization verified
        ↓
fresh kernel source observation
        ↓
candidate source map installed while DIRTY blocks effects
        ↓
second kernel observation
        ↓
exact joint commitment pinned
        ↓
epoch advances
        ↓
CLEAN advances last
```

## Native falsification

The existing privileged source-lifetime recovery schedule now removes only the witness signature from an otherwise valid joint authorization and calls the real live recovery path.

It requires all of the following to remain unchanged:

```text
DIRTY
CLEAN
enrollment epoch
source enrollment map
protected effect boundary
```

Protected egress must remain DENY.

The same schedule then presents the fully jointly signed authorization and continues through the already-proven pre-CLEAN crash/resume and post-CLEAN lost-reply reconciliation cases. This ensures the new authorization rule does not weaken exact-commitment crash recovery.

## Claim boundary

This proves that one cryptographic signing key alone is insufficient to authorize live source-continuity recovery in the tested Aegis recovery path.

It does not prove that the two private keys are controlled by two independent people, organizations, machines, accounts, or failure domains. The test harness generates both keys locally. Production independence requires provisioning the witness key outside the recovery authority's administrative and credential domain.

This change also does not create a new quorum protocol for journal witnesses or replace the existing majority-witness machinery. It is intentionally limited to the authority that can restore live `CLEAN` continuity.
