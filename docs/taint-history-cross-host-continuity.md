# Cross-host recovery-history continuity

The local TPM monotonic anchor prevents rollback while the same TPM remains trustworthy. It does not by itself preserve historical continuity if the TPM is replaced, cleared, or the entire host is rebuilt.

This proof composes two independent monotonic roots:

```text
local TPM NV anchor
        +
independent external witness quorum
        ↓
conjunctive recovery-history anchor
```

The accepted state exists only when both roots agree on the exact pair:

```text
(sequence, recovery_history_head_digest)
```

## External witness

The external side uses `journal.QuorumHeadStore`, so the witness is not a single mutable record. A strict majority must agree on the same semantic head.

The recovery-history adapter stores:

- a stable history ID;
- monotonic sequence;
- exact SHA-256 history-head digest;
- a protocol-specific key ID.

A missing external head maps only to the true sequence-zero state. Once a quorum has committed a nonzero head, a fresh local TPM cannot silently redefine history as empty.

## Replacement-TPM falsification

The executable proof establishes H1 and H2 under:

```text
TPM-A + 2-of-3 witness quorum
```

Then one witness is made unavailable. The remaining two witnesses still reconstruct H2.

Next, a completely new TPM root is provisioned at sequence zero:

```text
local TPM-B      = (0, "")
external quorum  = (2, H2)
                 ↓
          WITNESS MISMATCH
                 ↓
               DENY
```

The old signed recovery history remains present, but it cannot be accepted under the replacement TPM because cross-host continuity says the system has already committed H2.

This closes the specific reset pattern:

```text
replace/clear local TPM
+ reprovision fresh local anchor
+ keep or restore writable history
!= permission to start history again
```

## Advancement order

The conjunctive anchor advances the external witness first, then the local monotonic root.

If the witness commits but the local step fails, the two roots diverge and all ordinary reads fail closed. This is intentional: a partial distributed commit must not be guessed away.

Repair of that state is an explicit authorized recovery/migration operation, not an automatic reset.

## Claim boundary

This v1 proves:

- exact-digest agreement between local TPM and external quorum;
- tolerance of an unavailable minority witness while a current 2-of-3 majority remains;
- fail-closed behavior after replacement/reinitialization of the local TPM;
- fail-closed behavior after a one-sided witness commit.

It does not yet provide an authorized cross-TPM continuity-transfer protocol that can repair a legitimate hardware replacement without operator intervention. That is the next boundary.
