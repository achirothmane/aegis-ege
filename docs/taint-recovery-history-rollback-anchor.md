# Recovery history rollback anchor

A signed recovery-history chain can prove integrity of the bytes that are
present, but signatures alone cannot prove that the newest bytes are present.

If a writable history volume is snapshotted at R1, later advanced to R2, and
then restored to the intact R1 snapshot, R1 remains correctly signed and
internally consistent. Without an independent high-water commitment, the local
store cannot distinguish "current R1" from "rolled back from R2 to R1".

## Independent anchor

The anchored history layer therefore requires state outside the rollback domain
of the writable recovery-history volume:

    sequence
    exact_head_digest

The anchor advances only from the exact expected state to the exact next state.

For history:

    R1 -> anchor {1, digest(R1)}
    R2 -> anchor {2, digest(R2)}

If the writable volume is later restored to R1 while the independent anchor
remains at R2:

    local head    = digest(R1)
    anchored head = digest(R2)
    result        = ROLLBACK DETECTED / fail closed

The exact head digest is required. A counter alone would not detect a
same-length rewritten or substituted history.

## Executable falsification

The test performs a full writable-volume rollback:

1. append signed R1 through the anchored store;
2. copy the entire history directory as a snapshot;
3. append signed R2 and advance the external anchor;
4. delete the current history directory;
5. restore the full R1 snapshot;
6. prove the raw cryptographic store still accepts R1;
7. prove the anchored store rejects the same R1 state as rollback;
8. prove a new signed successor cannot be appended on top of the rolled-back
   volume.

This isolates the missing semantic primitive:

    cryptographic validity != freshness

## Commit-order boundary

The current wrapper writes the local history first and advances the independent
anchor second.

That ordering is intentionally fail-closed:

- if the process dies before local publication, neither side advances;
- if it dies after local publication but before anchor advance, local history is
  ahead of the anchor and subsequent anchored reads fail closed;
- after anchor advance, the exact local head and anchor agree.

This proof establishes safety, not automatic liveness repair for the
local-ahead/anchor-behind crash window.

## Claim boundary

The test anchor is an independent failure domain used to falsify the rollback
semantics. A production anchor must live outside the writable history volume,
for example in an external compare-and-set witness, TPM/HSM-backed state, or
another separately administered monotonic authority.

A second file or database row on the same rollback-capable volume does not
satisfy this claim.

This proof does not yet bind the taint-history head to the existing TPM root or
external witness protocol in production. That is the next composition step.
