# Tamper-evident execution journal

M6 adds an audit-integrity layer for the StateLatch execution lifecycle.

The journal is designed to answer:

> Can we detect that the recorded authorization, execution, or outcome history was modified after it was written?

## Record chain

Each JSONL entry contains:

```text
version
journal_id
sequence
prev_hash
event
entry_hash
```

The entry hash is SHA-256 over the complete entry content except the `entry_hash` field itself.

That creates the chain:

```text
entry 1
  ↓ hash
entry 2.prev_hash
  ↓ hash
entry 3.prev_hash
  ↓
...
```

Changing an earlier record breaks every later link.

## Signed head anchor

A hash chain by itself cannot detect simple tail deletion.

For example:

```text
A → B → C
```

can be truncated to:

```text
A → B
```

and the remaining prefix is still internally valid.

M6 therefore stores a separate head anchor containing:

```text
journal_id
final sequence
final head hash
updated_at
Ed25519 signature
```

Verification requires both the chain and the signed anchor to agree.

## What verification detects

The current implementation detects:

- entry payload modification;
- entry reordering;
- deletion from the middle of the chain;
- tail truncation while the current signed anchor is retained;
- anchor modification without the signing key;
- a missing anchor;
- an attempt to append after the journal has become unverifiable.

Append is fail-closed:

```text
verify current chain + anchor
→ invalid
→ refuse append
```

## StateLatch lifecycle binding

M6 defines journal events for:

```text
AUTHORIZATION
EXECUTION
OUTCOME
```

The live KinD proof requires all three entries to retain the same:

- `ActionID`;
- `EvidenceDigest`;
- `PlanDigest`.

Execution and outcome structures are also represented by payload digests so the audit event is bound to the full structured record without duplicating the entire payload into the journal entry.

## Live proof

The KinD integration test performs a real guarded node drain and records:

```text
authorization
→ guarded execution
→ postflight outcome
```

It verifies the three-entry journal, then modifies the recorded execution decision without recomputing the cryptographic chain.

Required result:

```text
verification fails
→ entry hash mismatch
```

## Authority boundary

The journal has **no authority**.

It does not:

- mint authorization;
- change ALLOW/BLOCK/ESCALATE;
- override a failed safety gate;
- alter reliability calibration;
- retry a failed mutation.

It is audit evidence only.

## Key handling

M6 accepts an Ed25519 private key from the caller.

The signing key is not written into the journal or anchor files.

The current repository does not provide production key custody. Production deployment would require an external key-management boundary such as KMS/HSM or equivalent operational controls.

## Crash behavior

Journal append and signed-anchor replacement are two durable writes.

If the process fails after the journal entry is fsynced but before the new anchor is atomically installed, verification fails closed because the anchor sequence/head no longer matches the journal.

Automatic repair of that crash window is not implemented in M6.

## Important anti-rollback limit

M6 detects tail deletion **against the current signed anchor**.

However, if an attacker can restore both:

1. an older valid journal prefix; and
2. the matching older correctly signed anchor,

local verification cannot distinguish that full snapshot rollback from legitimate old state.

Protecting against that stronger threat requires an external monotonic or immutable reference, for example:

- WORM/object-lock storage;
- an external transparency log;
- KMS-backed monotonic metadata;
- another independently retained latest-head checkpoint.

That external anti-rollback anchor is not implemented in M6.

## Scope

M6 is a tamper-evident local journal, not a compliance-grade immutable ledger.

Its purpose is to make silent record rewriting materially harder and detectable under the stated threat model while keeping the journal outside the trusted authorization path.
