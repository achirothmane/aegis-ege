# TPM-anchored recovery history rollback resistance

Signed recovery receipts prove authenticity, but signatures alone do not prove freshness. A complete storage snapshot can contain an older receipt, an older valid head, and an older valid companion file whose signatures and hashes still verify.

This proof binds recovery-history freshness to TPM-protected state outside the writable history volume.

## Invariant

```text
VALID_OLD_HISTORY != CURRENT_HISTORY

local signed history = H1
TPM protected head   = H2
=> H1 is rejected fail-closed
```

A monotonic counter alone is not enough. A writable companion file could be rewritten at the **same counter generation** with another head and a recomputed self-hash. Therefore the TPM now protects two independent facts:

- a monotonic NV counter;
- a separate ordinary NV exact-head record containing:
  - generation;
  - history sequence;
  - exact SHA-256 history-head digest.

The writable companion remains useful for crash recovery and auditability, but it is no longer the root of truth for the head digest.

## Commit path

```text
signed recovery receipt
        ↓
immutable content-addressed receipt
        ↓
fsync local history head
        ↓
pending TPM companion state fsync
        ↓
TPM exact-head NV :=
  generation N+1
  sequence   S+1
  digest     H(next)
        ↓
TPM monotonic counter N → N+1
        ↓
promote pending companion
```

The companion state also binds:

- TPM endorsement identity;
- measured-boot identity;
- current/previous TPM generation;
- current/previous history sequence;
- current/previous history-head digest;
- a self-hash for local corruption detection.

But current authority requires agreement among all three surfaces:

```text
TPM counter
TPM exact-head NV
writable companion
```

Any disagreement fails closed.

## Whole-volume rollback proof

The executable simulator proof creates:

```text
H1 -> TPM generation N
H2 -> TPM generation N+1
```

It then restores writable storage to H1:

- local history head is restored to H1;
- H2 receipt is removed;
- companion state is restored to H1 bytes.

The TPM remains at H2:

```text
counter    = N+1
exact head = H2
local disk = H1
```

The old H1 receipt remains correctly signed and locally verifiable, but anchored history returns rollback detected.

## Same-generation substitution proof

A stronger falsification keeps the TPM counter unchanged and rewrites only the writable companion:

```text
TPM counter          = N
TPM exact head       = H1
companion generation = N
companion head       = forged Hx
companion self-hash  = recomputed and valid
```

A counter-only design would not distinguish this from legitimate state. The exact-head NV comparison rejects it.

This proves:

```text
counter freshness != content freshness
```

## Interruption recovery

The protocol exercises both commit windows around TPM state:

1. **exact head committed, counter not yet incremented**
   - pending companion proves the intended successor;
   - restart verifies the protected exact head;
   - counter is completed exactly once;
   - pending state is promoted.

2. **exact head + counter committed, companion not promoted**
   - restart verifies both TPM facts;
   - pending companion is promoted without a second counter increment.

A pending file that exists before TPM state advances can be discarded while remaining fail-closed.

## Device and measured-boot binding

The TPM history anchor reuses the existing TPM trust primitives:

- endorsement-key-derived device identity;
- measured-boot identity from PCRs 0, 2, 4, and 7.

A companion from another TPM or another measured-boot state cannot be accepted merely because its bytes are valid.

## CI proof gate

CI requires all four TPM history proofs to **PASS without SKIP**:

- whole-volume rollback rejection;
- same-generation companion substitution rejection;
- post-counter interrupted commit recovery;
- exact-head-before-counter interrupted commit recovery.

## Claim boundary

This proves recovery-history rollback resistance while the same trustworthy TPM remains available and its NV authorization remains protected.

It does not yet prove continuity across TPM replacement, motherboard replacement, deliberate TPM clear with authorized migration, or a remote disaster-recovery site. Those require composition with the external witness/quorum layer.

Historical evidence remains non-authoritative throughout.
