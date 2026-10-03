# Cross-Genesis TPM recovery-history continuity

This proof composes two already-governed transitions that were previously established independently:

1. external witness quorum rotation across Genesis epochs; and
2. authorized recovery-history continuity transfer from one TPM to another.

The claim is deliberately narrow:

```text
TPM-A @ Hn
+
Genesis N / quorum A,B,C
        ↓
governed quorum rotation
        ↓
Genesis N+1 / quorum A,B,D
        ↓
authorized TPM-A → TPM-B transfer
        ↓
TPM-B @ Hn
        ↓
Hn → Hn+1
```

The history head must remain exact while both the witness trust epoch and the physical TPM root change.

## Composition invariant

The proof requires all of the following:

```text
old history quorum head
    == new history quorum head
    == TPM-A exact head
    == authorized source head
    == TPM-B imported head
```

and:

```text
OLD_QUORUM retired
AND
TPM-A retired
AND
NEW_QUORUM authoritative
AND
TPM-B authoritative
```

No transition is allowed to interpret a hardware replacement or a Genesis change as permission to restart history.

## Governed epoch transition

The executable proof uses a 2-of-3 quorum:

```text
Genesis 41: A B C
Genesis 42: A B D
```

A and B are the stable shared witnesses. C is deliberately unable to accept writes, so every committed old-epoch head necessarily exists on both shared witnesses before rotation.

The rotation then executes the production:

```text
OLD
 ↓
JOINT_FROZEN
 ↓
NEW
```

protocol.

After rotation:

- the old history quorum is no longer authoritative;
- the old ownership quorum is no longer authoritative;
- the new history quorum exposes the exact same H2;
- the new ownership quorum still identifies TPM-A as active.

## Transfer authorization after rotation

The TPM transfer authorization is signed only after the new Genesis quorum is active.

It binds the new history and ownership quorum policy hashes.

The proof first presents an otherwise valid authorization containing the pre-rotation policy hashes. It must be rejected before:

- TPM-B's monotonic counter changes; or
- ownership leaves TPM-A.

This establishes that a previously valid trust epoch cannot silently authorize a post-rotation physical-root transfer.

## Hardware-root replacement

Once the exact new-epoch quorum state is established:

```text
TPM-A = H2
new history quorum = H2
new ownership quorum = TPM-A
        ↓
fresh TPM-B attestation
        ↓
signed exact transfer under Genesis 42 policy hashes
        ↓
ownership = QUIESCED
        ↓
TPM-B imports H2
        ↓
ownership = TPM-B
```

TPM-A is then tested through the live new ownership witness and must remain retired.

TPM-B continues the same signed history:

```text
H1 → H2
     │
     ├─ Genesis quorum changed
     └─ TPM root changed
          ↓
         H3
```

## Falsification conditions

The proof fails if any of these become possible:

- an old-Genesis transfer authorization mutates TPM-B;
- an old-Genesis transfer authorization changes ownership;
- the old history quorum remains authoritative after rotation;
- the old ownership quorum remains authoritative after rotation;
- quorum rotation changes H2;
- TPM-B imports any head other than H2;
- TPM-A regains active ownership after transfer;
- TPM-B cannot continue H2 → H3;
- an old quorum becomes authoritative again after H3.

## Claim boundary

This proves composition of:

- exact recovery-history continuity;
- governed quorum rotation with stable majority overlap;
- destination attestation freshness/generation binding;
- one-way TPM ownership transfer; and
- predecessor retirement.

It does not yet prove recovery when the old and new witness sets lack a safety-preserving overlap, nor recovery after simultaneous loss of both local TPM state and a governed witness majority. Those require a separately authorized continuity mechanism rather than weakening this transition.
