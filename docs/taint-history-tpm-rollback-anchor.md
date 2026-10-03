# TPM-anchored recovery history rollback resistance

Signed recovery receipts prove authenticity, but signatures alone do not prove freshness. A complete storage snapshot can contain an older receipt, an older valid head, and an older valid companion file whose signatures and hashes still verify.

This proof adds a monotonic TPM NV anchor for the recovery-history head.

## Invariant

```text
VALID_OLD_HISTORY != CURRENT_HISTORY

if writable storage says H1
but TPM monotonic state already committed H2
then H1 is rejected fail-closed
```

## Commit path

```text
signed recovery receipt
        ↓
immutable content-addressed receipt
        ↓
fsync history head
        ↓
TPM history anchor Advance(previous, next)
        ↓
pending companion state fsync
        ↓
TPM NV counter increment
        ↓
pending companion state promoted
```

The TPM-side companion state binds:

- TPM endorsement identity;
- measured-boot identity;
- monotonic NV generation;
- previous generation;
- current recovery-history head digest;
- previous recovery-history head digest;
- a self-hash over the companion state.

## Whole-volume rollback proof

The executable simulator proof creates two valid historical states:

```text
H1 -> TPM generation N
H2 -> TPM generation N+1
```

It then restores the writable volume to the exact H1 snapshot:

- `history/head.json` is restored to H1;
- the H2 receipt is removed;
- the TPM companion file is restored to its H1 bytes;
- the old H1 receipt remains correctly signed and locally verifiable.

The TPM NV counter is not part of the writable volume and therefore remains at `N+1`.

Expected result:

```text
unanchored history read -> H1 signature VALID
TPM companion state     -> generation N
TPM NV counter          -> generation N+1
anchored history read   -> DENY / rollback detected
```

This demonstrates why receipt signatures and hash chaining are necessary but insufficient against full-volume restoration: freshness requires a monotonic fact outside the restored storage.

## Interruption recovery

The anchor also uses a pending-state protocol. If the companion file for the next generation is fsynced and the TPM counter advances before the process stops, a restarted anchor promotes the pending state instead of losing the committed generation.

## Claim boundary

This v1 proves rollback resistance when the writable history volume and its companion files are restored while the same TPM NV counter remains available and trustworthy.

It does not yet prove continuity across TPM replacement, motherboard replacement, deliberate TPM clear with re-provisioning authority, or a remote disaster-recovery site. Those require an independently administered external witness or quorum in addition to the local TPM anchor.
