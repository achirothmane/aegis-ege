# Disk-backed reboot recovery boundary

This proof distinguishes **durable evidence** from **live enforcement authority**.

A correctly signed recovery record may survive a host reboot on persistent
userspace storage. That persistence must not recreate kernel trust on the next
boot.

## Boot A

Boot A creates a signed RECOVERY_COMMITTED record containing:

- Boot A identity;
- recovery plan digest;
- governed cgroup identity;
- committed enrollment epoch;
- monotonic DIRTY generation;
- matching CLEAN watermark;
- exact signed recovery-authorization commitment.

The record is written using a temporary file, fsync, atomic rename, and directory
fsync. Boot A also pins the corresponding commitment in real bpffs kernel state.

## Boot B

A second independent Linux boot sees the persisted userspace record but not the
old bpffs pin.

The same record answers two different questions:

1. Is it authentic historical evidence? **Yes.** Its signature and internal
   bindings still verify.
2. Is it current execution authority? **No.** Its Boot A identity differs from
   the current Boot B identity, so authority verification fails closed.

Boot B then restores effect authority only by performing a fresh signed BPF
bootstrap, kernel-observing the sensitive source again, building a new
activation plan, and activating a new enrollment epoch. A clean connect is
ALLOWed; after reading the enrolled source, connect is DENYed.

Persistent record flow:

    Boot-A disk record
           |
           +--> signature + bindings valid --> HISTORICAL EVIDENCE
           |
    Boot B +--> boot binding mismatch ------> NOT AUTHORITY
           |
           +--> fresh kernel observation
           +--> fresh enrollment
           +--> fresh activation epoch 1
           +--> clean effect ALLOW
           +--> source read
           +--> tainted effect DENY

## Invariant

Disk persistence preserves facts about the previous boot. It does not preserve
effect authority across the reboot boundary.

## Claim boundary

This proves that a durably written userspace recovery record can survive the
tested two-boot boundary without resurrecting Boot-A authority.

The backing file is persisted through the host workspace shared into two
independent disposable VMs; the proof exercises durable file commit semantics
and kernel-state discontinuity. It does not claim power-loss guarantees of a
specific physical disk, storage controller, or filesystem implementation.

It also does not yet prove physical-host replacement recovery, distributed
multi-controller recovery from shared storage, or quorum ownership of recovery
authority.
