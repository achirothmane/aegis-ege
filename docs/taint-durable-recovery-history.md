# Durable taint recovery history across reboot

Aegis-EGE treats a Linux reboot as an authority discontinuity. Kernel state and
boot-bound recovery authority from a previous boot do not become authority on a
later boot.

That creates a separate requirement: the system still needs durable historical
truth about what actually completed before a later reboot, without allowing that
history to authorize new effects.

This proof introduces a signed, fsync-backed recovery history store with those
semantics.

## Historical receipt

A recovery-history receipt records:

- the exact boot identity on which the fact was observed;
- the activation-plan digest;
- protected cgroup identity;
- enrollment epoch;
- DIRTY and CLEAN generations;
- whether the clean effect boundary was observed as ALLOW;
- whether the same workload was observed as DENY after reading the enrolled
  sensitive source;
- the previous history receipt digest;
- a signed timestamped event.

The receipt is signed independently from kernel state and stored as an immutable
content-addressed record. A separately fsync-backed head points to the latest
receipt. Successor receipts must name the exact predecessor digest.

The store rejects:

- signature tampering;
- head/receipt digest disagreement;
- chain forks;
- symlink substitution at the head or receipt path;
- malformed continuity records where DIRTY and CLEAN disagree.

## Three-boot executable proof

The privileged CI schedule now executes three independent Linux kernel boots.

```text
Boot A
  -> boot-bound recovery authority
  -> real bpffs recovery commitment
  -> kernel terminates

Boot B
  -> boot_id B != boot_id A
  -> Boot-A authority DENY
  -> old bpffs state absent
  -> fresh signed bootstrap
  -> fresh kernel source observation
  -> fresh enrollment epoch 1
  -> clean effect ALLOW
  -> enrolled-source read
  -> tainted effect DENY
  -> signed historical receipt
  -> immutable receipt fsync
  -> history head fsync
  -> kernel terminates

Boot C
  -> boot_id C differs from A and B
  -> signed Boot-B historical receipt verifies
  -> exact history digest survives
  -> Boot-B effect authority DENY
```

The important separation is:

```text
historical truth survives
        !=
authority survives
```

A receipt can answer "what completed on Boot B?" after Boot B no longer exists.
It cannot answer "may this effect execute on Boot C?"

## Claim boundary

This proves signed durable historical continuity through independent kernel
reboots using an external filesystem path that is fsync-backed and preserved
across the disposable VMs.

It does **not** yet prove resistance to rollback of the entire persistent
storage volume, storage-controller lies, TPM-measured boot continuity for this
specific history head, remote witness quorum, or recovery across physical host
replacement. Those require a monotonic anchor outside the writable history
volume.
