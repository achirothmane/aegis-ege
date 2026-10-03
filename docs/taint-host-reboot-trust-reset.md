# Host reboot trust-reset and fresh re-enrollment proof

This proof treats a Linux host reboot as an authority discontinuity rather than
assuming that bpffs or recovery authority survives across boots.

The CI schedule executes one taint-native proof in two separate disposable VM
boots.

## Boot A

Boot A:

- captures the real Linux boot identity;
- signs a recovery authorization bound to that exact boot;
- creates a real eBPF array map containing the signed recovery commitment;
- pins that map under bpffs;
- writes only test handoff material into the repository path shared by vimto.

The VM then terminates.

## Boot B

Boot B starts from a new Linux kernel and must prove all of the following:

- the Linux boot identity differs from Boot A;
- the bpffs pin created on Boot A is absent;
- the otherwise-valid Boot-A recovery authorization is rejected specifically
  because its boot identity is stale;
- a newly signed authorization bound to Boot B verifies;
- a fresh signed taint BPF bootstrap is loaded on Boot B;
- the bootstrap receipt is bound to Boot B's boot identity;
- the sensitive source is observed again by the loaded BPF-LSM;
- those newly observed identities are enrolled in a fresh activation plan;
- activation starts a new enrollment epoch at 1;
- source continuity starts with `dirty == clean == 0`;
- a clean protected workload reaches the connect effect boundary and is ALLOWed;
- after that same workload reads the newly enrolled source, its connect is DENYed.

The resulting executable schedule is:

```text
Boot A
  -> boot-bound recovery authority A
  -> real bpffs pinned commitment A
  -> VM terminates

Boot B
  -> boot_id B != boot_id A
  -> old bpffs state absent
  -> authorization A DENY
  -> fresh Boot-B authorization verifies
  -> fresh signed BPF bootstrap
  -> kernel-observe source identities on Boot B
  -> fresh enrollment plan
  -> activation epoch = 1
  -> dirty = clean = 0
  -> clean effect boundary = ALLOW
  -> enrolled-source read
  -> tainted effect boundary = DENY
```

The repository path is deliberately the only handoff channel between the two
ephemeral VMs. Kernel state itself is not carried across.

## Invariant

A recovery authorization or kernel coordination state from Boot A cannot become
authority on Boot B. Restoring effect authority requires evidence and enrollment
created on Boot B.

## Claim boundary

This proves reboot trust reset plus fresh post-reboot source enrollment and
effect restoration on a newly booted disposable Linux kernel.

It does **not** prove durable recovery receipts across a disk-backed physical
machine reboot, persistence of user-space recovery metadata across host failure,
TPM-measured boot continuity, distributed recovery authority, or physical-host
replacement recovery. Those remain separate proof obligations.
