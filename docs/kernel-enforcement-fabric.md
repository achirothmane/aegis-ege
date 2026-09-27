# Kernel Enforcement Fabric — DecisionCapsule v1

Aegis-EGE now has a kernel-facing enforcement contract. Heavy epistemic evaluation remains in the control plane; the kernel receives only a compact decision capsule and the minimum fencing state needed to reject stale authority.

## Trust boundary

The kernel does **not** compute evidence quality, policy admissibility, assumption decay, or ZK proofs.

Userspace/control plane owns:

```text
Evidence
-> EASL / admissibility
-> authority
-> execution capability
-> DecisionCapsule installer
```

Kernel space owns:

```text
current scope fence
+ installed DecisionCapsule
+ local monotonic time
-> ALLOW or BLOCK
```

## DecisionCapsule ABI

The v1 fixed-size capsule is 240 bytes:

```text
decision_id_hash      [32]
subject_hash          [32]
action_hash           [32]
policy_hash           [32]
evidence_hash         [32]
boot_id_hash          [32]
authority_term        u64
decision_epoch        u64
revocation_epoch      u64
installed_at_mono_ns  u64
deadline_mono_ns      u64
decision              u32
constraints           u32
```

The kernel never receives raw evidence or human-readable policy text.

## Scope model

The first adapter protects outbound network connect operations for a cgroup.

A scope key is:

```text
cgroup_id
action_class
address_family
destination_address
destination_port
protocol
```

Evaluation attempts an exact destination match first. If no exact capsule exists, it checks a cgroup-wide wildcard network-connect capsule.

A separate fence key is intentionally broader:

```text
cgroup_id
action_class
```

Changing that fence invalidates all exact and wildcard capsules for the action class at once.

## Epoch fencing

Each scope fence contains:

```text
boot_id_hash
authority_term
decision_epoch
revocation_epoch
```

The BPF program requires an installed capsule to match every value.

This means:

- authority failover can invalidate prior capsules by incrementing `authority_term`;
- a newer decision invalidates the prior decision via `decision_epoch`;
- emergency revocation invalidates every capsule in the scope via `revocation_epoch`;
- reboot invalidates prior capsules through `boot_id_hash`.

## Clock-domain binding

External authorization time is not copied into the kernel as a foreign monotonic timestamp.

The installer converts:

```text
issued_at
not_after
max_lifetime
+ current wall clock
+ local CLOCK_MONOTONIC
+ current boot id
```

into:

```text
installed_at_mono_ns
deadline_mono_ns
boot_id_hash
```

The BPF program compares `deadline_mono_ns` to `bpf_ktime_get_ns()`.

## Fail-closed install ordering

Userspace updates the kernel in this order:

```text
1. write new scope fence
2. write new DecisionCapsule
```

If step 2 fails, the older capsule no longer matches the new fence. The failure creates a temporary deny, not a stale allow.

Revocation requires only a fence update. It does not depend on deleting every old capsule synchronously.

## cgroup BPF adapter

The first enforcement adapter is implemented in:

```text
kernel/bpf/aegis_connect.bpf.c
```

with sections:

```text
cgroup/connect4
cgroup/connect6
```

Once attached to a protected cgroup, a connect attempt is blocked when any of these is true:

- no current scope fence exists;
- no exact or wildcard capsule exists;
- boot instance differs;
- authority term differs;
- decision epoch was superseded;
- revocation epoch differs;
- local monotonic lease expired;
- capsule decision is BLOCK.

The adapter exports per-CPU denial/allow counters and emits sequenced enforcement evidence through a shared ring buffer. Reservation failures are counted in a separate kernel accounting map so telemetry loss is observable rather than silent. See [kernel-evidence-loss-accounting.md](kernel-evidence-loss-accounting.md).

## Pinned-map installer

`internal/kernelfabric.BPFToolStore` writes the ABI directly to pinned maps through `bpftool` without shell interpolation.

Expected pinned maps:

```text
/sys/fs/bpf/aegis-ege/maps/aegis_capsules
/sys/fs/bpf/aegis-ege/maps/aegis_fences
```

## Current boundary

DecisionCapsule v1 is an actual cgroup network enforcement adapter, but it is not yet the whole Kernel Enforcement Fabric.

Implemented:

```text
DecisionCapsule ABI
local monotonic lease binding
boot-instance binding
authority / decision / revocation fencing
exact + wildcard network scopes
cgroup connect4/connect6 BPF programs
pinned-map userspace installer
fail-closed install ordering
reference evaluator + ABI tests
BPF compile gate in CI
sequenced ring-buffer enforcement evidence
kernel emitted/lost accounting
userspace continuity tracker
EASL contradiction bridge for degraded continuity
```

Not yet implemented:

```text
BPF-LSM filesystem/process enforcement
XDP ingress enforcement
signed/attested BPF loader bootstrap
kernel-side constraint classes beyond network connect
runtime verifier test on a privileged CI host
```

Those are subsequent adapters/layers; they should not be simulated inside this v1 network hook.

## Governing invariant

> A stale, revoked, expired, superseded, reboot-crossing, or absent DecisionCapsule must fail closed before the protected kernel operation is allowed.
