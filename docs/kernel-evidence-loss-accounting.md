# Kernel Evidence Loss Accounting

Kernel enforcement is useful only if its evidence plane can say when evidence itself was lost.

Aegis-EGE therefore treats ring-buffer loss as an epistemic event, not as a logging inconvenience.

## Kernel event ABI

Every cgroup network enforcement decision attempts to emit a fixed 128-byte event:

```text
sequence
observed_at_mono_ns
cgroup_id
authority_term
decision_epoch
revocation_epoch
decision_id_hash
action_class
verdict
reason
address_family
destination_address
destination_port
protocol
abi_version
event_type
```

The event is emitted for both ALLOW and BLOCK decisions, including missing-fence and missing-capsule denials.

## Loss accounting

The BPF object owns a global array-map accounting record:

```text
sequence
emitted
lost
```

The algorithm is intentionally ordered:

```text
1. atomically allocate sequence
2. try bpf_ringbuf_reserve()
3a. success -> fill + submit -> emitted++
3b. failure -> lost++
```

The sequence is allocated before ring-buffer reservation.

This gives two independent loss signals:

- a later consumer-visible sequence gap;
- the authoritative kernel `lost` counter.

The second signal catches trailing loss even when no later event exists to reveal a gap.

## Userspace continuity tracker

`internal/kernelfabric.EvidenceReader` consumes the pinned ring buffer and reads the pinned accounting map.

Default paths:

```text
/sys/fs/bpf/aegis-ege/maps/aegis_ev_events
/sys/fs/bpf/aegis-ege/maps/aegis_ev_acct
```

The reader tracks:

```text
last_sequence
kernel_sequence
emitted_events
lost_events_total
lost_since_baseline
sequence_gaps
```

Continuity status is:

```text
INTACT
DEGRADED
```

It becomes DEGRADED when either:

- the kernel loss counter increases after the reader baseline; or
- a non-contiguous event sequence is observed.

No arbitrary confidence percentage is invented.

## Checkpoints

Loss is cumulative in the kernel map.

A userspace consumer may explicitly checkpoint an investigated loss window. A checkpoint updates the userspace baseline; it does not rewrite or erase the kernel's cumulative loss counter.

## EASL bridge

The continuity assessment can be converted directly into an EASL evidence item.

For an assumption such as:

```text
kernel-evidence-continuity
```

the bridge behaves as follows:

```text
INTACT
  -> fresh EASL evidence

DEGRADED
  -> fresh EASL evidence
  -> explicit contradiction edge to kernel-evidence-continuity
```

EASL therefore receives a normal producer-supplied contradiction instead of being taught kernel-specific ring-buffer semantics.

The resulting path is:

```text
BPF enforcement
   |
   v
sequenced ring-buffer event
   |
   +---- reserve failure ----> kernel lost counter
   |
   v
userspace EvidenceReader
   |
   +---- sequence gaps
   +---- lost delta
   |
   v
ContinuityAssessment
   |
   v
EASL Evidence
   |
   v
assumption invalidation / downstream policy
```

## Failure semantics

Evidence loss does not silently change an enforcement ALLOW into a BLOCK inside the BPF program.

The enforcement decision and the evidence-continuity decision are separate domains:

- the kernel enforces the current DecisionCapsule;
- EASL/downstream policy decides what loss of enforcement evidence means for future authority.

This separation prevents a telemetry backpressure incident from inventing kernel policy while still making the loss impossible to ignore.

## Remaining work

This layer establishes measurable evidence continuity for the cgroup network adapter.

Still separate:

```text
signed / attested BPF loader bootstrap
BPF-LSM evidence events
XDP evidence events
cross-host aggregation
durable off-host evidence sink
policy for automatic recovery after a degraded interval
```
