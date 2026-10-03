# VCS-04 — Metered Delivery Continuity

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-01 established conservative reconciliation.
VCS-02 bound settlement to materially independent evidence.
VCS-03 bound settlement to attested hardware and topology continuity.

VCS-04 asks the commercial question that changes an invoice:

> Did the buyer receive the quantity of compute that the contract says was delivered?

## Bounded unit

The experiment uses the deliberately simple settlement unit:

```text
GPU-seconds = elapsed whole seconds × active contracted GPU count
```

This is not a claim that every GPU-second has equal performance or economic
quality. Performance/goodput remains a later contract dimension.

The purpose of VCS-04 is to prove continuity and accounting semantics before
adding performance semantics.

## Meter stream

Each independently observed stream contains ordered slices:

```text
sequence
start
end
gpu_count
counter_start_seconds
counter_end_seconds
```

A slice is admissible only when:

- sequence is strictly consecutive;
- intervals do not overlap;
- uncovered gaps are within the configured bound;
- the slice is inside both the admitted lease and execution receipt;
- cumulative counters do not reset or jump;
- counter delta equals `duration × gpu_count`;
- observed GPU count does not exceed contracted count;
- the stream is bound to evidence already assessed by VCS-02.

## Composition

VCS-04 does not bypass earlier proofs:

```text
attested hardware continuity
        ↓
independent evidence binding
        ↓
meter stream continuity
        ↓
cross-source quantity reconciliation
        ↓
SETTLED | CREDIT_DUE | DISPUTED | UNKNOWN
```

If VCS-03 cannot establish the execution, metering cannot resurrect it.

## Settlement rules under test

### Complete agreement

```text
contract: 64 GPUs × execution interval
provider meter = expected GPU-seconds
tenant meter   = expected GPU-seconds
```

Result:

```text
SETTLED
```

### Valid quantity disagreement

Both streams are internally continuous, but:

```text
provider delivered quantity != tenant delivered quantity
```

Result:

```text
DISPUTED
```

This is different from UNKNOWN: both observations are valid enough to disagree.

### Independent agreement on under-delivery

```text
provider delivered < contract
tenant delivered   < contract
provider == tenant
```

Result:

```text
CREDIT_DUE
```

This is the first VCS experiment where an executable proof directly models a
financial remedy condition.

### Over-metering

Even if both sources agree on a quantity greater than the contracted quantity,
the profile does not silently produce SETTLED.

Result:

```text
DISPUTED
```

The contract or billing policy must explicitly define how excess usage is
authorized and priced before it can be settled.

## Continuity falsification corpus

VCS-04 includes executable cases for:

```text
duplicate / overlapping interval
lost interval after restart
sequence gap
counter reset
counter delta larger than elapsed capacity
metering after execution receipt boundary
provider / tenant quantity contradiction
agreed under-delivery
complete positive control
```

Any structural continuity failure returns:

```text
UNKNOWN
```

rather than manufacturing a numerical billing conclusion from incomplete
evidence.

## Why metering remains outside the kernel

The generic kernel does not need to know:

```text
GPU
GPU-second
64 GPUs
billing rate
invoice
service credit
reserved capacity
on-demand capacity
```

VCS-04 changes only:

```text
internal/computesettlement/
```

The domain adapter interprets time and capacity. Existing kernel/evidence
primitives continue to govern identity, evidence provenance, independence,
receipt binding, and conservative reconciliation.

## Relation to existing kernel continuity

Aegis already has generic kernel evidence continuity that treats sequence gaps
and counter resets as degraded/invalid evidence.

VCS-04 follows the same fail-closed doctrine but does not reuse that type
directly because kernel event accounting and commercial GPU delivery are
different semantic domains.

This is intentional:

```text
same invariant pattern
!=
same domain representation
```

## Claim boundary

VCS-04 proves accounting continuity for explicit time/capacity slices.

It does not yet prove:

- useful model throughput;
- tokens/sec;
- FLOP delivery;
- NCCL bandwidth;
- memory-bandwidth quality;
- thermal throttling;
- MIG partition equivalence;
- whether an allocated GPU was productive during every billed second;
- legal entitlement to a specific monetary credit percentage.

Those belong to later contract-policy and performance-delivery experiments.

The current claim is narrower:

> A structurally invalid, incomplete, reset, duplicated, overlapping, or
> contradictory meter stream cannot silently become a settled compute invoice.

## Complexity Dividend

After VCS-04 the held-out commercial domain has required:

```text
VCS-01 → reuse generic outcome reconciliation
VCS-02 → extract one generic evidence-independence primitive
VCS-03 → compose existing signature/evidence primitives
VCS-04 → domain-only metering semantics
```

No GPU metering logic is promoted into the governance kernel.
