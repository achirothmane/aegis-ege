# VCS-05 — Performance / Goodput Delivery

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-01 established conservative reconciliation.
VCS-02 bound settlement to materially independent evidence.
VCS-03 bound settlement to attested hardware/topology continuity.
VCS-04 bound settlement to continuous GPU-second accounting.

VCS-05 asks the next commercial question:

> Did the buyer receive compute at the contracted quality level, not merely the contracted amount of time?

## Generic performance envelope

The experiment deliberately avoids hard-coding NCCL, tokens/sec, FLOP/s, memory bandwidth, or another vendor-specific performance semantic into the governance kernel.

    metric
    unit
    minimum_value
    max_gap
    max_below_floor_duration

Example fixture:

    metric        = collective.goodput
    unit          = contract_units_per_second
    minimum_value = 1000

A future contract can map this generic envelope to a concrete metric such as NCCL bandwidth, model goodput, tokens/sec, or another independently measurable quantity.

## Performance stream

Each independent source reports ordered windows:

    sequence
    start
    end
    metric
    unit
    value

The stream is structurally admissible only when sequence is strictly consecutive, windows do not overlap, uncovered gaps remain inside the explicit policy, every window is inside both the admitted lease and execution receipt, metric and unit match the contract envelope, and the stream is bound to an evidence source already admitted by VCS-02.

A valid performance stream can therefore be wrong about compliance, but it cannot be structurally ambiguous.

## Layering rule

VCS-05 is strictly downstream of the previous proofs:

    hardware continuity
          ↓
    independent evidence
          ↓
    metering continuity
          ↓
    performance continuity
          ↓
    commercial disposition

A later quality signal can never upgrade an earlier failure. For example, metering=DISPUTED plus excellent performance remains DISPUTED, and metering=CREDIT_DUE plus excellent performance remains CREDIT_DUE.

## Executable cases

### VCS05-A — matching quality

Provider and tenant independently observe performance above the contract floor for the execution interval.

Result: **SETTLED**.

### VCS05-B — provider / tenant performance contradiction

Both streams are structurally valid, but provider says compliant while tenant says below floor.

Result: **DISPUTED**. The evidence is good enough to disagree, so this is not UNKNOWN.

### VCS05-C — independent agreement on sustained underperformance

Both sources observe performance below the contracted floor for the same degradation duration.

Result: **CREDIT_DUE**.

The adapter does not calculate currency. It establishes the contract condition from which a pricing/remedy policy can later calculate money.

### VCS05-D — disagreement on degradation extent

Both sources conclude the contract failed, but disagree on how long the performance remained below the floor.

Result: **DISPUTED**. This matters because remedy size may depend on degradation duration.

### VCS05-E — explicit tolerance

The contract can permit a bounded below-floor duration such as max_below_floor_duration=1s. A one-second dip then does not automatically create a credit. This prevents the settlement engine from inventing stricter commercial terms than the actual contract.

### VCS05-F — structural evidence failures

Overlapping performance windows, sequence gaps, uncovered observation gaps, wrong metric/unit, performance evidence outside the execution receipt, or a digest not bound to the independently assessed source all remain **UNKNOWN** rather than becoming financial conclusions.

## Why metric semantics remain outside the kernel

The universal governance layer still does not know NCCL, NVLink, tokens/sec, FLOP/s, goodput, bandwidth, thermal throttling, model architecture, or batch size.

It only contributes generic capabilities already proven elsewhere: identity, evidence provenance, independence, authority, lease binding, receipt binding, and conservative outcomes.

The compute adapter owns the meaning of the performance metric and threshold.

## Claim boundary

VCS-05 does not prove that a particular real-world metric is economically correct for every AI workload. NCCL bandwidth may be relevant to one distributed training contract while application tokens/sec may be more relevant to an inference contract.

The claim is narrower:

> Once a contract names a measurable quality metric and threshold, structurally valid independent observations can govern whether delivered compute met that envelope without embedding the metric's domain semantics into the kernel.

VCS-05 also does not prove benchmark workload equivalence, resistance to benchmark gaming, causal attribution of low performance, thermal/power-state provenance, exact monetary credit calculation, or legal enforceability of a remedy.

## Complexity Dividend

The held-out compute domain now exercises:

    VCS-01  outcome reconciliation
    VCS-02  evidence independence
    VCS-03  attested hardware continuity
    VCS-04  metered quantity continuity
    VCS-05  performance quality continuity

VCS-05 adds only compute-domain quality semantics. No performance-specific primitive is promoted into the governance kernel.
