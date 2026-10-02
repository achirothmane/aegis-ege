# Concurrent Effect Claim Reduction v4

Status: **non-normative falsification experiment**

This experiment attacks the six-primitives candidate with concurrent workers,
split-brain delivery, and causal join behavior.

## Attack shape

Two workers may read the same RESERVED custody snapshot at the same time:

```text
worker A ─┐
          ├─ reads RESERVED
worker B ─┘

both derive a valid claim
only one claim may commit
```

The important case is not only two different identities. Duplicate delivery can
run under the same logical executor identity, so owner binding alone is not
enough.

## Reduction

No new primitive is introduced.

The candidate basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

Concurrency safety is represented by exact `State -> Transition` compare-and-swap
semantics at commit time:

```text
transition.From == current State
        |
        +-- yes -> apply
        |
        +-- no  -> reject stale claim
```

The experiment also treats:

- join readiness as a derived predicate over predecessor custody State;
- causal ordering as Evidence about effect relationships;
- conflicting ordering evidence as UNKNOWN rather than an invented total order.

## Executable corpus

Tests cover:

- duplicate workers with the same identity racing on one RESERVED effect;
- stale second claim rejected after the first worker enters CROSSING;
- takeover identity blocked from stealing another owner's reservation;
- independent sibling effects allowed to cross without an invented order;
- a join blocked until every predecessor is CLOSED;
- UNKNOWN predecessor making the join UNKNOWN;
- conflicting external ordering observations remaining UNKNOWN;
- stale pre-crash claim rejected after custody advances to UNKNOWN;
- the primitive basis remaining exactly six.

## Current bounded result

This attack does not yet force `Lock`, `CAS`, `Fence`, `Ordering`,
`Causality`, or `Join` to become fundamental primitives. They remain derived
mechanisms over State, Transition, Constraint, and Evidence.

This is still not a proof of minimality. A stronger next attack should exercise
distributed compare-and-swap without a single linearizable authority, or cyclic
causal dependencies across independently authoritative systems.
