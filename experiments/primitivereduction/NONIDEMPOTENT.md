# Non-Idempotent External Effect Reduction v2

Status: **non-normative falsification experiment**

This experiment attacks the six-primitives candidate with a harder failure mode:
a consequential external effect may occur even though the governed business
target does not change observably.

Example shape:

```text
target state = unchanged
external provider = may have accepted effect
response = lost
retry arrives
```

Target-state revalidation alone is insufficient here. Replaying the request can
duplicate a non-idempotent effect.

## Hypothesis under test

The kernel still does not need a seventh primitive if it represents effect
custody as another instance of the existing `State` primitive and moves that
state through ordinary `Transition` values.

The candidate basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

## Derived custody protocol

Before the effect boundary:

```text
logical EffectIdentity
        ↓
State(governance.effect_custody)
        ↓
RESERVED
        ↓
CROSSING
       / \
      /   \
 CLOSED  UNKNOWN
            ↓
     fresh exact evidence
            ↓
         CLOSED
```

There is deliberately no `UNKNOWN -> RESERVED` transition.

A retry while custody is UNKNOWN therefore cannot obtain replay permission
merely because the original business target state still looks unchanged.

## What the executable corpus proves

Across GitHub merge, Kubernetes delete, and PostgreSQL schema migration, tests
exercise:

- an external effect may occur while the business target remains unchanged;
- ordinary target-state admission can still look valid after the lost response;
- the additional custody State blocks duplicate delivery at the actual effect boundary;
- UNKNOWN never becomes replay permission through retry;
- executor takeover cannot silently steal another executor's RESERVED custody;
- provider evidence must bind the exact logical effect and current custody state;
- fresh exact provider evidence can close the obligation without pretending the
  business target itself changed;
- custody phase changes are represented by the existing Transition primitive;
- the candidate primitive count remains six.

## Result boundary

The current attack does **not** force `EffectIdentity`, `ExecutionAttempt`,
`EffectCustody`, or `Receipt` to become fundamental primitives. They remain
derived relations over the six-primitives candidate.

This still is not a proof of minimality. A future counterexample involving
multiple independent effect boundaries, non-observable providers, partial
multi-effect completion, or cross-system causal ordering may still force a new
primitive or a stronger State relation.
