# Primitive Reduction Adversarial Corpus v1

Status: **non-normative falsification extension**

This corpus attacks the six-primitives candidate after the initial cross-domain
reduction experiment. It does not alter the frozen governed-action kernel v1
contract.

The candidate basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

## Failure schedules exercised

The corpus covers, across GitHub merge, Kubernetes delete, and PostgreSQL schema
migration:

- stale evidence;
- capability substitution;
- target substitution;
- authority revoked before the effect boundary;
- lease/validity expiry before the effect boundary;
- stale pre-crash proposal after world-state advance;
- duplicate delivery after an already-observed effect;
- effect occurred but the local receipt was lost;
- contradictory observations;
- executor takeover for the same logical effect;
- material transition mutation;
- monotonic-clock rollback on the same boot;
- boot change where monotonic ticks are intentionally non-comparable.

## Derived relations strengthened

The experiment now includes three derived mechanisms without adding a seventh
primitive:

1. `EvaluateAtBoundary` — compares the proposal's bound State to the actual
   effect-boundary State before reusing admission.
2. `EffectIdentity` — deterministically derives logical effect identity from
   Identity + Capability + Transition + State binding. Executor takeover does
   not create a new logical effect.
3. `StateRelation` — expresses cross-state relations such as monotonicity and
   anti-rollback as a Constraint over two State observations.

`ReconcileAll` remains conservative: any stale, invalid, or contradictory
observation keeps disposition at `UNKNOWN`.

## Current result

The adversarial corpus does **not yet force** promotion of `Time`, `Object`,
`EffectIdentity`, `Authority`, `Lease`, or `Receipt` to primitive status.

That is a bounded experimental result, not a proof of minimality. A future
failure schedule may still reveal a distinction that cannot be represented by
the current six.
