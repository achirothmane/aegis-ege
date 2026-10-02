# Primitive Reduction Experiment v0

Status: **non-normative experiment**

This experiment tests a candidate reduction of the governed-action lifecycle to six
small, domain-agnostic primitives:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

It does **not** change the frozen governed-action kernel v1 contract in
`docs/governed-action/kernel-v1.md`. The frozen K01-K06 relations remain the
normative baseline. This directory is a falsification harness for a possible
lower-level factorization.

## Question

Can the same small basis express admission, bounded authority, effect execution,
receipt construction, observation, and reconciliation across radically different
domains without embedding GitHub, Kubernetes, or PostgreSQL semantics in the
evaluator?

## Executable tests

`model_test.go` currently exercises the same evaluator against:

- GitHub pull-request merge;
- Kubernetes deployment deletion;
- PostgreSQL schema migration.

The evaluator knows none of those domain names. Adapters/fixtures translate each
world into state facts, evidence, constraints, capabilities, and transitions.

The suite also performs primitive ablation. For every domain, it removes each
candidate primitive in turn and requires fail-closed admission:

```text
- Identity   -> MISSING_IDENTITY
- State      -> MISSING_STATE
- Capability -> MISSING_CAPABILITY
- Constraint -> MISSING_CONSTRAINT
- Evidence   -> MISSING_EVIDENCE
- Transition -> MISSING_TRANSITION
```

Additional checks exercise:

- target identity carried by `StateRef`, rather than a seventh Object primitive;
- monotonic time represented as `State + Constraint`, rather than a seventh Time
  primitive;
- Intent, Authority, and ExecutionLease as derived relations;
- Receipt as a derived relation bound to observed after-state evidence;
- `CLOSED` only when exact expected after-state is observed with valid evidence;
- ambiguity or stale/invalid observation remains `UNKNOWN`.

## Claim boundary

Passing these tests is **not a proof of mathematical minimality**. It establishes
only a stronger, falsifiable engineering claim:

> for the modeled cross-domain corpus, the six-primitives candidate is sufficient,
> the generic evaluator contains no domain business semantics, and deleting any one
> primitive destroys admission expressibility under the current harness.

A primitive is promoted beyond experiment status only after broader adversarial
corpora and existing frozen-kernel semantics fail to reveal a missing distinction.

## Why time and object are not primitives yet

A target is represented by the namespace/object identity inside `StateRef` and is
bound to both Capability and Transition.

Time is represented as a state fact in a declared clock domain and constrained by
generic predicates. Example:

```text
State["clock.monotonic_tick"] = 100
Constraint: clock.monotonic_tick < 150
```

If later execution proves that boot-bound monotonicity, anti-rollback, or temporal
ordering cannot be represented safely this way, Time/Monotonicity becomes a
candidate seventh primitive. We do not add it before the implementation forces us
to.

## Run

```bash
go test ./experiments/primitivereduction
```

The repository-wide CI should also execute this package through the normal Go test
path.
