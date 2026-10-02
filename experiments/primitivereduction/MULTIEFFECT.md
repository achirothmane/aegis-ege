# Multi-Effect Partial Completion Reduction v3

Status: **non-normative falsification experiment**

This experiment attacks the six-primitives candidate with a harder composition:
one governed action spans several independent effect boundaries across unrelated
systems, some effects complete, another becomes ambiguous, and execution later
resumes after process restart.

The modeled chain is deliberately cross-domain:

```text
GitHub merge
    ↓
Kubernetes delete
    ↓
PostgreSQL schema migration
```

Each effect has independent durable custody. Later effects may depend on truthful
closure of earlier effects.

## Attack shape

```text
effect A -> CLOSED
effect B -> may have happened -> UNKNOWN
process crashes
effect C is still RESERVED
restart arrives
```

Required behavior:

- A must never replay;
- B must not replay while UNKNOWN;
- C must not execute while B is UNKNOWN;
- exact external evidence may close B;
- only then may C proceed;
- the whole plan must not claim CLOSED until every effect is CLOSED.

## Candidate reduction

No new primitive is introduced. The basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

The higher-order concepts are represented as derived composition:

- **EffectPlan** -> a governance `StateRef` whose facts bind the dependency graph;
- **plan attestation** -> `Evidence` bound to the exact plan-state digest;
- **causal prerequisite** -> `Constraint` over predecessor custody State;
- **effect custody** -> ordinary `State`;
- **custody phase change** -> ordinary `Transition`;
- **plan disposition** -> derived from the set of custody State values.

The derived plan dispositions are:

```text
OPEN
PARTIAL
UNKNOWN
CLOSED
```

They are not primitives.

## Executable falsification corpus

The tests exercise:

- three unrelated domains in one causal effect plan;
- later effects blocked until predecessor custody is CLOSED;
- partial completion where an earlier effect is CLOSED and later effects remain RESERVED;
- ambiguous middle effect forcing whole-plan UNKNOWN;
- restart from durable plan/custody state without replaying already-closed effects;
- safe continuation of the next RESERVED effect after restart;
- dependency-removal attack without rehash;
- dependency-removal attack with rehash but stale plan attestation;
- foreign custody substitution across plan steps;
- final CLOSED only after all effect custodies are CLOSED.

## Current bounded result

This attack still does **not** force `Plan`, `Causality`, `PartialCompletion`,
`EffectStep`, `EffectIdentity`, or `EffectCustody` to become fundamental
primitives.

That does not establish mathematical minimality. The next counterexample class
should target simultaneous/concurrent effects, cyclic dependencies, or effects
whose only ordering evidence lives in independent external systems.
