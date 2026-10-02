# Capability Elimination v8

Status: **non-normative semantic-reduction experiment**

The earlier falsification rounds repeatedly showed that higher-order concepts
could be composed from the six candidate primitives:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

This round attacks the basis itself.

## Question

Is `Capability` truly a fundamental **semantic** primitive, or can the
authorization relation be represented by:

```text
Identity
+ State
+ Constraint
+ Evidence
+ Transition
```

and then a mechanical capability token be minted only after admission?

## Reduced candidate

```text
Identity
State
Constraint
Evidence
Transition
```

`ReducedProposal` contains no `Capability` field.

Authorization is represented as an evidence-backed constraint over the already
present proposal relation:

```text
subject.id
transition.operation
target.key
```

The authority evidence must be valid, state-bound, and consumed by a constraint.
The reduced evaluator fails closed if the subject, operation, target, evidence,
or authority constraint changes.

## Important distinction

This experiment does **not** claim that runtime capability tokens are useless.

It separates two roles:

```text
semantic admission:
    Identity + State + Constraint + Evidence + Transition
                  ↓
               ALLOW
                  ↓
mechanical enforcement:
    mint scoped Capability / lease / token
```

A capability can therefore remain a strong implementation/security primitive
without being a fundamental semantic atom of the governance model.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the same actions admit without a Capability field;
- subject substitution fails closed;
- operation substitution fails closed;
- target substitution fails closed;
- authority evidence removal fails closed;
- authority constraint removal fails closed;
- stale evidence fails closed;
- a mechanical Capability can be derived only after successful admission;
- unauthorized relations cannot mint that Capability;
- ablating any of the remaining five candidates fails closed.

## Current bounded result

For the modeled corpus, the previous **six-primitives basis is no longer minimal**.

`Capability` survives as a derived mechanical/security object, but this
experiment shows it is not required as an independent semantic input to
admission.

The new candidate basis is therefore:

```text
Identity
State
Constraint
Evidence
Transition
```

This is not a proof that five is minimal. The next reduction attack should test
whether `Evidence` itself is fundamental, or whether it decomposes into
`Fact/Claim + Attestation/Provenance` and therefore reveals a deeper semantic
basis rather than another superficial record type.
