# Distributed Linearization Boundary v5

Status: **non-normative falsification experiment**

This experiment attacks a hidden assumption in Primitive Reduction v4:

> exact compare-and-swap prevents duplicate claims only when all competing
> claimants commit through the same linearization authority.

## Counterexample

Two disconnected authorities can each begin from the same durable RESERVED
snapshot:

```text
site A: RESERVED --local CAS--> CROSSING
site B: RESERVED --local CAS--> CROSSING
```

Both transitions are locally valid.

Therefore:

```text
local CAS != global exclusivity
```

This is an enforcement-substrate limit, not automatically evidence for a
seventh semantic primitive.

## Candidate reduction

The six-primitives candidate remains unchanged:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

The experiment adds a derived `LinearizationWitness`:

- named shared commit domain;
- authority identity;
- epoch;
- evidence bound to the exact custody State.

A distributed effect boundary fails closed if the required shared commit domain
is absent, mismatched, stale, or unsupported.

The witness is intentionally **not** treated as the serialization mechanism.
A test demonstrates that two disconnected authorities can still both commit if
the substrate falsely claims they are one shared authority.

## Important boundary

The experiment therefore establishes a stronger claim boundary:

> the six primitives can express the requirement for exclusive effect custody,
> but they cannot manufacture linearizability from independent authorities.

The actual exclusivity guarantee requires an enforcement substrate such as a
single authoritative compare-and-swap service, a correctly implemented
consensus-backed state machine, or another mechanism providing equivalent
single-commit semantics.

If that substrate assumption is false, the logical guarantee fails.

## Executable corpus

Tests cover:

- split-brain local CAS where both disconnected sites reach CROSSING;
- missing shared linearization domain -> fail closed;
- wrong/local-only domain witness -> fail closed;
- stale witness/custody binding -> fail closed;
- exact shared-domain witness satisfies the admission precondition;
- one shared authority accepts the first claim and rejects the stale second;
- a witness alone cannot serialize two falsely independent "global" authorities;
- the candidate primitive count remains six.

## Current bounded result

This round does **not** justify adding `Consensus`, `Linearization`, `Quorum`,
`Leader`, `Epoch`, or `FencingToken` as fundamental governance primitives.

Instead, it discovers an explicit **substrate assumption / impossibility
boundary** that future production claims must state and test.
