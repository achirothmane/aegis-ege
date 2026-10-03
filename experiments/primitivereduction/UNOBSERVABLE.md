# Unobservable External Effect Boundary v6

Status: **non-normative falsification experiment**

This experiment attacks the six-primitives candidate with a classic ambiguous
external-effect failure:

```text
request sent
provider may or may not have applied the effect
response lost
local custody = UNKNOWN
provider offers no reliable query and no atomic deduplication
```

Two worlds are locally indistinguishable:

```text
World A: effect happened, response lost
World B: effect did not happen, response lost
```

If the provider exposes neither exact observation nor atomic idempotency,
automatic replay is unsafe in World A and refusing replay sacrifices progress
in World B. The kernel cannot infer which world it is in from local state alone.

## Candidate reduction

The candidate basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

The experiment adds derived provider semantics:

- **ProviderContract** — evidence-bound declaration of destination guarantees;
- **ProviderObservation** — evidence about one exact logical effect;
- **RecoveryAction** — derived decision:
  - `STOP_UNKNOWN`
  - `RETRY_SAME_EFFECT`
  - `CLOSE_APPLIED`

These are not promoted to primitives.

## Recovery rules

```text
UNKNOWN custody
    |
    +-- final APPLIED evidence ----------------> CLOSE_APPLIED
    |
    +-- final ABSENT evidence -----------------> RETRY_SAME_EFFECT
    |
    +-- atomic dedup + exact same effect id ---> RETRY_SAME_EFFECT
    |
    +-- otherwise -----------------------------> STOP_UNKNOWN
```

A non-final/best-effort observation never manufactures certainty.

## Impossibility boundary

This experiment makes the following boundary explicit:

> exactly-once recovery for an opaque non-idempotent destination cannot be
> manufactured by the governance kernel alone.

The destination must cooperate through at least one trustworthy mechanism such
as atomic idempotency/deduplication, definitive effect lookup, transactional
fencing, or an equivalent destination-side guarantee.

Without that cooperation, the only safe automatic disposition after ambiguity
is to remain UNKNOWN and stop replay.

## Executable corpus

Tests cover:

- two indistinguishable hidden provider worlds producing the same local inputs;
- opaque provider -> STOP_UNKNOWN;
- atomic dedup with exact effect identity -> retry allowed;
- wrong idempotency key -> fail closed;
- final APPLIED observation -> truthful closure;
- final ABSENT observation -> same-effect retry allowed, not CLOSED;
- non-final observation -> no manufactured closure;
- stale provider semantics -> fail closed;
- observation for another logical effect -> cannot resolve custody;
- primitive basis remains exactly six.

## Current bounded result

This round does **not** force `ProviderContract`, `Idempotency`,
`ExactlyOnce`, `ObservationFinality`, or `RecoveryAction` to become
fundamental governance primitives.

Instead, like the distributed linearization experiment, it exposes a real
**destination-cooperation / impossibility boundary** that production claims
must state rather than hide.
