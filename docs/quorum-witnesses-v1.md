# Quorum Witnesses v1

Status: executable majority-quorum proof.

This layer composes multiple already-trusted `ExternalHeadStore` witnesses into one majority witness.

The first production profile is:

```text
Witness A
Witness B
Witness C
    ↓
2-of-3 strict majority
    ↓
QuorumHeadStore
    ↓
CapabilityRootAnchor
```

## Why strict majority

A quorum threshold must be greater than half of the configured witnesses.

For three witnesses, 2-of-3 is valid.

For four witnesses, 2-of-4 is rejected because two disjoint groups could each claim a different truth.

The constructor therefore enforces:

```text
threshold > members / 2
```

This guarantees quorum intersection.

## Read semantics

Each witness returns its own independently verified `ExternalHead`.

The quorum groups observations by semantic state:

```text
journal id
sequence
exact head commitment
protocol key id
```

The witness-specific CAS `StoreVersion` is deliberately excluded from semantic equality because independent witnesses have independent CAS tokens.

A read is accepted only when at least the configured threshold agrees on the same semantic head.

Examples for 2-of-3:

```text
A = T2
B = T2
C = T99
=> T2

A = T2
B = T2
C = unavailable
=> T2

A = T1
B = T2
C = unavailable
=> FAIL CLOSED
```

A single witness owner therefore cannot define quorum truth.

## Per-witness CAS vector

The aggregate `StoreVersion` is not a fake shared CAS token.

It encodes a vector:

```text
witness-a -> CAS version A
witness-b -> CAS version B
...
```

This preserves the fact that each witness has its own linearization point.

## Advance semantics

A transition is attempted only after a quorum is first observed at the caller's expected semantic state.

Then each matching witness receives an independent compare-and-advance operation using that witness's own CAS version.

The transition is reported successful only after a quorum independently returns the exact requested next semantic head.

A single successful write is not truth.

```text
A advances T2 -> T3
B fails
C fails

=> no quorum at T3
=> operation fails closed
=> B + C still define T2
```

A later retry can advance B and C to T3 without rolling A backward.

## Failure tolerance

For 2-of-3, the model tolerates one witness that is:

- unavailable;
- stale;
- divergent;
- controlled by an owner returning a different validly signed head.

It does not tolerate two colluding or compromised witnesses. Two witnesses form the configured quorum and can define a false state.

That limit is explicit and is the reason quorum membership itself must terminate in the existing Genesis / governance trust path.

## Executable falsification coverage

The current corpus proves:

1. 1-of-3 and 2-of-4 non-majority configurations are rejected.
2. Duplicate witness identities are rejected.
3. One witness reporting a much higher fabricated head cannot override two agreeing witnesses.
4. One unavailable witness does not stop a healthy 2-of-3 quorum.
5. Split state without two agreeing witnesses fails closed.
6. Advance succeeds only after two witnesses independently commit the next head.
7. A one-member partial advance does not become quorum truth.
8. A later retry can complete the transition through the remaining quorum without rolling the early member backward.
9. An absent majority can initialize sequence zero consistently.

## Trust composition

`QuorumHeadStore` assumes each member store has already authenticated its witness identity.

For remote witnesses, that means each member may be a `RemoteHeadStore` created from an authorized witness trust manifest.

Production must additionally bind the quorum membership set and threshold into Genesis or an equivalently governed relying context. Otherwise a workload operator could replace the 2-of-3 set itself, defeating the quorum while leaving the quorum algorithm correct.

That membership-binding step is the next trust boundary after this executable quorum proof.
