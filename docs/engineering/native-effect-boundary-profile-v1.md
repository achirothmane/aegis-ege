# Native Effect Boundary Profile v1

Status: **experimental cross-substrate proof profile**.

This document does not change the frozen governed-action semantic contract. It
extracts the enforcement obligations that survived both the PostgreSQL and
Kubernetes native destination-fencing experiments.

## Question

What must a destination substrate provide so that a stale executor cannot turn
an old userspace authorization into a new external effect after takeover,
state drift, authority revocation, or replay?

The answer is not "use a lock" and it is not "check a fencing token before the
provider call." The destination must make the relevant facts participate in the
same native linearization boundary as the effect itself.

## Required native obligations

For one exact effect attempt, the destination profile must establish all of the
following at the actual mutation boundary:

1. **Exact target identity** — the mutation applies to the exact governed target,
   not merely the same display name.
2. **Exact effect/attempt binding** — the logical effect and execution attempt
   being committed are the ones admitted by the runtime.
3. **Current executor ownership** — the destination sees the exact current owner
   identity.
4. **Current fencing generation** — a predecessor generation cannot commit after
   ownership has advanced.
5. **Executable custody phase** — the attempt is at the permitted boundary phase
   (`CROSSING` in the reference runtime), not reopened from UNKNOWN/CLOSED.
6. **Exact pre-effect state** — the semantic state/revision used for admission is
   still the state against which the mutation is committed.
7. **Current authority binding** — the exact admission authority used by the
   attempt is still valid for the boundary-specific profile.
8. **Atomic check-and-effect** — obligations 1–7 and the external effect share one
   substrate linearization boundary. A race between validation and mutation must
   be rejected by the substrate, not merely noticed later in userspace.
9. **Single-effect cardinality** — replay of the same exact effect cannot create a
   second physical effect.
10. **Exact post-effect observation** — CLOSED requires evidence tied to the exact
    effect and resulting state; provider success alone is insufficient.

These are enforcement obligations, not ten new semantic primitives.

## Two passing realizations

### PostgreSQL

The PostgreSQL profile satisfies the obligations with multiple protected rows
inside one serializable transaction. Row locks cover custody, target state and
authority; the same transaction inserts the exact effect record and advances the
target state.

The important property is **one atomic transaction**, not co-location in one row.

### Kubernetes

The Kubernetes API does not provide a general transaction across arbitrary
objects. The passing profile therefore co-locates semantic state, authority,
custody fence and effect marker on one ConfigMap. The API server's
`resourceVersion` compare-and-swap becomes the native linearization boundary.

A deliberately tested alternative fails: a separate Lease can advance to a new
owner while the target object's `resourceVersion` remains unchanged, allowing a
stale target mutation. Therefore:

```text
separate Lease + target mutation
        -> insufficient native fencing

same-object state + authority + fence + effect
        -> resourceVersion CAS
        -> survives the registered v1 corpus
```

## General rule

A substrate is compatible with this profile only when it can map the required
facts into one native commit boundary:

```text
exact target
+ exact attempt/effect
+ current owner/generation
+ executable phase
+ exact pre-state
+ live authority
        |
        v
native atomic validation + effect
        |
        +--> zero effect on any stale/conflicting input
        +--> one effect for the exact current input
```

The realization may be a transaction, one-object CAS, conditional write,
server-side compare-and-set, or another mechanism with equivalent semantics.
The profile does not require a specific database or API.

## Counterexample rule

A profile fails when any required fact can change without invalidating the
effect mutation. In particular, a separately checked lock/lease is insufficient
when takeover can change that lock while leaving the effect target's mutation
precondition valid.

## Claim boundary

The evidence currently covers exactly two positive realizations:

- PostgreSQL 16.6 serializable transaction + row locks;
- Kubernetes single-ConfigMap `resourceVersion` CAS.

It also contains one explicit negative realization: split-object Kubernetes
Lease + target ConfigMap.

This is **bounded generalization evidence**, not a proof that every provider can
satisfy the profile. APIs without atomic conditional mutation over the required
facts must remain outside the native-fencing claim or use a trusted server-side
mediator that supplies an equivalent boundary.

No new governed-action primitive, universal distributed transaction, consensus
protocol, or arbitrary-provider fencing claim is introduced.
