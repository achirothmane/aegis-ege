# State Necessity Boundary v13

Status: **non-normative falsification experiment**

v12 left four candidate primitives standing:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

v13 asks whether `State` can be removed from the smallest runtime admission
surface.

## Three-primitive candidate

The candidate becomes:

```text
Identity
Attestation
Transition
```

The attestation remains bound to:

- subject identity;
- trusted issuer;
- decision;
- operation;
- target.

But all target state semantics are deliberately removed:

- no current StateRef;
- no version;
- no digest;
- no before-state;
- no after-state.

## Indistinguishability result

Without State, these two worlds collapse to the same kernel input:

```text
World A:
target at revision R1
state-bound authorization is current

World B:
target advanced to revision R2
old authorization is stale
```

The runtime still sees the same:

```text
Identity + Attestation + Transition
```

and therefore cannot distinguish current from stale authority.

## Revision identity is stronger than visible value

v13 also covers an ABA-like boundary:

```text
R1 = value A
R2 = value B
R3 = value A
```

Even if R1 and R3 have the same visible digest/facts, they are distinct revision
identities.

A state-free kernel cannot observe that distinction, so an authorization minted
against R1 remains indistinguishable from one presented at R3.

This matters because safe admission is not only about the value of state; it is
about *which revision* the authority was bound to.

## Why putting state back inside Attestation or Transition is not elimination

If we add any of these back:

```text
state version
state digest
state epoch
before-state hash
after-state hash
resourceVersion
branch SHA
schema version
```

then State semantics have merely moved into another record.

That is representation compression, not semantic elimination.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the candidate contains only Identity, Attestation, Transition;
- no StateRef / version / digest / before / after field exists in the runtime
  proposal or transition;
- current and advanced target revisions become identical kernel input;
- v11 rejects the same state advance that v13 can no longer represent;
- same-value/different-revision state remains invisible without State;
- subject, operation, target, and issuer substitution still fail closed;
- an attested DENY still fails closed.

## Current bounded result

v13 **falsifies the state-free three-primitive basis** for the modeled corpus.

The strongest surviving basis therefore remains:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

State may later be refined into a more primitive concept such as revision-bound
world identity, but some semantic representation of current/relevant state must
remain if stale authority and ABA-style state return are to be distinguishable.

This remains non-normative and does not modify frozen governed-action kernel v1
semantics.
