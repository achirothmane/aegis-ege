# Transition Necessity Boundary v12

Status: **non-normative falsification experiment**

v11 reduced the smallest kernel admission surface to four candidate primitives:

```text
Identity
State
Attestation / Provenance Binding
Transition
```

v12 tests whether `Transition` can be removed as well.

## Three-primitive candidate

The proposed reduction is:

```text
Identity
State
Attestation
```

with an attestation bound only to:

- subject identity;
- current state;
- issuer;
- decision.

It contains no operation, desired after-state, effect identity, or transition
digest.

## Indistinguishability result

Once transition semantics are removed, these two worlds can map to the same
kernel input:

```text
World A:
same subject
same current state
same trusted attestation
requested effect = A

World B:
same subject
same current state
same trusted attestation
requested effect = B
```

If the effect identity is not represented, the kernel cannot distinguish them.

That failure is especially strong for opaque or non-idempotent external effects,
because two different effects may leave the modeled state unchanged:

```text
State S
  ├── effect alpha ──> State S
  └── effect beta  ──> State S
```

A before/after state pair is therefore insufficient to reconstruct which effect
was authorized.

## Why hiding the operation inside Attestation is not a reduction

One possible objection is to add an operation or effect digest back into the
attestation.

But then the attestation becomes action-bound:

```text
Attestation(subject, state, operation/effect)
```

and the transition/effect relation has simply been moved into another record.

That is representation compression, not semantic elimination.

v11 already demonstrates this action-specific binding explicitly: changing the
operation while keeping the attestation causes admission to fail closed.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the transition-free candidate contains only Identity, State, Attestation;
- no Transition / Operation / Effect / desired-after-state field is hidden in
  the runtime proposal or attestation;
- an admitted operation and a substituted operation become identical kernel
  inputs after transition removal;
- v11 rejects the same operation substitution that v12 can no longer represent;
- distinct external effects with identical before/after modeled state remain
  indistinguishable;
- subject, state, and issuer substitution still fail closed;
- an attested DENY still fails closed.

## Current bounded result

v12 **falsifies the three-primitive transition-free basis** for the modeled
corpus.

The strongest surviving basis remains:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

The word `Transition` may later be refined into a more precise action/effect
relation, but some semantic identity for the requested effect must remain.

This does not prove global mathematical minimality. It proves that removing
transition/effect identity without hiding it elsewhere destroys a distinction
required for safe effect custody.
