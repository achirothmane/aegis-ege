# Attestation Necessity Boundary v15

Status: **non-normative falsification experiment**

v14 left four candidate primitives standing:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

v15 asks whether `Attestation` can be removed from the smallest runtime
admission surface now that policy constraints have already been moved outside
the minimal kernel.

This is stronger than v10.

v10 showed that provenance could not be removed while `Constraint` still
remained in the semantic proposal.

v15 asks the cleaner question after v11:

> if the policy layer has already adjudicated the request, can the runtime
> kernel omit the authorization attestation entirely?

## Three-primitive candidate

The candidate becomes:

```text
Identity
State
Transition
```

The runtime still knows:

- who is acting;
- which exact state revision is current;
- which exact transition/effect is requested.

But it receives no trusted statement that this actor is actually authorized to
perform that transition in that state.

## Indistinguishability result

Without Attestation, these two worlds collapse to the same kernel input:

```text
World A:
same actor
same state
same transition
trusted policy producer authorized the action

World B:
same actor
same state
same transition
no trusted authorization exists
```

The runtime sees only:

```text
Identity + State + Transition
```

and therefore cannot distinguish the worlds.

There are only two generic choices:

```text
ALLOW both
  -> unauthorized world executes

DENY both
  -> authorized world is lost
```

So the authorized/unauthorized distinction cannot be preserved.

## Identity is not authority

v15 also demonstrates that keeping `Identity` is not sufficient.

An identity tells the kernel *who* is presenting the request.

It does not, by itself, say:

```text
this identity is authorized
for this exact transition
against this exact state
```

When Attestation is removed, replacing one complete subject identity with
another still leaves a structurally valid proposal.

The missing relation is authority provenance.

## Why hiding authorization inside State or Identity is not elimination

Possible rewrites such as:

```text
State.Facts["authorized"] = "true"
Identity.Kind = "trusted-admin"
Transition.Operation = "preauthorized.merge"
```

do not eliminate authorization semantics.

They merely hide policy/provenance inside another primitive.

Without a trusted origin for those facts, the same problem reappears.

Likewise, a boolean such as:

```text
authorized = true
```

is simply an attestation with its provenance erased.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the candidate contains only Identity, State, Transition;
- no Attestation / Evidence / Capability / Constraint / Authority / Decision /
  Issuer / Signature / Proof field is hidden in the runtime proposal;
- an authorized world and an unauthorized world become identical kernel input;
- v11 rejects a missing attestation that v15 can no longer represent;
- Identity without Attestation does not bind authority to the actor;
- State/Transition structural binding still fails closed;
- a fail-closed evaluator must deny both authorized and unauthorized worlds,
  proving the original distinction is unrecoverable.

## Current bounded result

v15 **falsifies the attestation-free three-primitive basis** for the modeled
corpus.

After independently testing removal of all four surviving candidates:

- remove Transition -> distinction lost;
- remove State -> stale/current authority distinction lost;
- remove Identity -> authorization becomes bearer authority;
- remove Attestation -> authorized/unauthorized worlds collapse.

The strongest surviving basis remains:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

This is still not a proof of global mathematical minimality.

It is, however, the strongest executable minimality evidence in the current
corpus: each member has now survived direct removal while the other three
remain.

This remains non-normative and does not modify frozen governed-action kernel v1
semantics.
