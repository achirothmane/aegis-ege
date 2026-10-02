# Identity Necessity Boundary v14

Status: **non-normative falsification experiment**

v13 left four candidate primitives standing:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

v14 asks whether `Identity` can be removed from the smallest runtime admission
surface.

## Three-primitive candidate

The candidate becomes:

```text
State
Attestation
Transition
```

The runtime proposal deliberately contains no:

- subject identity;
- actor identity;
- executor identity;
- principal identity;
- issuer identity;
- tenant identity;
- key ID.

The remaining attestation is only an opaque verified decision bound to the exact
state and transition.

## Indistinguishability result

Without subject identity, these two worlds collapse to the same kernel input:

```text
World A:
authorized actor presents authorization X

World B:
different actor presents the same authorization X
```

The kernel sees only:

```text
State + Attestation + Transition
```

and must therefore make the same decision in both worlds.

The authorization has become bearer authority: possession is sufficient.

## Cross-tenant consequence

The same problem appears across tenant boundaries:

```text
tenant A / executor 7
tenant B / executor 7
```

If actor identity is absent from the semantic binding, both can present the same
state-bound action authorization and remain indistinguishable to the minimal
kernel.

That is a confused-deputy / authority-transfer boundary, not merely a logging
problem.

## Comparison with v11

v11 binds the attestation digest to the subject identity.

Changing:

```text
subject A -> subject B
```

while keeping the attestation causes admission to fail closed.

v14 cannot represent that substitution at all because subject identity has been
removed from the proposal.

## Why putting identity back inside Attestation is not elimination

A possible objection is to add any of these to the attestation:

```text
subject ID
principal ID
executor ID
tenant ID
issuer ID
key ID
certificate subject
workload identity
```

But each of those restores identity semantics under another field name.

That is representation compression, not semantic elimination.

Likewise, treating `Valid=true` as "verified for exactly the right principal"
would merely hide the identity check behind an opaque boolean. v14 intentionally
does not count that as a valid reduction.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the candidate contains only State, Attestation, Transition;
- no subject / actor / executor / principal / issuer / tenant / key-ID field is
  hidden in the runtime proposal or attestation;
- an authorized actor and a substituted actor become identical kernel inputs;
- v11 rejects the same subject substitution that v14 cannot represent;
- the identity-free object behaves like bearer authority across tenant actors;
- state and transition substitution still fail closed;
- invalid or DENY attestations still fail closed.

## Current bounded result

v14 **falsifies the identity-free three-primitive basis** for the modeled corpus.

The strongest surviving basis remains:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

Identity may later be refined into a deeper concept such as principal binding or
authority-bearing actor identity, but some semantic distinction between who may
exercise an authorization and who may not must remain.

This remains non-normative and does not modify frozen governed-action kernel v1
semantics.
