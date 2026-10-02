# Constraint Elimination v11

Status: **non-normative semantic-reduction experiment**

v10 established that provenance cannot simply be removed. The surviving
five-candidate basis was:

```text
Identity
State
Constraint
Attestation / Provenance
Transition
```

v11 attacks a different question:

> must the kernel itself receive and evaluate Constraint as a semantic input?

## Reduction

A trusted policy/evidence producer may evaluate the richer relation first:

```text
Identity
+ State
+ Constraints
+ Provenance
+ Transition
        ↓
     ALLOW
```

and then emit one compact attestation bound to the exact admitted relation:

```text
AdmissionAttestation {
    issuer
    decision
    exact subject/state/target/transition binding
}
```

The v11 runtime proposal contains no `Capability`, no `Evidence`, and no
`Constraint` field.

Candidate basis:

```text
Identity
State
Attestation
Transition
```

## Important distinction

This does **not** mean policy constraints cease to exist.

It means their evaluation can be moved outside the smallest kernel admission
surface, provided the resulting decision is:

- produced by a trusted issuer;
- bound to the exact state revision;
- bound to the exact subject;
- bound to the exact target;
- bound to the exact transition;
- fail-closed on revocation or stale binding.

The kernel becomes a small reference monitor for an already-adjudicated,
state-bound decision.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests verify:

- the same governed actions admit with no Constraint field;
- a policy-violating source relation cannot mint the compact attestation;
- subject substitution fails closed;
- operation substitution fails closed;
- state revision substitution fails closed;
- target substitution fails closed;
- an untrusted policy issuer cannot authorize;
- issuer revocation fails closed;
- an attested DENY cannot become executable authority;
- removing Identity, State, Attestation, or Transition fails closed.

## Reduction boundary

This reduction is valid only if the trusted producer is actually responsible for
policy adjudication.

It would be invalid to claim "Constraint disappeared" while silently embedding
policy logic inside an opaque boolean or inside kernel-specific special cases.

The clean separation is:

```text
Policy layer:
    evaluate constraints
    produce state-bound admission attestation

Minimal kernel:
    verify identity
    verify state binding
    verify attestation provenance/trust
    verify exact transition
    allow or deny
```

## Current bounded result

For the modeled corpus, `Constraint` is not required as an independent
semantic input to the minimal kernel.

The new candidate basis becomes four:

```text
Identity
State
Attestation / Provenance Binding
Transition
```

This does not contradict v10.

v10 falsified a *provenance-free* four-primitive basis:

```text
Identity + State + Constraint + Transition
```

v11 tests a different four-primitive basis:

```text
Identity + State + Attestation + Transition
```

The next reduction attack should target one of these four directly rather than
merely renaming records.
