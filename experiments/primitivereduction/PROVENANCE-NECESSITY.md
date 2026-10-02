# Provenance Necessity Boundary v10

Status: **non-normative falsification experiment**

Primitive Reduction v9 refined the semantic basis to:

```text
Identity
State
Constraint
Attestation
Transition
```

v10 tests whether `Attestation` can be eliminated entirely.

## Four-primitive candidate

The strongest naive reduction is:

```text
Identity
State
Constraint
Transition
```

with all provenance removed.

That candidate can still evaluate:

- subject identity;
- current state;
- target binding;
- requested transition;
- constraint predicates.

But it cannot answer one crucial question:

> who asserted the claim, and is that origin trusted?

## Indistinguishability result

Without provenance, these two worlds become identical semantic input:

```text
World A:
trusted issuer asserts claim C

World B:
untrusted actor copies claim C exactly
```

After stripping provenance:

```text
Identity + State + Constraint + Transition
```

is byte-for-byte the same in both worlds.

A four-primitive evaluator therefore makes the same decision in both worlds.

That is a real reduction failure, not merely an implementation gap.

## Hidden assumption found in v9

v10 also exposes a weaker point in the v9 executable model.

`Attestation.Valid` was intentionally an abstraction for implementation-specific
verification. But if `Valid=true` is interpreted as only binding/signature
integrity, an untrusted issuer can create a perfectly self-consistent
attestation and the base v9 evaluator has no explicit trusted-issuer state with
which to reject it.

Therefore:

```text
binding validity != issuer trust
```

v10 makes issuer trust explicit through an ordinary `StateRef`:

```text
namespace = governance.provenance_trust
object    = issuers
version   = trust epoch
facts     = trusted issuer identities
```

This reuses the existing `State` primitive; it does not add a sixth semantic
primitive.

## Root-of-trust boundary

The trust state itself cannot be made authoritative merely because a proposal
contains it.

Its authenticity and currentness must terminate in an external root of trust,
for example the existing Genesis Manifest / cryptographic root-of-trust
machinery.

Otherwise trust becomes circular:

```text
claim is trusted because state says issuer is trusted
state is trusted because another claim says state is trusted
...
```

The semantic model must bottom out in an anchored trust root.

## Executable corpus

Tests demonstrate:

- the four-primitive candidate cannot distinguish trusted from copied claims;
- the provenance-free proposal contains no hidden issuer/evidence field;
- a self-consistent untrusted attestation can pass the base v9 evaluator when
  trust is hidden behind `Valid`;
- explicit trusted-issuer State accepts the original trusted issuer;
- the same State rejects a recomputed untrusted self-attestation;
- issuer revocation fails closed without changing the claim itself;
- trusted-issuer State cannot replace the attestation binding;
- trust mechanics reuse `State` rather than creating a sixth primitive.

## Current bounded result

v10 **falsifies the four-primitive reduction** for the modeled corpus.

`Attestation` may be better named conceptually as a **Provenance Binding**, but
some provenance-bearing relation remains necessary.

The strongest candidate basis therefore remains five:

```text
Identity
State
Constraint
Attestation / Provenance Binding
Transition
```

This still does not prove global mathematical minimality. It does establish that
removing provenance without hiding it elsewhere destroys a distinction required
for safe admission.
