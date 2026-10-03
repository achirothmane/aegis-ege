# Evidence Decomposition v9

Status: **non-normative semantic-reduction experiment**

Primitive Reduction v8 reduced the semantic basis to five candidates:

```text
Identity
State
Constraint
Evidence
Transition
```

v9 attacks the broad `Evidence` concept itself.

## Question

Is `Evidence` a fundamental semantic atom?

Or is it a composite that mixes two different things:

```text
claim content
+
provenance / attestation
```

## Decomposition

In v9, claim content is not represented by a new `Claim` record.

The claim already exists in the semantic model as:

```text
State facts
+
Constraint predicates
```

What remains irreducible in the current corpus is provenance: who attests to the
claim, and whether that attestation is bound to the exact subject, state,
transition, target, and constraint content.

The v9 proposal therefore has no `Evidence` field and no `Capability` field.

Candidate basis:

```text
Identity
State
Constraint
Attestation
Transition
```

## Attestation binding

Each attestation binds:

```text
issuer Identity
subject Identity
current State
requested Transition
target
exact Constraint content
```

A mutation to any of those values invalidates the attestation.

The implementation-specific verifier is abstracted by `Valid`; v9 does not
claim to implement signatures, TPM verification, or provider trust roots.

## Executable corpus

Across GitHub, Kubernetes, and PostgreSQL, tests require:

- admission without any `Evidence` field;
- all constraints to have valid provenance;
- claims without attestations to fail closed;
- claim mutation to invalidate old provenance;
- issuer substitution to invalidate the attestation;
- subject / operation / state substitution to invalidate provenance;
- invalid or foreign attestations to fail closed;
- cross-domain attestation replay to fail closed;
- compatibility `Evidence` to be materializable only after attestation
  validation;
- ablation of Identity, State, Constraint, Attestation, or Transition to fail
  closed.

## Result

v9 does **not** reduce the candidate count below five.

Instead, it shows that the old `Evidence` record was too coarse to be treated
as the deepest semantic primitive.

For this corpus:

```text
Evidence
  =
claim content already represented by State/Constraint
  +
Attestation / Provenance
```

So the deeper five-candidate basis becomes:

```text
Identity
State
Constraint
Attestation
Transition
```

This is a semantic refinement, not a claim of final minimality.

## Next falsification

The next attack should target `Attestation` itself.

The key question is whether provenance is genuinely fundamental, or whether it
can be reduced to:

```text
Identity
+ Binding
+ trusted verification relation
```

without smuggling trust semantics into State facts or implementation-specific
cryptography.

If provenance disappears only by hiding it inside `State` or a boolean
`Valid`, that is not a valid reduction.
