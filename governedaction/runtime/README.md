# Four-Primitive Reference Runtime v0

Status: **experimental / non-normative**

This package is the first executable runtime composition built after the
primitive-reduction series converged on the bounded semantic basis:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

It does **not** replace or revise the frozen governed-action v1 contract.
It composes the existing `governedaction` effect-boundary ordering with a
minimal semantic surface.

## Why this exists

The primitive-reduction experiments answered a research question:

> which semantic distinctions survive direct elimination?

The reference runtime asks the next engineering question:

> can those surviving distinctions drive a real executable lifecycle without
> re-introducing Capability, Constraint, Evidence, RetryToken, domain-specific
> action classes, or another kernel primitive?

The v0 lifecycle is:

```text
Request
  │
  ├─ Identity
  ├─ exact State
  ├─ trusted Attestation
  └─ exact Transition
  │
  ▼
boundary revalidation
  │
  ▼
durable custody
  │
  ▼
boundary revalidation again
  │
  ▼
one effect invocation
  │
  ▼
trusted observation
  │
  ├─ exact intended state -> CLOSED
  └─ anything weaker      -> UNKNOWN
```

There is no automatic retry.

## Primitive/composite boundary

The runtime uses four primitive **types**. Multiple instances do not create new
primitive types.

Examples:

- subject and executor are two `Identity` instances;
- current target state and effect-custody state are `State` instances at the
  wider governed-action layer;
- admission and outcome provenance are `Attestation` instances;
- requested mutation and custody evolution are `Transition` relations.

Runtime records such as `Request`, `Custody`, `Observation`, and effect IDs
are composites.

## Adapter responsibilities

The runtime intentionally does not manufacture trust or durability.

An adapter must provide:

```text
CurrentState
VerifyAttestation
RetainCustody
Execute
Observe
```

### CurrentState

Must return the exact native state revision used at the actual effect boundary.
Caller labels are not state evidence.

### VerifyAttestation

Must verify the implementation-specific trust relation, including whatever the
selected profile requires: signature/integrity, issuer trust, revocation,
trust epoch, and other provenance checks.

The runtime itself only fixes the semantic binding digest.

### RetainCustody

Must durably and atomically retain the exact:

```text
EffectID
AttemptID
Target
Owner Identity
```

before the effect may escape.

It must reject unsafe duplicate reservations using the native substrate
(transaction, compare-and-swap, fencing, uniqueness constraint, etc.).

An in-memory map is used only by tests and is not a production custody model.

### Execute

Is invoked at most once by one `Run` call.

A nil error is only a call/provider fact. It is not closure evidence.

An error after boundary entry does not establish that no effect occurred.

### Observe

Must produce a typed state observation. Closure requires:

1. exact logical EffectID binding;
2. exact observed State binding;
3. trusted observation Attestation;
4. exact equality with the requested `Transition.To`.

## Dispositions

```text
REJECTED
UNKNOWN
CLOSED
```

### REJECTED

The effect callback was not entered.

Custody may already have been retained if the second boundary revalidation
failed after the durable custody write.

### UNKNOWN

An effect may have happened, but the runtime lacks exact trusted evidence for
the intended after-state.

Provider acceptance, transport failure, observer failure, contradictory state,
or an untrusted observation cannot be upgraded to CLOSED.

### CLOSED

An exact trusted observation matches the intended after-state.

A provider call may have returned an error and still become CLOSED if later
trusted observation proves the intended state. The provider error remains in
the result history; it is not rewritten away.

## Effect identity

`EffectIdentity` binds:

```text
subject
+ exact target state revision
+ operation
+ exact intended after-state
```

It deliberately excludes the authorization path.

Therefore two trusted policy paths authorizing the same exact logical effect do
not create two logical effects, while changing subject, target, state revision,
operation, or intended state changes the effect identity.

## Current executable coverage

The same runtime implementation is exercised against generic fixtures for:

- GitHub;
- Kubernetes;
- PostgreSQL;
- Terraform.

Tests also cover:

- stale state before custody;
- state drift after custody but before effect entry;
- untrusted admission;
- provider success without postcondition evidence;
- provider error with exact later observation;
- observation outage;
- duplicate attempt/custody replay;
- subject/state/target/operation substitution;
- untrusted observation;
- cross-effect observation reuse.

## Claim boundary

v0 supports only this bounded claim:

> the surviving four semantic primitive types can drive one generic executable
> admission → custody → effect → observation → closure loop across the modeled
> domains without adding a domain-specific kernel primitive.

It does not prove:

- global mathematical minimality;
- complete mediation;
- production durability;
- a universal policy language;
- universal identity;
- universal exactly-once execution;
- a global trust root;
- a scheduler or durable workflow engine.

Those remain in domain adapters, native enforcement substrates, and the frozen
governed-action contract.
