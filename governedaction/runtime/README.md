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


## Crash/restart recovery v1

The first post-v0 hardening step adds an observation-only recovery path:

```text
previous attempt
  ↓
durable custody exists
  ↓
process disappears / observation is lost
  ↓
restart
  ↓
load exact EffectID + AttemptID custody
  ↓
verify fresh recovery Attestation
  ↓
observe only
  ↓
CLOSED | UNKNOWN
```

Recovery never calls `Execute` and never creates a replacement attempt.

This makes the continuation rule explicit:

```text
restart / wakeup / possession of old request
!=
permission to perform another effect
```

A fresh recovery Attestation is bound to:

```text
exact EffectID
+ exact AttemptID
+ exact target
+ exact retained custody owner
+ exact recoverer Identity
```

The recoverer may be a different principal from the original executor, but v1
does not transfer custody ownership. It only authorizes observation/reconciliation
of the already retained attempt. A true ownership takeover requires a later
atomic custody-transfer/fencing step and is intentionally outside this PR.

If recovery cannot obtain exact trusted evidence for the intended after-state,
the result remains `UNKNOWN`. That state never grants replay permission.

The executable recovery corpus covers:

- effect entered, observation lost, restart, exact observation, no replay;
- repeated recovery of the same attempt without additional effects;
- missing recovery authorization;
- recoverer substitution;
- attempt substitution;
- tampered retained custody;
- persistent observation failure;
- observed state mismatch.

The claim remains bounded: native storage must make `LoadCustody` faithful to
the durable record, and the adapter still owns trust verification, storage
durability, fencing and observation authenticity.


## Fenced executor takeover v1

The next hardening layer addresses executor replacement without allowing two
workers to hold effect authority at the same time.

It introduces a durable composite custody state:

```text
EffectID
AttemptID
Target
Owner Identity
Generation
Phase
```

`Generation` is a monotonic fencing token. `Phase` is one of:

```text
RESERVED
CROSSING
UNKNOWN
CLOSED
```

These are runtime state carried by the existing semantic basis; they are not
new semantic primitive types.

### Safe transfer boundary

Only `RESERVED` custody may transfer execution ownership:

```text
A owns generation 1 / RESERVED
        ↓
fresh takeover Attestation
        ↓
atomic CAS
        ↓
B owns generation 2 / RESERVED
```

The old generation cannot cross the native effect boundary after the transfer.

```text
A(gen=1) returns late ──> DENY
B(gen=2) current       ──> may continue
```

The adapter must enforce Owner + Generation at the native effect boundary.
A userspace pre-check alone is not sufficient because transfer can race between
check and use.

### Crash boundary

Execution moves durable custody to `CROSSING` **before** calling the external
effect:

```text
RESERVED
  ↓ durable CAS
CROSSING
  ↓ external effect callback
UNKNOWN
  ↓ exact trusted observation
CLOSED
```

This makes a critical distinction explicit:

- `RESERVED`: no effect has been allowed to enter through this fenced path;
- `CROSSING` / `UNKNOWN`: an effect may have happened;
- `CLOSED`: exact trusted observation proved the intended after-state.

Therefore takeover is denied from `CROSSING`, `UNKNOWN`, or `CLOSED`.
Those phases can be observed/reconciled, but they cannot be reopened as safe
execution merely because another worker is available.

### Executable checks

The v1 takeover corpus proves:

- normal fenced execution reaches CLOSED;
- A can reserve, disappear, and transfer exact RESERVED custody to B;
- the transfer atomically advances the fencing generation;
- a late A holding the old generation is denied by native fencing;
- B can execute the exact retained effect;
- concurrent B/C takeover attempts have exactly one CAS winner;
- a second takeover fences the intermediate owner;
- new-owner substitution invalidates takeover authorization;
- fresh target state is still revalidated after takeover;
- CROSSING, UNKNOWN and CLOSED cannot be converted back to executable RESERVED.

### Claim boundary

This is still an experimental reference runtime.

The safety claim requires **complete mediation for the tested effect path**:
all mutations participating in executor takeover must pass through an adapter
that atomically enforces the exact current Owner + Generation at the native
effect boundary. Code that can bypass that destination fence is outside the
claim.

This layer does not manufacture distributed consensus. The adapter must supply
the linearizable compare-and-swap / transaction / uniqueness primitive used for
custody reservation and transfer.
