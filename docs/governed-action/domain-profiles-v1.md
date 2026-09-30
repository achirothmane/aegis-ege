# K01 domain-profile mapping — candidate Kernel v1

Status: **DRAFT / UNFROZEN**  
Normative owner: Aegis integration-contract steward  
Companion contract: [kernel-v1.md](kernel-v1.md)

This mapping applies the K01 ActionRef / DecisionBasis rules to the three design-visible seeds already selected by the queue:

- CI rerun / Workflow Failure Lab;
- Kubernetes node mutation / Aegis;
- the existing EEP synthetic CRM fixture.

It does not add a new runtime profile service. Existing domain contracts remain authoritative for their payload semantics.

## 1. Reviewed source set

| Owner | Reviewed revision / identity | K01 use |
|---|---|---|
| Aegis-EGE | `0d94613e1a05ae467170e615633d79c31a309d36` | K01 base after C09 |
| EASL | `7c4e1e28218853919d00362dc071e1eb6f61cc56` | current subject-state semantics |
| EASL StateBinding vectors | blob `82d151531da6f98262de1e247658d89a8299c53c` | earned conformance identity |
| Workflow Failure Lab | `d44bd4c47f8748bfca706a4c4833adf8ce940cf6` | C05-repaired CI/EBA consumer |
| WFL vendored StateBinding vectors | blob `82d151531da6f98262de1e247658d89a8299c53c` | byte-identical EASL mirror |
| Agent Action Guard | `5276336cec396a0ac0b77d45eb5b981b01d7d7ea` | AuthorityGrant semantics |
| assumption-gate | `435bc970c10dda83b786677ce9cc98ab9eac3799` | AssumptionState semantics |

Important versioned contracts already owned by those repositories include:

- `eba.integration/v0.1`
- `eba.temporal/v1`
- `eba.context/v1`
- `eba.canonical-json/v1`
- EASL `subject_state_binding` conformance v1
- `aegis.ege/evidence-composition/v1`
- `aegis.ege/permit/v0alpha1`
- `aegis.eep/crm-http-json/v1`
- `aegis.eep/crm-postcondition/v1`
- `aegis.eep/crm-outcome/v0alpha2`

## 2. CI rerun seed

### Trusted profile selection

The trusted selector is the **owner-controlled CI verifier/execution package**, not the remote analyzer or the ActionRequest.

The selected profile is the current CI use of:

- `eba.integration/v0.1`;
- `eba.temporal/v1`;
- `eba.context/v1`;
- `eba.canonical-json/v1`;
- EASL subject-state binding conformance v1;
- the domain evidence policy `ci-retry-gate.evidence-decision.v1`;
- Agent Action Guard AuthorityGrant semantics.

The caller cannot remove those mandatory dependencies by supplying a smaller basis.

### ActionRef

**ActionIdentity**

The logical rerun proposal lineage for one owner-controlled CI action request.

**ActionRevision material semantics**

The revision must bind at least the current CI context already declared by the profile:

- principal;
- operation;
- repository namespace;
- workflow run id;
- run attempt;
- head SHA;
- workflow id;
- exact resource scope / failed-job execution where the selected operation is job-scoped;
- side-effect meaning;
- current owner-controlled verifier/profile versions.

A changed run attempt, head SHA, repository/account scope, operation, or exact job execution is not the same admitted revision.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Evidence decision | domain policy says the rerun candidate is eligible | WFL CI evidence gate |
| StateBinding | current run/head/attempt state still matches evaluated state | WFL EASL compatibility layer using the pinned EASL vectors |
| AssumptionState | required rerun-safety assumption is VALID and correctly bound | WFL EBA verifier; assumption shape owned by assumption-gate |
| AuthorityGrant | principal/action/resource/side-effect scope is allowed | WFL EBA verifier; grant semantics owned by Agent Action Guard |
| Context profile | exact trace, audience and GitHub repository namespace match | `eba.context/v1` validator |
| Temporal profile | required artifacts are valid at the explicit evaluation instant | `eba.temporal/v1` validator |
| Canonical profile | authorizing artifact bytes are in the supported deterministic domain | `eba.canonical-json/v1` validator |
| Action digest / request_ref | Decision applies to this exact ActionRequest revision | WFL execution-boundary verifier |

### AuthorityContext

The CI seed binds:

- principal `ci-retry-gate` or the currently configured exact principal;
- GitHub Actions rerun operation;
- exact repository namespace;
- exact workflow-run/job resource scope;
- side effect = true;
- owner-controlled execution environment.

The namespace is not authenticated by a client string; it is constructed in the trusted local profile.

### Hard preconditions versus observations

Current run/head/attempt reads are **state observations and StateBindings**.

They are not renamed as a universal atomic destination guard.

Any provider-enforced current-state requirement for the actual rerun operation remains a domain/native enforcement question and is tested in D01. K01 does not claim exactly-once rerun or a new GitHub fencing primitive.

### Adapter/effect/outcome semantics

- effect implementation: owner-controlled native GitHub rerun operation;
- current dispatch receipt semantics come from `eba.integration/v0.1`;
- `SUCCEEDED` means the rerun API dispatch was accepted, not that the new workflow later passed;
- later workflow outcome remains separate observation evidence.

K04 will define the candidate-kernel closure relation. K01 does not upgrade a dispatch receipt into closure.

### Admission invalidation

Admission must fail or be re-established when, where material:

- head SHA changes;
- run attempt changes;
- repository/account namespace changes;
- operation/resource scope changes;
- AuthorityGrant is revoked/expired/out-of-scope;
- AssumptionState is stale/contradicted/unknown;
- mandatory profile or validator version becomes unknown;
- the owner-controlled verifier semantics change materially.

## 3. Kubernetes node-mutation seed

### Trusted profile selection

The trusted selector is **Aegis server/deployment configuration at the governed EGE boundary**.

For the current node-drain seed, configured stronger obligations force mutation through:

```text
POST /v1/ege/execute
```

The legacy execute route cannot be selected to bypass configured EBA/capability obligations.

Relevant current contracts include:

- `eba.integration/v0.1`;
- `eba.context/v1`;
- `eba.temporal/v1`;
- `eba.canonical-json/v1`;
- `aegis.ege/evidence-composition/v1`;
- `aegis.ege/permit/v0alpha1`;
- the installed consequence/capability policy versions;
- EASL subject-state semantics where consumed.

### ActionRef

**ActionIdentity**

The logical governed node-mutation intent.

**ActionRevision material semantics**

The revision must bind, where applicable:

- intent/action identity;
- action kind;
- Kubernetes node target;
- cluster/account/deployment namespace identity;
- resourceVersion;
- deterministic execution-plan digest;
- evidence-manifest digest;
- relevant EBA artifact references;
- principal/audience/namespace context;
- installed mutation adapter semantics;
- configured consequence policy/version/hash;
- capability-fence semantics when required;
- required evidence-composition profile/version.

Changing the node, cluster/account context, resourceVersion, plan digest, adapter meaning, policy meaning, or mandatory evidence profile yields a different material revision/basis.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Signed EGE Permit | exact action/evidence/plan/context bindings were signed by the configured permit authority | Aegis EGE execution boundary |
| EBA conformance bundle when configured | evidence, assumptions, authority and approvals satisfy the selected profile | Aegis EBA validator |
| StateBinding / live state | current node/plan-relevant state still matches admission | Aegis/EASL + Kubernetes adapter |
| Evidence composition | required named-source / independence predicate is satisfied at its declared assurance | Aegis evidence composer |
| Consequence admission | consequence class/policy permits this exact action scope | Aegis consequence validator |
| Capability fence when configured | the mutation remains within current capability scope | Aegis capability-fence owner |
| Adapter/profile version | the installed mutation meaning matches the admitted meaning | Aegis server/adapter owner |
| Approval references when required | approval applies to the exact revision/context | Aegis EBA validator |

### AuthorityContext

Where the profile requires them, the basis binds:

- execution principal;
- exact action;
- target/resource;
- authenticated deployment namespace or explicit singleton context;
- approval authority;
- credential/audience semantics;
- capability scope.

A self-hashed EBA artifact is not external issuer authentication. The Kubernetes/Aegis profile uses authenticated parent binding through the signed Permit for the covered external artifacts.

### Hard destination preconditions

The current Kubernetes execution path may use destination-enforced or API-server-enforced predicates such as:

- Node resourceVersion;
- Pod UID / identity preconditions;
- other server-side mutation preconditions declared by the adapter.

The Kubernetes Lease coordinates cooperating Aegis executors; it is **not** represented as fencing a non-cooperating destination writer.

### Bounded-age observations

Examples include:

- node health observation;
- PDB/preflight state;
- evidence observations with freshness bounds;
- previously read resource state before the final mutation-time check.

A prior read cannot replace a required server-enforced precondition.

### Adapter/effect/outcome semantics

The bound adapter meaning is the installed Aegis Kubernetes mutation implementation and deterministic plan semantics.

Current postflight/domain observations remain owned by the Kubernetes adapter and existing decision contract. K04 will define the candidate-kernel ClosureObligation relation; K01 makes no universal closure claim.

### Admission invalidation

Admission must fail or be re-established when, where material:

- action or target changes;
- resourceVersion changes;
- plan digest changes;
- evidence/assumption/authority/approval binding changes;
- required evidence independence becomes unknown/dependent;
- principal/audience/namespace changes;
- configured consequence/capability policy changes materially;
- adapter semantics change;
- a mandatory use-time validator becomes unavailable.

## 4. EEP synthetic CRM seed

### Trusted profile selection

The trusted selector is **the configured Aegis EEP executor profile**, not the incoming plan.

Current versioned profiles:

- execution: `aegis.eep/crm-http-json/v1`;
- intended postcondition: `aegis.eep/crm-postcondition/v1`;
- outcome artifact: `aegis.eep/crm-outcome/v0alpha2`;
- execution Permit: `aegis.ege/permit/v0alpha1`.

### ActionRef

**ActionIdentity**

The logical customer-update intent.

**ActionRevision material semantics**

The revision must bind:

- intent id;
- operation `update_customer` / current exact domain operation;
- exact customer target;
- destination id;
- account id;
- base endpoint;
- adapter profile;
- expected resource version;
- signed plan/patch digest;
- postcondition profile version;
- evidence/permit bindings used to authorize the attempt.

A different destination, account, customer, endpoint, expected resource version, adapter profile, patch meaning, or postcondition profile is a materially different revision.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Signed Permit | exact intent/target/evidence/plan/execution binding is authorized | Aegis EEP executor |
| ExecutionBinding | destination/account/endpoint/adapter/expected version match configured executor | Aegis EEP executor |
| Durable attempt claim | one attributable possible effect is owned before dispatch can escape | Aegis attempt store |
| Journal evidence | authorization/dispatch/outcome evidence is retained | Aegis journal owner |
| Destination identity read | customer endpoint identifies the configured destination/account | CRM adapter |
| Expected resource version | the exact conditional-write version is established | CRM adapter |
| Postcondition profile | intended-field meaning is versioned | EEP postcondition evaluator |

### AuthorityContext

The CRM seed binds:

- configured destination;
- account;
- endpoint;
- exact customer;
- permitted operation;
- adapter profile;
- the authority represented by the signed Permit.

A request cannot switch account or endpoint by changing only the plan payload.

### Hard destination precondition

The current automatic profile requires destination-enforced:

```text
If-Match: <expected ETag/resource version>
```

HTTP 412 is a definite precondition rejection for this profile.

A local lock is not represented as remote fencing.

If the destination cannot supply/enforce the identity + conditional-write contract, this automatic profile is unsupported.

### Bounded-age observations

The pre-mutation GET and post-mutation observations are observations.

The pre-mutation read supplies the ETag used by the later destination precondition, but the read by itself is not atomicity.

### Adapter/effect/postcondition versions

Admission binds:

- `aegis.eep/crm-http-json/v1`;
- `aegis.eep/crm-postcondition/v1`;
- the current signed plan semantics;
- exact configured destination/account/endpoint.

The postcondition profile distinguishes:

- `ALREADY_SATISFIED`;
- `VERIFIED`;
- `PARTIAL`;
- `UNSATISFIED`;
- `UNKNOWN`.

K01 preserves those typed facts. K04 later defines the common closure/disposition relation and must not erase them.

### Admission invalidation

Admission must fail or be re-established when:

- destination/account/endpoint changes;
- customer/operation changes;
- expected resource version changes;
- plan/patch digest changes;
- adapter profile changes;
- postcondition profile changes;
- mandatory durable claim/journal is unavailable;
- required destination identity or conditional-write support is missing.

## 5. Obligation-to-owner table

| K01 obligation | Owning implementation / contract |
|---|---|
| exact ActionRequest / action digest in CI | WFL `eba.integration/v0.1` |
| CI temporal admissibility | WFL `eba.temporal/v1` |
| CI/Aegis contextual bindings | WFL/Aegis `eba.context/v1` consumers |
| deterministic EBA bytes | WFL/Aegis `eba.canonical-json/v1` consumers |
| relevant-state invalidation | EASL StateBinding + domain consumers |
| assumption projection semantics | assumption-gate + consuming profile |
| authority scope semantics | Agent Action Guard + consuming profile |
| EGE permit signature/binding | Aegis `aegis.ege/permit/v0alpha1` |
| evidence independence | Aegis `aegis.ege/evidence-composition/v1` |
| Kubernetes mutation-time state/preconditions | Aegis Kubernetes adapter |
| CRM destination/account/precondition binding | Aegis `aegis.eep/crm-http-json/v1` |
| CRM intended-postcondition meaning | Aegis `aegis.eep/crm-postcondition/v1` |
| effect/attempt common relations | **K02 — not defined here** |
| resumption/time common relations | **K03 — not defined here** |
| closure/UNKNOWN common relations | **K04 — not defined here** |

## 6. CE1 and CE2 seed review

### CE1 — vacuous profile

All three seeds must reject a caller attempt to:

- select an empty mandatory-requirement set;
- remove an owner-required validator;
- select an unknown profile/version;
- substitute a self-declared validator as trusted;
- use route choice to obtain weaker governance for the same governed operation.

### CE2 — revision / approval substitution

All three seeds must reject reuse of an earlier basis when a material binding changes.

At minimum the review covers:

- CI: repository/run/attempt/head SHA/workflow/job scope/principal;
- Kubernetes: action/target/cluster context/resourceVersion/plan/evidence/policy/adapter;
- EEP: destination/account/endpoint/customer/expected version/plan/postcondition profile.

## 7. Positive-seed review

A positive seed is useful only when the required operation can still proceed under its legitimate profile:

- a legitimate eligible CI rerun can reach the owner-controlled native execution boundary;
- a legitimate governed Kubernetes drain can pass the configured EGE boundary;
- a legitimate CRM update can pass exact destination/account/If-Match checks and preserve its typed postcondition result.

Reject-all behavior does not satisfy K01.

## 8. K01 limits

This map does not claim:

- a universal action schema;
- a universal evidence ontology;
- a shared identity provider;
- a general policy engine;
- a universal closure enum;
- exactly-once external effects;
- automatic provider substitution;
- a new shared runtime or repository.

The next semantic item after K01 is K02, not platform extraction.
